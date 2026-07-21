"""Phase 6E.4A: persistent cross-job correlation - persistence mechanics.

This module is the only place that touches the database for stateful
correlation. It is intentionally NOT called from AnalysisService yet - see
`StatefulIncidentCorrelationService.resolve_and_merge`'s `enabled` guard,
which makes the whole facade a proven no-op whenever
`settings.stateful_correlation_enabled` is False. Production routing
integration (deciding when to call this, LLM report reuse, retriage
suppression) is Phase 6E.4B's responsibility, not this foundation's.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional, Sequence, cast

from sqlalchemy.exc import IntegrityError

from agent.config import Settings
from agent.correlation.merge import merge_incident_bundles
from agent.correlation.stateful import (
    StatefulCorrelationProfile,
    StatefulStateSnapshot,
    classify_state_decision,
    compute_correlation_key,
    derive_stateful_profile,
)
from agent.detection.config import DetectionSettings
from agent.detection.incident_correlation import MAX_INCIDENT_EVIDENCE
from agent.detection.models import DetectionEvidence, DetectionSignal, IncidentBundle
from agent.persistence.lifecycle import IncidentLifecycle
from agent.persistence.mappers import DataMapper
from agent.persistence.orm_models import (
    DetectionSignal as OrmDetectionSignal,
    Incident,
    IncidentCorrelationState,
    IncidentEvent,
    IncidentSignal,
    IngestionJob,
)
from agent.persistence.unit_of_work import UnitOfWork
from agent.schema import CanonicalLogEvent


ResolveStatus = Literal[
    "created", "merged", "no_op", "new_generation", "stale", "unsupported", "disabled"
]

MaterialChangeCode = str

# How many persisted incident events to reconstruct evidence from. Generous
# relative to MAX_INCIDENT_EVIDENCE so the pure merge always has a pool that
# spans earlier jobs, but still bounded so no single incident reconstruction
# scans an unbounded event set.
_EVIDENCE_RECONSTRUCTION_LIMIT = MAX_INCIDENT_EVIDENCE * 5
_EVIDENCE_QUOTE_MAX_CHARS = 500


class StatefulCorrelationError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class StatefulResolveResult:
    status: ResolveStatus
    canonical_incident: Optional[Incident]
    incoming_incident_id: str
    canonical_incident_id: Optional[str]
    correlation_key: Optional[str]
    generation: Optional[int]
    material_changes: tuple[MaterialChangeCode, ...]
    # Event IDs represented in the merged incident's bounded evidence. Lives
    # only on this transient result object (never persisted in metrics JSON),
    # so callers can confirm earlier jobs' evidence survives a merge.
    evidence_event_ids: tuple[str, ...] = ()


def _as_utc(value: Any) -> datetime:
    """SQLite drops tzinfo on round-trip even for DateTime(timezone=True)
    columns; every other supported dialect preserves it. Normalize to
    UTC-aware here so downstream comparisons never straddle naive/aware.

    `value` is typed Any because this codebase's classic (non-Mapped)
    SQLAlchemy Column declarations statically type instance attribute
    access as Column[datetime] rather than datetime - the runtime value on
    a loaded ORM instance is always a real datetime.
    """
    value = cast(datetime, value)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _compute_expires_at(now: datetime, last_seen: datetime, ttl: timedelta) -> datetime:
    """expires_at must always be strictly later than last_seen (a table CHECK
    constraint). Bounded future-dated event timestamps can push last_seen past
    `now`, so anchor the TTL to the later of the two."""
    return max(now, last_seen) + ttl


def _state_snapshot(state: IncidentCorrelationState) -> StatefulStateSnapshot:
    return StatefulStateSnapshot(
        correlation_version=str(state.correlation_version),
        generation=int(state.generation),
        incident_id=str(state.incident_id),
        first_seen=_as_utc(state.first_seen),
        last_seen=_as_utc(state.last_seen),
        expires_at=_as_utc(state.expires_at),
    )


def _is_noop(canonical_row: Incident, incoming_bundle: IncidentBundle, job: IngestionJob) -> bool:
    """A true no-op requires the SAME job to already be associated and every
    incoming event/signal ID to already be present. A distinct new job is
    never a no-op even with identical IDs - it is a material projection
    change (job_association_added)."""
    if job not in canonical_row.jobs:
        return False
    existing_event_ids = {e.event_id for e in canonical_row.events if not e.is_context}
    if not set(incoming_bundle.event_ids) <= existing_event_ids:
        return False
    existing_signal_ids = {s.signal_id for s in canonical_row.signals}
    if not set(incoming_bundle.signal_ids) <= existing_signal_ids:
        return False
    return True


def _apply_stateful_metrics(
    row: Incident,
    *,
    correlation_key: str,
    strategy: str,
    correlation_version: str,
    generation: int,
    merge_count: int,
    job_count: int,
    total_events: int,
    correlated_signal_count: int,
    absorbed_signal_count: int,
    primary_signal_id: str,
) -> None:
    """Stamp the full bounded scalar stateful-metric set onto the incident.

    Only scalars: no job/event/signal ID lists ever go into metrics JSON -
    the full associations live in the relational tables.
    """
    metrics = dict(row.metrics or {})
    metrics["stateful_correlation_version"] = correlation_version
    metrics["stateful_correlation_key"] = correlation_key
    metrics["stateful_correlation_strategy"] = strategy
    metrics["stateful_generation"] = int(generation)
    metrics["stateful_merge_count"] = int(merge_count)
    metrics["correlated_job_count"] = int(job_count)
    metrics["total_events"] = int(total_events)
    metrics["correlated_signal_count"] = int(correlated_signal_count)
    metrics["absorbed_signal_count"] = int(absorbed_signal_count)
    metrics["primary_signal_id"] = primary_signal_id
    row.metrics = metrics  # type: ignore[assignment]


class StatefulIncidentMergeService:
    """Focused persistence mechanics for one canonical Incident row."""

    def create_canonical(
        self,
        uow: UnitOfWork,
        *,
        bundle: IncidentBundle,
        job: IngestionJob,
        correlation_key: str,
        strategy: str,
        correlation_version: str,
        generation: int,
    ) -> tuple[Incident, bool]:
        """Return the canonical Incident row for `bundle`, plus whether
        anything material changed on it.

        When an Incident with this exact deterministic incident_id already
        exists (e.g. persisted earlier by plain batch-local persistence, or
        by a previous stateful resolve), it is reused rather than
        duplicated - but the full stateful metric set is still (re)stamped,
        a new job association is still added, and `Incident.version` still
        bumps exactly once for that change, rather than silently skipping
        all of that bookkeeping the way an early return would.
        """
        primary_signal_id = str(
            bundle.metrics.get("primary_signal_id")
            or (bundle.signal_ids[0] if bundle.signal_ids else "")
        )

        existing = uow.incidents.get_for_update(bundle.incident_id)
        if existing is not None:
            job_newly_associated = job not in existing.jobs
            if job_newly_associated:
                existing.jobs.append(job)

            prev_metrics = cast(dict, existing.metrics or {})
            first_time_stateful = "stateful_correlation_key" not in prev_metrics
            prev_generation = int(prev_metrics.get("stateful_generation", 0) or 0)
            material_change = (
                job_newly_associated
                or first_time_stateful
                or prev_metrics.get("stateful_correlation_key") != correlation_key
                or prev_generation != generation
            )

            _apply_stateful_metrics(
                existing,
                correlation_key=correlation_key,
                strategy=strategy,
                correlation_version=correlation_version,
                generation=generation,
                merge_count=int(prev_metrics.get("stateful_merge_count", 0) or 0),
                job_count=len(existing.jobs),
                total_events=len(bundle.event_ids),
                correlated_signal_count=len(bundle.signal_ids),
                absorbed_signal_count=len(bundle.absorbed_signal_ids),
                primary_signal_id=primary_signal_id,
            )
            if material_change:
                existing.version = max(1, int(existing.version or 1)) + 1
            return existing, material_change

        orm_incident = DataMapper.domain_incident_to_orm(bundle)
        uow.incidents.add(orm_incident)
        orm_incident.jobs.append(job)
        IncidentLifecycle.transition(orm_incident, "new", actor="stateful_correlation")

        _apply_stateful_metrics(
            orm_incident,
            correlation_key=correlation_key,
            strategy=strategy,
            correlation_version=correlation_version,
            generation=generation,
            merge_count=0,
            job_count=len(orm_incident.jobs),
            total_events=len(bundle.event_ids),
            correlated_signal_count=len(bundle.signal_ids),
            absorbed_signal_count=len(bundle.absorbed_signal_ids),
            primary_signal_id=primary_signal_id,
        )
        return orm_incident, True

    def merge_into_canonical(
        self,
        uow: UnitOfWork,
        *,
        canonical_row: Incident,
        incoming_bundle: IncidentBundle,
        job: IngestionJob,
        available_signals: Optional[Sequence[DetectionSignal]],
        canonical_evidence: Sequence[DetectionEvidence],
        detection_settings: DetectionSettings,
        max_context_events: int,
        correlation_key: str,
        strategy: str,
        correlation_version: str,
        generation: int,
    ) -> tuple[Incident, tuple[MaterialChangeCode, ...], tuple[str, ...]]:
        existing_metrics = cast(dict, canonical_row.metrics or {})
        prev_merge_count = int(existing_metrics.get("stateful_merge_count", 0) or 0)
        job_newly_associated = job not in canonical_row.jobs

        canonical_bundle = DataMapper.orm_to_domain_incident(canonical_row)
        # SQLite drops tzinfo on DateTime(timezone=True) round-trips; other
        # dialects preserve it. Normalize so merge_incident_bundles never
        # compares a naive ORM-loaded timestamp against an aware one. Also
        # inject the reconstructed historical evidence (the ORM incident has
        # no evidence column, so mappers hydrate it empty - see Phase 6E.4A
        # blocker 5).
        canonical_bundle = canonical_bundle.model_copy(
            update={
                "first_seen": _as_utc(canonical_bundle.first_seen),
                "last_seen": _as_utc(canonical_bundle.last_seen),
                "evidence": list(canonical_evidence),
            }
        )
        outcome = merge_incident_bundles(
            canonical=canonical_bundle,
            incoming=incoming_bundle,
            available_signals=available_signals,
            settings=detection_settings,
            max_context_events=max_context_events,
        )
        merged = outcome.incident

        existing_rows_by_id = {row.event_id: row for row in canonical_row.events}
        for event_id in merged.event_ids:
            row = existing_rows_by_id.get(event_id)
            if row is None:
                canonical_row.events.append(IncidentEvent(event_id=event_id, is_context=False))
            elif row.is_context:
                row.is_context = False
        for event_id in merged.context_event_ids:
            if event_id not in existing_rows_by_id:
                canonical_row.events.append(IncidentEvent(event_id=event_id, is_context=True))

        existing_signal_ids = {s.signal_id for s in canonical_row.signals}
        for signal_id in merged.signal_ids:
            if signal_id not in existing_signal_ids:
                canonical_row.signals.append(IncidentSignal(signal_id=signal_id))

        if job_newly_associated:
            canonical_row.jobs.append(job)

        material_changes = list(outcome.material_changes)
        if job_newly_associated:
            # A new job association changes the incident's projection even when
            # its event/signal IDs already exist.
            material_changes.append("job_association_added")

        # Classic (non-Mapped) Column declarations statically type instance
        # attributes as Column[T]; the same convention as
        # agent/persistence/lifecycle.py's IncidentLifecycle.transition.
        canonical_row.title = merged.title  # type: ignore[assignment]
        canonical_row.incident_type = merged.incident_type  # type: ignore[assignment]
        canonical_row.incident_family = merged.incident_family  # type: ignore[assignment]
        canonical_row.severity = merged.severity  # type: ignore[assignment]
        canonical_row.confidence = merged.confidence  # type: ignore[assignment]
        canonical_row.first_seen = merged.first_seen  # type: ignore[assignment]
        canonical_row.last_seen = merged.last_seen  # type: ignore[assignment]
        canonical_row.primary_entity = merged.primary_entity  # type: ignore[assignment]
        canonical_row.target_entities = merged.target_entities  # type: ignore[assignment]
        canonical_row.mitre_techniques = merged.mitre_techniques  # type: ignore[assignment]
        canonical_row.metrics = merged.metrics  # type: ignore[assignment]

        _apply_stateful_metrics(
            canonical_row,
            correlation_key=correlation_key,
            strategy=strategy,
            correlation_version=correlation_version,
            generation=generation,
            merge_count=prev_merge_count + 1,
            job_count=len(canonical_row.jobs),
            total_events=int(merged.metrics.get("total_events", len(merged.event_ids))),
            correlated_signal_count=int(
                merged.metrics.get("correlated_signal_count", len(merged.signal_ids))
            ),
            absorbed_signal_count=int(
                merged.metrics.get("absorbed_signal_count", len(merged.absorbed_signal_ids))
            ),
            primary_signal_id=str(merged.metrics.get("primary_signal_id", "")),
        )

        if material_changes:
            # Exactly one version bump per material merge (including a pure
            # new-job association), exposing the updated row for the outbox.
            canonical_row.version = max(1, int(canonical_row.version or 1)) + 1  # type: ignore[assignment]

        evidence_event_ids = tuple(item.event_id for item in merged.evidence)
        return canonical_row, tuple(material_changes), evidence_event_ids


class StatefulIncidentCorrelationService:
    """Public facade: `resolve_and_merge` is the single entry point.

    Not wired into AnalysisService in this foundation PR. When
    `settings.stateful_correlation_enabled` is False, this method performs
    no database writes and returns status="disabled" - callers can invoke
    it unconditionally without behavior changing while the flag stays off.
    """

    def __init__(self, merge_service: Optional[StatefulIncidentMergeService] = None) -> None:
        self._merge_service = merge_service or StatefulIncidentMergeService()

    def resolve_and_merge(
        self,
        uow: UnitOfWork,
        *,
        incoming_bundle: IncidentBundle,
        incoming_events: Sequence[CanonicalLogEvent],
        incoming_signal_rows: Sequence[OrmDetectionSignal],
        job: IngestionJob,
        settings: Optional[Settings] = None,
        detection_settings: Optional[DetectionSettings] = None,
        now: Optional[datetime] = None,
    ) -> StatefulResolveResult:
        settings = settings or uow.settings
        detection_settings = detection_settings or DetectionSettings()
        now = now or datetime.now(timezone.utc)

        if not settings.stateful_correlation_enabled:
            return self._result("disabled", incoming_bundle)

        profile = derive_stateful_profile(
            incoming_bundle,
            incoming_events,
            correlation_version=settings.stateful_correlation_version,
            max_profile_items=settings.stateful_correlation_max_profile_items,
            ipv4_subnet_prefix=detection_settings.SUBNET_SWEEP_IPV4_PREFIX,
            ipv6_subnet_prefix=detection_settings.SUBNET_SWEEP_IPV6_PREFIX,
        )
        if profile is None:
            return self._result("unsupported", incoming_bundle)

        correlation_key = compute_correlation_key(profile)
        ttl = timedelta(seconds=settings.stateful_correlation_state_ttl_seconds)
        window_seconds = settings.stateful_correlation_window_seconds

        assert uow.session is not None, "resolve_and_merge requires an open UnitOfWork"

        state = uow.correlation_state.get_for_update(correlation_key)

        if state is None:
            try:
                return self._try_create(
                    uow,
                    incoming_bundle=incoming_bundle,
                    job=job,
                    profile=profile,
                    correlation_key=correlation_key,
                    ttl=ttl,
                    now=now,
                )
            except IntegrityError:
                # Disambiguate by re-reading: if another worker's state row
                # is now present, this really was the unique-correlation_key
                # race - fall through and merge into the winner. If no state
                # row exists, the failure was an unrelated FK/CHECK/unique
                # violation (e.g. an incoming incident referencing a missing
                # detection-signal row) and must propagate unchanged rather
                # than being replaced with a generic race error.
                state = uow.correlation_state.get_for_update(correlation_key)
                if state is None:
                    raise

        canonical_incident_row = uow.incidents.get_for_update(state.incident_id)
        decision = classify_state_decision(
            _state_snapshot(state),
            correlation_version=profile.correlation_version,
            incident_exists=canonical_incident_row is not None,
            incoming_first_seen=incoming_bundle.first_seen,
            incoming_last_seen=incoming_bundle.last_seen,
            window_seconds=window_seconds,
            now=now,
        )

        if decision == "stale":
            # Leave the active correlation row entirely unchanged.
            return self._result(
                "stale",
                incoming_bundle,
                canonical_incident=canonical_incident_row,
                canonical_incident_id=str(state.incident_id),
                correlation_key=correlation_key,
                generation=int(state.generation),
            )

        if decision == "merge":
            assert canonical_incident_row is not None
            return self._merge(
                uow,
                canonical_row=canonical_incident_row,
                incoming_bundle=incoming_bundle,
                incoming_signal_rows=incoming_signal_rows,
                job=job,
                profile=profile,
                correlation_key=correlation_key,
                state=state,
                ttl=ttl,
                now=now,
                detection_settings=detection_settings,
            )

        # decision in ("new_generation", "repair")
        return self._new_generation(
            uow,
            incoming_bundle=incoming_bundle,
            job=job,
            profile=profile,
            correlation_key=correlation_key,
            state=state,
            ttl=ttl,
            now=now,
        )

    # -- internal paths ----------------------------------------------------

    def _try_create(
        self,
        uow: UnitOfWork,
        *,
        incoming_bundle: IncidentBundle,
        job: IngestionJob,
        profile: StatefulCorrelationProfile,
        correlation_key: str,
        ttl: timedelta,
        now: datetime,
    ) -> StatefulResolveResult:
        """Create the canonical incident and its state row inside a single
        savepoint so the FK (state.incident_id -> incidents.incident_id) is
        satisfied at flush time.

        Raises `IntegrityError` (never swallowed here) on ANY constraint
        violation - the unique-correlation_key race, an unrelated FK
        violation (e.g. a missing detection-signal row), or a CHECK
        violation. The caller disambiguates by re-reading the correlation
        state afterward: only when it finds a winner's state row does it
        treat this as the known race and merge into it; otherwise it
        re-raises the original error unchanged. Either way, the savepoint
        rollback leaves no orphan duplicate incident behind.
        """
        session = uow.session
        assert session is not None
        canonical_row: Optional[Incident] = None
        try:
            with session.begin_nested():
                canonical_row, _ = self._merge_service.create_canonical(
                    uow,
                    bundle=incoming_bundle,
                    job=job,
                    correlation_key=correlation_key,
                    strategy=profile.strategy,
                    correlation_version=profile.correlation_version,
                    generation=1,
                )
                # Flush the incident (and its event/signal associations) first
                # so the state row's incident_id FK is satisfiable - there is
                # no ORM relationship between the two tables, so SQLAlchemy
                # cannot infer the insert order on its own. Both writes stay
                # inside this savepoint, so any failure rolls back the
                # incident as well and leaves no orphan.
                session.flush()
                new_state = IncidentCorrelationState(
                    correlation_key=correlation_key,
                    correlation_version=profile.correlation_version,
                    strategy=profile.strategy,
                    incident_id=canonical_row.incident_id,
                    profile=profile.model_dump(mode="json"),
                    generation=1,
                    first_seen=incoming_bundle.first_seen,
                    last_seen=incoming_bundle.last_seen,
                    expires_at=_compute_expires_at(now, incoming_bundle.last_seen, ttl),
                    version=1,
                )
                uow.correlation_state.add(new_state)
                session.flush()
        except IntegrityError:
            # Savepoint auto-rolled-back: the temporary incident AND state row
            # are both gone. Defensively expunge the incident so it can never
            # be re-inserted on the outer commit, leaving no orphan duplicate.
            if canonical_row is not None and canonical_row in session:
                session.expunge(canonical_row)
            raise

        return self._result(
            "created",
            incoming_bundle,
            canonical_incident=canonical_row,
            canonical_incident_id=str(canonical_row.incident_id),
            correlation_key=correlation_key,
            generation=1,
            material_changes=("new_state",),
        )

    def _merge(
        self,
        uow: UnitOfWork,
        *,
        canonical_row: Incident,
        incoming_bundle: IncidentBundle,
        incoming_signal_rows: Sequence[OrmDetectionSignal],
        job: IngestionJob,
        profile: StatefulCorrelationProfile,
        correlation_key: str,
        state: IncidentCorrelationState,
        ttl: timedelta,
        now: datetime,
        detection_settings: DetectionSettings,
    ) -> StatefulResolveResult:
        session = uow.session
        assert session is not None

        if _is_noop(canonical_row, incoming_bundle, job):
            return self._result(
                "no_op",
                incoming_bundle,
                canonical_incident=canonical_row,
                canonical_incident_id=str(canonical_row.incident_id),
                correlation_key=correlation_key,
                generation=int(state.generation),
            )

        available_signals = self._load_available_signals(
            uow, canonical_row, incoming_signal_rows
        )
        canonical_evidence = self._reconstruct_canonical_evidence(
            uow, canonical_row, limit=_EVIDENCE_RECONSTRUCTION_LIMIT
        )
        merged_row, material_changes, evidence_event_ids = (
            self._merge_service.merge_into_canonical(
                uow,
                canonical_row=canonical_row,
                incoming_bundle=incoming_bundle,
                job=job,
                available_signals=available_signals,
                canonical_evidence=canonical_evidence,
                detection_settings=detection_settings,
                max_context_events=detection_settings.MAX_CONTEXT_EVENTS_PER_INCIDENT,
                correlation_key=correlation_key,
                strategy=profile.strategy,
                correlation_version=profile.correlation_version,
                generation=int(state.generation),
            )
        )
        session.flush()

        new_first_seen = min(_as_utc(state.first_seen), incoming_bundle.first_seen)
        new_last_seen = max(_as_utc(state.last_seen), incoming_bundle.last_seen)
        ok = uow.correlation_state.extend_active_generation(
            correlation_key,
            expected_version=int(state.version),
            profile=profile.model_dump(mode="json"),
            first_seen=new_first_seen,
            last_seen=new_last_seen,
            expires_at=_compute_expires_at(now, new_last_seen, ttl),
            now=now,
        )
        if not ok:
            raise StatefulCorrelationError("stateful_correlation_state_conflict")
        # A guarded bulk UPDATE bypasses the ORM, so the in-session state
        # object's version is now stale; expire it so a later resolve in the
        # same UnitOfWork re-reads the committed version.
        session.expire(state)

        return self._result(
            "merged",
            incoming_bundle,
            canonical_incident=merged_row,
            canonical_incident_id=str(merged_row.incident_id),
            correlation_key=correlation_key,
            generation=int(state.generation),
            material_changes=material_changes,
            evidence_event_ids=evidence_event_ids,
        )

    def _new_generation(
        self,
        uow: UnitOfWork,
        *,
        incoming_bundle: IncidentBundle,
        job: IngestionJob,
        profile: StatefulCorrelationProfile,
        correlation_key: str,
        state: IncidentCorrelationState,
        ttl: timedelta,
        now: datetime,
    ) -> StatefulResolveResult:
        session = uow.session
        assert session is not None

        active_canonical_row = uow.incidents.get_for_update(state.incident_id)
        if (
            active_canonical_row is not None
            and incoming_bundle.incident_id == str(state.incident_id)
        ):
            # The incoming batch is deterministically identical to the
            # incident the (expired/out-of-window) active state still
            # points at - nothing new actually happened. Fabricating
            # generation+1 while reusing this exact same incident_id would
            # be misleading, so leave the generation/state pointer untouched
            # and report a no-op instead of a fake new generation.
            return self._result(
                "no_op",
                incoming_bundle,
                canonical_incident=active_canonical_row,
                canonical_incident_id=str(active_canonical_row.incident_id),
                correlation_key=correlation_key,
                generation=int(state.generation),
            )

        new_generation = int(state.generation) + 1
        canonical_row, _ = self._merge_service.create_canonical(
            uow,
            bundle=incoming_bundle,
            job=job,
            correlation_key=correlation_key,
            strategy=profile.strategy,
            correlation_version=profile.correlation_version,
            generation=new_generation,
        )
        session.flush()
        ok = uow.correlation_state.replace_expired_generation(
            correlation_key,
            expected_version=int(state.version),
            new_incident_id=str(canonical_row.incident_id),
            new_generation=new_generation,
            profile=profile.model_dump(mode="json"),
            first_seen=incoming_bundle.first_seen,
            last_seen=incoming_bundle.last_seen,
            expires_at=_compute_expires_at(now, incoming_bundle.last_seen, ttl),
            now=now,
        )
        if not ok:
            raise StatefulCorrelationError("stateful_correlation_state_conflict")
        session.expire(state)

        return self._result(
            "new_generation",
            incoming_bundle,
            canonical_incident=canonical_row,
            canonical_incident_id=str(canonical_row.incident_id),
            correlation_key=correlation_key,
            generation=new_generation,
            material_changes=("new_generation",),
        )

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _result(
        status: ResolveStatus,
        incoming_bundle: IncidentBundle,
        *,
        canonical_incident: Optional[Incident] = None,
        canonical_incident_id: Optional[str] = None,
        correlation_key: Optional[str] = None,
        generation: Optional[int] = None,
        material_changes: tuple[MaterialChangeCode, ...] = (),
        evidence_event_ids: tuple[str, ...] = (),
    ) -> StatefulResolveResult:
        return StatefulResolveResult(
            status=status,
            canonical_incident=canonical_incident,
            incoming_incident_id=incoming_bundle.incident_id,
            canonical_incident_id=canonical_incident_id,
            correlation_key=correlation_key,
            generation=generation,
            material_changes=material_changes,
            evidence_event_ids=evidence_event_ids,
        )

    @staticmethod
    def _reconstruct_canonical_evidence(
        uow: UnitOfWork,
        canonical_row: Incident,
        *,
        limit: int,
    ) -> list[DetectionEvidence]:
        """Rebuild bounded, deterministic DetectionEvidence for the canonical
        incident from persisted canonical events (the ORM incident has no
        evidence column, so mappers hydrate evidence empty and historical
        evidence would otherwise vanish across cross-job merges).

        Uses only safe structured fields and the sanitized message excerpt -
        never raw records or parser_metadata.
        """
        incident_event_ids = sorted(
            {e.event_id for e in canonical_row.events if not e.is_context}
        )[:limit]
        evidence: list[DetectionEvidence] = []
        for event_id in incident_event_ids:
            row = uow.canonical_events.get(event_id)
            if row is None:
                continue
            original_fields: dict[str, object] = {}
            for key, value in (
                ("src_ip", row.src_ip),
                ("dst_ip", row.dst_ip),
                ("src_port", row.src_port),
                ("dst_port", row.dst_port),
                ("protocol", row.protocol),
                ("action", row.action),
            ):
                if value is not None:
                    original_fields[key] = value
            quote = str(row.safe_message_excerpt or "")[:_EVIDENCE_QUOTE_MAX_CHARS]
            source = str(row.source_name or row.parser_name or "canonical_event")
            evidence.append(
                DetectionEvidence(
                    event_id=str(event_id),
                    quote=quote,
                    reason="persisted_incident_evidence",
                    source=source,
                    original_fields=original_fields,
                    correlation_context={},
                )
            )
        return evidence

    @staticmethod
    def _load_available_signals(
        uow: UnitOfWork,
        canonical_row: Incident,
        incoming_signal_rows: Sequence[OrmDetectionSignal],
    ) -> list[DetectionSignal]:
        def _normalized(signal: DetectionSignal) -> DetectionSignal:
            # See _as_utc: SQLite drops tzinfo on round-trip.
            return signal.model_copy(
                update={
                    "first_seen": _as_utc(signal.first_seen),
                    "last_seen": _as_utc(signal.last_seen),
                }
            )

        domain_signals: list[DetectionSignal] = []
        seen: set[str] = set()
        for row in incoming_signal_rows:
            if row.signal_id not in seen:
                domain_signals.append(_normalized(DataMapper.orm_to_domain_signal(row)))
                seen.add(str(row.signal_id))
        for signal_assoc in canonical_row.signals:
            signal_id = str(signal_assoc.signal_id)
            if signal_id in seen:
                continue
            orm_row = uow.detection_signals.get(signal_id)
            if orm_row is not None:
                domain_signals.append(_normalized(DataMapper.orm_to_domain_signal(orm_row)))
                seen.add(signal_id)
        return domain_signals
