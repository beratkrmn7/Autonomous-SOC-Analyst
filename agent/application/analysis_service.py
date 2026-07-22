import logging
import uuid
from dataclasses import replace
from functools import partial
from typing import Optional, List, Dict, Any, Sequence, cast
from agent.application.search_outbox import SearchOutboxService
from agent.persistence.unit_of_work import UnitOfWork
from agent.persistence.lifecycle import IncidentLifecycle
from agent.persistence.mappers import DataMapper
from agent.persistence.orm_models import (
    AuditEvent,
    CanonicalEvent,
    DetectionSignal,
    Incident,
    EvidenceItem,
    IngestionJob,
    Report,
    TriageRun,
)
from agent.application.models import AnalysisResult
from agent.ingestion.pipeline import IngestionPipeline
from agent.ingestion.models import CanonicalLogEvent
from agent.filtering import EventFilter
from agent.detection.config import DetectionSettings
from agent.detection.engine import DetectionEngine
from agent.detection.models import IncidentBundle
from agent.models import IncidentState
from agent.graph import app
from agent.triage.models import TriageIncidentContext
from agent.triage.routing import (
    DETERMINISTIC_TRIAGE_VERDICT,
    DigestMember,
    RoutingDecision,
    build_digest,
    decide_route,
    generate_deterministic_report,
)
from agent.application.cancellation import (
    JobCancellationChecker,
    JobCancellationRequested,
)
from agent.application.stateful_correlation_service import (
    StatefulIncidentCorrelationService,
    StatefulResolveResult,
    reconcile_existing_incident,
)
from agent.application.stateful_pipeline import (
    HydratedCanonicalIncident,
    hydrate_canonical_incident,
)
from sqlalchemy.sql import func
logger = logging.getLogger(__name__)


# Resolver statuses whose canonical incident is the final incident to route,
# triage and project. "unsupported"/"stale"/"disabled" fall back to the
# batch-local persistence path so no detection is ever discarded.
_CANONICAL_RESOLVE_STATUSES = frozenset(
    {"created", "merged", "no_op", "new_generation"}
)
_FALLBACK_RESOLVE_STATUSES = frozenset({"unsupported", "stale", "disabled"})

# Resolver statuses that warrant a bounded audit row (true no-ops never do).
_STATEFUL_AUDIT_ACTIONS = {
    "created": "stateful_correlation_created",
    "merged": "stateful_correlation_merged",
    "new_generation": "stateful_correlation_new_generation",
    "unsupported": "stateful_correlation_unsupported",
    "stale": "stateful_correlation_stale",
}

# Meaningfulness ranking used only to pick the single representative status
# when several resolver results converge on one final canonical incident; the
# union of material changes is preserved separately and never depends on this.
_RESOLVE_STATUS_RANK = {
    "disabled": 0,
    "no_op": 0,
    "created": 1,
    "unsupported": 1,
    "stale": 1,
    "merged": 2,
    "new_generation": 3,
}


def _new_stateful_metrics() -> Dict[str, int]:
    return {
        "incoming_batch_incident_count": 0,
        "final_canonical_incident_count": 0,
        "stateful_created_count": 0,
        "stateful_merged_count": 0,
        "stateful_no_op_count": 0,
        "stateful_new_generation_count": 0,
        "stateful_unsupported_count": 0,
        "stateful_stale_count": 0,
        "absorbed_batch_incident_count": 0,
    }


def _annotate_routing(state: IncidentState, decision: RoutingDecision, detection_confidence: float) -> None:
    state["triage_route"] = decision.route
    state["routing_reason"] = decision.reason
    state["triage_origin"] = decision.triage_origin
    state["llm_invoked"] = decision.llm_invoked
    state["detection_confidence"] = detection_confidence


def _stash_routing_in_incident_metrics(inc: IncidentBundle, decision: RoutingDecision) -> None:
    """Persist the routing decision in the existing Incident.metrics JSON column.

    This lets an idempotent hydration RESTORE the exact original route
    instead of recomputing it from hydrated canonical events, which do not
    round-trip every raw field (for example TCP flags and parser metadata)
    needed to safely re-derive a store_only SPI classification. No schema
    change is required since Incident.metrics already exists.
    """
    inc.metrics = {
        **inc.metrics,
        "triage_route": decision.route,
        "routing_reason": decision.reason,
        "triage_origin": decision.triage_origin,
        "llm_invoked": decision.llm_invoked,
    }


def _restore_or_recompute_route(
    inc: IncidentBundle,
    event_map: Dict[str, CanonicalLogEvent],
    signal_map: Dict[str, Any],
    settings: DetectionSettings,
) -> tuple[RoutingDecision, List[CanonicalLogEvent]]:
    """Restore a previously persisted routing decision, or recompute it.

    Used only when hydrating an idempotent completed result. Jobs persisted
    after this stash was introduced carry an exact, lossless record of the
    original decision in Incident.metrics; older rows without it fall back
    to a best-effort recompute from the reconstructed incident/events.
    """
    incident_events = [event_map[eid] for eid in inc.event_ids if eid in event_map]
    stored_route = inc.metrics.get("triage_route")
    if stored_route in (
        "individual_triage",
        "deterministic_report",
        "digest",
        "store_only",
    ):
        decision = RoutingDecision(
            route=cast(Any, stored_route),
            reason=str(inc.metrics.get("routing_reason", "")),
            triage_origin=cast(Any, inc.metrics.get("triage_origin", "deterministic")),
            llm_invoked=bool(inc.metrics.get("llm_invoked", False)),
        )
        return decision, incident_events

    decision, incident_events = _route_incident(inc, event_map, signal_map, settings)
    return decision, incident_events


def _route_incident(
    inc: IncidentBundle,
    event_map: Dict[str, CanonicalLogEvent],
    signal_map: Dict[str, Any],
    settings: DetectionSettings,
) -> tuple[RoutingDecision, List[CanonicalLogEvent]]:
    """Compute a routing decision the same way for fresh and hydrated incidents."""
    incident_events = [event_map[eid] for eid in inc.event_ids if eid in event_map]
    incident_context_events = [
        event_map[eid] for eid in inc.context_event_ids if eid in event_map
    ]
    rule_ids = frozenset(
        signal_map[sid].rule_id for sid in inc.signal_ids if sid in signal_map
    )
    decision = decide_route(
        inc, incident_events, incident_context_events, rule_ids, settings
    )
    return decision, incident_events


def _new_routing_metrics() -> Dict[str, int]:
    return {
        "total_incidents": 0,
        "individual_triage_count": 0,
        "deterministic_report_count": 0,
        "digest_incident_count": 0,
        "store_only_count": 0,
        "digest_count": 0,
        "provider_invocation_count": 0,
    }


class AnalysisService:
    def __init__(
        self,
        uow: Optional[Any] = None,
        cancellation_checker: Optional[JobCancellationChecker] = None,
        llm_enabled: Optional[bool] = None,
    ):
        if llm_enabled is None:
            from agent.config import get_settings

            llm_enabled = get_settings().llm_enabled
        self.uow = uow
        self.cancellation_checker = cancellation_checker
        self.llm_enabled = llm_enabled
        self.ingest = IngestionPipeline()
        self.filter_engine = EventFilter()
        self.detection_engine = DetectionEngine()

    def _raise_if_cancelled(self, job_id: Optional[str]) -> None:
        if job_id and self.cancellation_checker:
            self.cancellation_checker.raise_if_cancelled(job_id)

    def _create_or_update_job(self, uow: Any, result: AnalysisResult) -> IngestionJob:
        """Create a fresh completed job, or update the existing placeholder
        processing job (idempotency flow). Shared by both persistence paths."""
        job_id = result.job_id
        job: IngestionJob | None = None
        if result.ingestion_result and not job_id:
            job_id = str(uuid.uuid4())
            job = IngestionJob(
                id=job_id,
                idempotency_key=getattr(result, 'idempotency_key', None),
                file_sha256=getattr(result, 'file_sha256', None),
                pipeline_version=getattr(result, 'pipeline_version', None),
                analysis_mode=getattr(result, 'analysis_mode', None),
                source_name=result.ingestion_result.source_name,
                input_format=result.ingestion_result.input_format.value,
                total_records=result.ingestion_result.metrics.total_records,
                parsed_records=result.ingestion_result.metrics.parsed_records,
                failed_records=result.ingestion_result.metrics.failed_records,
                unsupported_records=result.ingestion_result.metrics.unsupported_records,
                duration_ms=result.ingestion_result.metrics.duration_ms,
                parser_counts=result.ingestion_result.metrics.parser_counts,
                error_counts=result.ingestion_result.metrics.error_counts,
                status="completed",
                completed_at=func.now()
            )
            uow.ingestion_jobs.add(job)
        elif job_id:
            job = uow.session.get(IngestionJob, job_id)
            if job and result.ingestion_result:
                job.total_records = result.ingestion_result.metrics.total_records
                job.parsed_records = result.ingestion_result.metrics.parsed_records
                job.failed_records = result.ingestion_result.metrics.failed_records
                job.unsupported_records = result.ingestion_result.metrics.unsupported_records
                job.semantically_invalid_records = getattr(result.ingestion_result.metrics, "semantically_invalid_records", 0)
                job.skipped_records = getattr(result.ingestion_result.metrics, "skipped_records", 0)
                job.bytes_read = getattr(result.ingestion_result.metrics, "bytes_read", 0)
                job.duration_ms = result.ingestion_result.metrics.duration_ms
                job.parser_counts = result.ingestion_result.metrics.parser_counts
                job.error_counts = result.ingestion_result.metrics.error_counts

        if job is None:
            raise RuntimeError("analysis_job_missing")
        return job

    def _persist_canonical_events(
        self, uow: UnitOfWork, job: IngestionJob, event_map: Dict[str, CanonicalLogEvent]
    ) -> list[CanonicalEvent]:
        """Persist canonical events and associate them with this job. Existing
        events are reused (never duplicated) and linked to the job."""
        persisted_events: list[CanonicalEvent] = []
        for event in event_map.values():
            orm_event = DataMapper.domain_event_to_orm(event)
            existing_event = uow.canonical_events.get_for_update(orm_event.event_id)
            if not existing_event:
                uow.canonical_events.add(orm_event)
                job.events.append(orm_event)
                persisted_events.append(orm_event)
            else:
                DataMapper.reconcile_existing_event(existing_event, orm_event)
                if existing_event not in job.events:
                    job.events.append(existing_event)
                persisted_events.append(existing_event)
        return persisted_events

    def _persist_current_job_signals(
        self, uow: UnitOfWork, job: IngestionJob, signals: list
    ) -> tuple[list[DetectionSignal], Dict[str, DetectionSignal]]:
        """Persist ONLY the signals detected during this job and associate
        them with this job. Returns the persisted rows plus a signal_id->row
        map. Historical canonical signals are never associated here."""
        persisted_signals: list[DetectionSignal] = []
        signal_row_by_id: Dict[str, DetectionSignal] = {}
        for signal in signals:
            orm_signal = DataMapper.domain_signal_to_orm(signal)
            existing_signal = uow.detection_signals.get_for_update(orm_signal.signal_id)
            if not existing_signal:
                uow.detection_signals.add(orm_signal)
                job.signals.append(orm_signal)
                persisted_signals.append(orm_signal)
                signal_row_by_id[str(orm_signal.signal_id)] = orm_signal
            else:
                DataMapper.reconcile_existing_signal(existing_signal, orm_signal)
                if existing_signal not in job.signals:
                    job.signals.append(existing_signal)
                persisted_signals.append(existing_signal)
                signal_row_by_id[str(existing_signal.signal_id)] = existing_signal
        return persisted_signals, signal_row_by_id

    def _persist_triage_outputs(
        self,
        uow: UnitOfWork,
        job: IngestionJob,
        inc_state: IncidentState,
        triage_incident: Incident,
        *,
        allow_lifecycle_transition: bool = True,
    ) -> None:
        """Persist the TriageRun, evidence and Report for one routed incident.

        digest/store_only never called a provider and produce no individual
        report, so they create no fabricated triage run, report, or lifecycle
        transition implying an agent reviewed the incident.

        `allow_lifecycle_transition` defaults True (the legacy batch-local
        behavior: transition unconditionally). The stateful path sets it False
        when the canonical incident is already past "new" (analyst-managed or
        triaged in a prior job), so a re-triage on new evidence never resets or
        invalidly transitions an analyst-managed status.
        """
        assert uow.session is not None
        route = inc_state.get("triage_route", "individual_triage")
        if route in ("digest", "store_only"):
            return

        incident_id = inc_state.get("incident_id")
        llm_invoked = bool(inc_state.get("llm_invoked", True))
        verdict = inc_state.get("triage_verdict")
        # Phase 6E.3: policy_adjustments has no dedicated column (no
        # migration); stash it in the existing token_usage JSON column,
        # which is otherwise unused here.
        token_usage = {"policy_adjustments": inc_state.get("policy_adjustments", [])}
        provider_unavailable = bool(
            route == "individual_triage"
            and not llm_invoked
            and inc_state.get("review_reason") == "provider_unavailable"
        )
        if llm_invoked:
            new_status = "triaged" if verdict else "needs_review"
            run = TriageRun(
                triage_run_id=str(uuid.uuid4()),
                job_id=job.id,
                incident_id=incident_id,
                verdict=verdict,
                severity=inc_state.get("severity"),
                confidence_score=inc_state.get("confidence_score"),
                incident_type=inc_state.get("incident_type"),
                iteration_count=inc_state.get("iteration_count", 0),
                status="completed" if verdict else "failed",
                token_usage=token_usage,
            )
        elif provider_unavailable:
            new_status = "needs_review"
            verdict = verdict or "needs_review"
            run = TriageRun(
                triage_run_id=str(uuid.uuid4()),
                job_id=job.id,
                incident_id=incident_id,
                verdict=verdict,
                severity=inc_state.get("severity"),
                confidence_score=inc_state.get("confidence_score"),
                incident_type=inc_state.get("incident_type"),
                review_reason="provider_unavailable",
                iteration_count=0,
                status="failed",
                token_usage=token_usage,
            )
        else:
            # deterministic_report: honestly represented with zero provider
            # iterations, using the preserved deterministic incident
            # type/severity/confidence. The persisted verdict is the valid
            # label "suspicious_activity", never the route name.
            new_status = "triaged"
            verdict = verdict or DETERMINISTIC_TRIAGE_VERDICT
            run = TriageRun(
                triage_run_id=str(uuid.uuid4()),
                job_id=job.id,
                incident_id=incident_id,
                verdict=verdict,
                severity=inc_state.get("severity"),
                confidence_score=inc_state.get("confidence_score"),
                incident_type=inc_state.get("incident_type"),
                iteration_count=0,
                provider="deterministic",
                status="completed",
                token_usage=token_usage,
            )

        if allow_lifecycle_transition:
            IncidentLifecycle.transition(
                triage_incident,
                new_status,
                actor_type=(
                    "triage_agent"
                    if llm_invoked
                    else "triage_system"
                    if provider_unavailable
                    else "deterministic_triage"
                ),
                actor_id="system",
                details={"verdict": verdict, "route": route},
            )
        uow.triage_runs.add(run)
        uow.session.flush()

        # Process Evidence from safe_triage_input which has full candidate records
        triage_input = inc_state.get("safe_triage_input", {})
        candidates = triage_input.get("candidate_evidence", [])
        valid_map = {e["evidence_id"]: e for e in inc_state.get("validated_evidence", [])}
        reject_map = {e["evidence_id"]: e for e in inc_state.get("rejected_evidence", [])}

        for cand in candidates:
            ev_id = cand.get("evidence_id")
            status = "candidate"
            rej_reason = None
            if ev_id in valid_map:
                status = "validated"
            elif ev_id in reject_map:
                status = "rejected"
                rej_reason = reject_map[ev_id].get("rejection_reason")
            evidence = EvidenceItem(
                evidence_id=ev_id or str(uuid.uuid4()),
                job_id=job.id,
                incident_id=incident_id,
                triage_run_id=run.id,
                event_id=cand.get("event_id"),
                quote=cand.get("quote")[:5000] if isinstance(cand.get("quote"), str) else str(cand.get("quote") or ""),
                reason=cand.get("reason")[:5000] if isinstance(cand.get("reason"), str) else str(cand.get("reason") or ""),
                source=cand.get("source"),
                validation_status=status,
                rejection_reason=rej_reason,
            )
            uow.evidence.add(evidence)

        if inc_state.get("final_report"):
            report = Report(
                report_id=str(uuid.uuid4()),
                job_id=job.id,
                incident_id=incident_id,
                triage_run_id=run.id,
                content=inc_state.get("final_report", "")[:15000] if isinstance(inc_state.get("final_report"), str) else str(inc_state.get("final_report", "")),
                entities=inc_state.get("entities", {}),
                recommended_actions=inc_state.get("recommended_actions", []),
                mitre_techniques=inc_state.get("mitre_techniques", []),
            )
            uow.reports.add(report)

    def _persist_analysis(self, result: AnalysisResult, run_triage: bool):
        with cast(UnitOfWork, self.uow) as uow:
            # 1. Ingestion Job
            job = self._create_or_update_job(uow, result)

            # 2. Canonical Events
            persisted_events = self._persist_canonical_events(uow, job, result.event_map)

            # 3. Detection Signals
            assert result.detection_result is not None
            persisted_signals, _ = self._persist_current_job_signals(
                uow, job, result.detection_result.signals
            )
                
            # 4. Incidents
            assert result.detection_result is not None
            persisted_incidents: list[Incident] = []
            for inc in result.detection_result.incidents:
                orm_inc = DataMapper.domain_incident_to_orm(inc)
                
                # Check idempotency/existing
                existing = uow.incidents.get_for_update(orm_inc.incident_id)
                if not existing:
                    uow.incidents.add(orm_inc)
                    job.incidents.append(orm_inc)
                    IncidentLifecycle.transition(orm_inc, "new", actor="detection_engine")
                    persisted_incidents.append(orm_inc)
                else:
                    changed = reconcile_existing_incident(
                        existing,
                        bundle=inc,
                        job=job,
                        max_context_events=(
                            self.detection_engine.settings.MAX_CONTEXT_EVENTS_PER_INCIDENT
                        ),
                    )
                    if changed:
                        # One optimistic/projection version increment for the
                        # complete scalar + association reconciliation.
                        existing.version = max(1, int(existing.version or 1)) + 1
                    persisted_incidents.append(existing)

            persisted_incident_by_id = {
                str(incident.incident_id): incident for incident in persisted_incidents
            }
            
            uow.session.flush() # Flush to get incident IDs ready for triage references
            
            # 5, 6, 7. Triage Run, Evidence, Report
            self._raise_if_cancelled(result.job_id)
            if run_triage:
                for inc_state in result.incidents:
                    incident_id = inc_state.get("incident_id")
                    if not incident_id:
                        continue
                    triage_incident = persisted_incident_by_id.get(str(incident_id))
                    if triage_incident:
                        self._persist_triage_outputs(uow, job, inc_state, triage_incident)

            # 7.5 OpenSearch Outbox Enqueue
            SearchOutboxService(
                uow.session,
                uow.search_index_outbox,
                uow.settings,
            ).enqueue_analysis(
                events=persisted_events,
                signals=persisted_signals,
                incidents=persisted_incidents,
            )
                            
            # 8. Complete only if the database still grants this processing lease.
            # This conditional update is the final cancellation-vs-completion arbiter.
            if result.job_id:
                completed = uow.session.query(IngestionJob).filter(
                    IngestionJob.id == result.job_id,
                    IngestionJob.status == "processing",
                ).update({
                    "status": "completed",
                    "completed_at": func.now(),
                    "lease_expires_at": None,
                    "next_retry_at": None,
                }, synchronize_session=False)
                if completed != 1:
                    raise JobCancellationRequested(result.job_id)
            # Commit happens on context exit. Any cancellation exception rolls
            # back all incidents, triage runs, evidence, and reports above.

    # ------------------------------------------------------------------
    # Phase 6E.4: stateful persistent cross-job correlation integration.
    # ------------------------------------------------------------------

    def _complete_job(self, uow: UnitOfWork, job_id: Optional[str]) -> None:
        """Flip a placeholder processing job to completed, only while the DB
        still grants this processing lease (final cancellation arbiter)."""
        if not job_id:
            return
        assert uow.session is not None
        completed = uow.session.query(IngestionJob).filter(
            IngestionJob.id == job_id,
            IngestionJob.status == "processing",
        ).update({
            "status": "completed",
            "completed_at": func.now(),
            "lease_expires_at": None,
            "next_retry_at": None,
        }, synchronize_session=False)
        if completed != 1:
            raise JobCancellationRequested(job_id)

    def _persist_batch_local_incident(
        self, uow: UnitOfWork, job: IngestionJob, bundle: IncidentBundle
    ) -> Incident:
        """Legacy batch-local incident persistence, used as the fail-closed
        fallback for unsupported/stale resolver outcomes so no detection is
        ever discarded."""
        orm_inc = DataMapper.domain_incident_to_orm(bundle)
        existing = uow.incidents.get_for_update(orm_inc.incident_id)
        if not existing:
            uow.incidents.add(orm_inc)
            job.incidents.append(orm_inc)
            IncidentLifecycle.transition(orm_inc, "new", actor="detection_engine")
            return orm_inc
        changed = reconcile_existing_incident(
            existing,
            bundle=bundle,
            job=job,
            max_context_events=(
                self.detection_engine.settings.MAX_CONTEXT_EVENTS_PER_INCIDENT
            ),
        )
        if changed:
            existing.version = max(1, int(existing.version or 1)) + 1
        return existing

    @staticmethod
    def _account_stateful_status(status: str, metrics: Dict[str, int]) -> None:
        key = {
            "created": "stateful_created_count",
            "merged": "stateful_merged_count",
            "no_op": "stateful_no_op_count",
            "new_generation": "stateful_new_generation_count",
            "unsupported": "stateful_unsupported_count",
            "stale": "stateful_stale_count",
        }.get(status)
        if key is not None:
            metrics[key] += 1

    @staticmethod
    def _combine_resolves(
        results: List[StatefulResolveResult],
    ) -> StatefulResolveResult:
        """Aggregate every resolver result that landed on one final canonical
        incident during this job into a single deterministic result.

        Several incoming batch incidents (for example a horizontal_scan then a
        service-specific rdp_probe) can all resolve to one canonical incident,
        and a later merged/new-generation result may add events, signals,
        context, a job association, or promote the primary identity. Keeping
        only the first result (a plain setdefault) would silently drop those.
        The union of material_changes is preserved and sorted; the final
        generation and correlation key come from the last result; and the
        representative status is the most meaningful one for hydration/routing.
        """
        material: set[str] = set()
        for r in results:
            material.update(r.material_changes)
        representative = max(
            results, key=lambda r: _RESOLVE_STATUS_RANK.get(r.status, 0)
        )
        last = results[-1]
        return replace(
            representative,
            material_changes=tuple(sorted(material)),
            generation=last.generation,
            correlation_key=last.correlation_key,
            canonical_incident=(
                last.canonical_incident
                if last.canonical_incident is not None
                else representative.canonical_incident
            ),
            canonical_incident_id=(
                last.canonical_incident_id or representative.canonical_incident_id
            ),
        )

    def _add_stateful_audit(
        self,
        uow: UnitOfWork,
        incident_row: Incident,
        combined: StatefulResolveResult,
        results: List[StatefulResolveResult],
    ) -> None:
        """Bounded audit event(s) for the meaningful stateful outcomes on one
        final canonical incident. One row per distinct meaningful status (never
        for a true no-op), each carrying the combined/unioned material changes,
        plus a single identity-promotion row when the union promoted the
        primary identity - even if the promotion came from a later result.
        Never carries event/signal/job ID lists."""
        incident_id = str(incident_row.incident_id)
        distinct_statuses = sorted(
            {r.status for r in results if r.status in _STATEFUL_AUDIT_ACTIONS}
        )
        for status in distinct_statuses:
            self._add_audit_row(
                uow, incident_id, _STATEFUL_AUDIT_ACTIONS[status], combined, status
            )
        if "primary_identity_promoted" in combined.material_changes:
            self._add_audit_row(
                uow,
                incident_id,
                "stateful_identity_promoted",
                combined,
                combined.status,
            )

    @staticmethod
    def _add_audit_row(
        uow: UnitOfWork,
        incident_id: str,
        action: str,
        combined: StatefulResolveResult,
        status_for_details: str,
    ) -> None:
        audit = AuditEvent(
            audit_event_id=f"ae_{uuid.uuid4().hex}",
            incident_id=incident_id,
            event_type="stateful_correlation",
            entity_type="incident",
            entity_id=incident_id,
            action=action,
            actor="system",
            actor_type="stateful_correlation",
            actor_id="system",
            details={
                "status": status_for_details,
                "correlation_key": combined.correlation_key,
                "generation": combined.generation,
                "material_changes": sorted(combined.material_changes),
            },
        )
        uow.audit_events.add(audit)

    @staticmethod
    def _stash_routing_on_row(incident_row: Incident, decision: RoutingDecision) -> None:
        incident_row.metrics = {  # type: ignore[assignment]
            **(dict(incident_row.metrics or {})),
            "triage_route": decision.route,
            "routing_reason": decision.reason,
            "triage_origin": decision.triage_origin,
            "llm_invoked": decision.llm_invoked,
        }

    def _process_events_stateful(
        self,
        result: AnalysisResult,
        run_triage: bool,
        job_id: Optional[str],
        stateful_correlation_enabled: Optional[bool] = None,
    ) -> AnalysisResult:
        det_result = result.detection_result
        assert det_result is not None
        det_settings = self.detection_engine.settings
        resolver = StatefulIncidentCorrelationService()

        stateful_metrics = _new_stateful_metrics()
        routing_metrics = _new_routing_metrics()
        digest_groups: Dict[str, List[DigestMember]] = {}
        incident_states: List[IncidentState] = []
        final_incidents_domain: List[IncidentBundle] = []

        try:
            self._raise_if_cancelled(job_id)
            with cast(UnitOfWork, self.uow) as uow:
                settings = uow.settings
                # Phases 4-7: job, canonical events, current-job signals, flush.
                job = self._create_or_update_job(uow, result)
                persisted_events = self._persist_canonical_events(
                    uow, job, result.event_map
                )
                persisted_signals, signal_row_by_id = (
                    self._persist_current_job_signals(uow, job, det_result.signals)
                )
                uow.session.flush()

                # Phase 8: resolve every incoming batch incident. Every result
                # that lands on one final canonical incident is collected (not
                # just the first), so a later merge/new-generation/identity
                # promotion is never hidden by an earlier created result.
                final_rows: Dict[str, Incident] = {}
                resolves_by_final_id: Dict[str, List[StatefulResolveResult]] = {}
                fallbacks: List[tuple] = []
                for inc in det_result.incidents:
                    stateful_metrics["incoming_batch_incident_count"] += 1
                    incoming_events = [
                        result.event_map[eid]
                        for eid in inc.event_ids
                        if eid in result.event_map
                    ]
                    incoming_signal_rows = [
                        signal_row_by_id[sid]
                        for sid in inc.signal_ids
                        if sid in signal_row_by_id
                    ]
                    r = resolver.resolve_and_merge(
                        uow,
                        incoming_bundle=inc,
                        incoming_events=incoming_events,
                        incoming_signal_rows=incoming_signal_rows,
                        job=job,
                        settings=settings,
                        detection_settings=det_settings,
                        enabled=stateful_correlation_enabled,
                    )
                    self._raise_if_cancelled(job_id)
                    self._account_stateful_status(r.status, stateful_metrics)
                    if r.status in _CANONICAL_RESOLVE_STATUSES:
                        row = cast(Incident, r.canonical_incident)
                        final_id = str(row.incident_id)
                        final_rows[final_id] = row
                        resolves_by_final_id.setdefault(final_id, []).append(r)
                    else:
                        # unsupported / stale / disabled: fail closed to the
                        # batch-local path so the detection is never lost.
                        fallbacks.append((inc, r))

                for inc, r in fallbacks:
                    row = self._persist_batch_local_incident(uow, job, inc)
                    final_id = str(row.incident_id)
                    final_rows.setdefault(final_id, row)
                    resolves_by_final_id.setdefault(final_id, []).append(r)

                uow.session.flush()

                # One combined, deterministic result per final canonical
                # incident (unioned material changes, final generation/key).
                combined_by_final_id: Dict[str, StatefulResolveResult] = {
                    fid: self._combine_resolves(rs)
                    for fid, rs in resolves_by_final_id.items()
                }

                stateful_metrics["final_canonical_incident_count"] = len(final_rows)
                stateful_metrics["absorbed_batch_incident_count"] = max(
                    0,
                    stateful_metrics["incoming_batch_incident_count"] - len(final_rows),
                )

                # Bounded audit events after every final incident row exists.
                for final_id, row in final_rows.items():
                    combined = combined_by_final_id.get(final_id)
                    if combined is not None:
                        self._add_stateful_audit(
                            uow, row, combined, resolves_by_final_id[final_id]
                        )

                current_job_event_ids = set(result.event_map.keys())
                current_job_signal_ids = set(signal_row_by_id.keys())

                # Phases 9-11: hydrate, route and triage each unique final
                # incident exactly once.
                for final_id in sorted(final_rows):
                    row = final_rows[final_id]
                    self._raise_if_cancelled(job_id)
                    final_resolve = combined_by_final_id.get(final_id)
                    row_event_ids = {str(e.event_id) for e in row.events}
                    primary_event_ids = {
                        str(event.event_id)
                        for event in row.events
                        if not event.is_context
                    }
                    current_primary_event_ids = (
                        primary_event_ids & current_job_event_ids
                    )
                    row.metrics = {  # type: ignore[assignment]
                        **dict(row.metrics or {}),
                        "contributing_job_count": len(row.jobs),
                        "current_job_event_count": len(current_primary_event_ids),
                        "prior_job_event_count": len(
                            primary_event_ids - current_job_event_ids
                        ),
                    }
                    row_signal_ids = {str(s.signal_id) for s in row.signals}
                    hydrated = hydrate_canonical_incident(
                        uow,
                        row,
                        resolve_status=(final_resolve.status if final_resolve else "fallback"),
                        correlation_key=(final_resolve.correlation_key if final_resolve else None),
                        generation=(final_resolve.generation if final_resolve else None),
                        material_changes=(final_resolve.material_changes if final_resolve else ()),
                        current_job_event_ids=sorted(
                            row_event_ids & current_job_event_ids
                        ),
                        current_job_signal_ids=sorted(
                            row_signal_ids & current_job_signal_ids
                        ),
                    )
                    final_incidents_domain.append(hydrated.bundle)
                    state = self._route_and_triage_final(
                        uow,
                        job,
                        row,
                        hydrated,
                        run_triage,
                        job_id,
                        routing_metrics,
                        digest_groups,
                        det_settings,
                    )
                    incident_states.append(state)

                result.triage_digests = [
                    build_digest(incident_type, members)
                    for incident_type, members in sorted(digest_groups.items())
                ]
                routing_metrics["digest_count"] = len(result.triage_digests)

                # Phase 12: enqueue final canonical/fallback projections once.
                SearchOutboxService(
                    uow.session, uow.search_index_outbox, settings
                ).enqueue_analysis(
                    events=persisted_events,
                    signals=persisted_signals,
                    incidents=list(final_rows.values()),
                )

                # Phase 13: complete the job; commit on context exit.
                self._complete_job(uow, result.job_id)

        except JobCancellationRequested:
            raise
        except Exception as e:
            logger.error(
                "Stateful analysis failed",
                exc_info=False,
                extra={
                    "error": type(e).__name__,
                    "error_msg": str(e),
                    "job_id": getattr(result, "job_id", None),
                },
            )
            if getattr(result, "job_id", None):
                with cast(UnitOfWork, self.uow) as uow:
                    job = uow.session.query(IngestionJob).get(result.job_id)
                    if job:
                        job.status = "failed"
                        job.error_code = (
                            "PERSISTENCE_INTEGRITY_ERROR"
                            if "IntegrityError" in str(type(e))
                            else "INTERNAL_ANALYSIS_ERROR"
                        )
                        uow.session.commit()
            raise

        result.incidents = incident_states
        result.routing_metrics = routing_metrics
        result.stateful_metrics = stateful_metrics
        # Return a copied final DetectionResult carrying the unique final
        # canonical/fallback incidents; the original engine result is never
        # mutated, and current-job signals are never presented as historical.
        result.detection_result = det_result.model_copy(
            update={
                "incidents": final_incidents_domain,
                "metrics": det_result.metrics.model_copy(
                    update={"incident_count": len(final_incidents_domain)}
                ),
            }
        )
        return result

    def _route_and_triage_final(
        self,
        uow: UnitOfWork,
        job: IngestionJob,
        row: Incident,
        hydrated: HydratedCanonicalIncident,
        run_triage: bool,
        job_id: Optional[str],
        routing_metrics: Dict[str, int],
        digest_groups: Dict[str, List[DigestMember]],
        det_settings: DetectionSettings,
    ) -> IncidentState:
        """Route and (for analyze mode) triage one final canonical incident.

        Detect mode (run_triage=False) never routes, triages, or creates
        TriageRun/Report rows. Analyze mode routes on the fully hydrated
        canonical identity and invokes the provider at most once, only for
        the individual_triage route.
        """
        bundle = hydrated.bundle
        initial_state = self._build_initial_state(
            bundle, hydrated.event_map, hydrated.signal_map,
            current_job_event_ids=hydrated.current_job_event_ids,
            current_job_signal_ids=hydrated.current_job_signal_ids,
        )
        if job_id and self.cancellation_checker:
            initial_state["cancellation_check"] = partial(
                self._raise_if_cancelled, job_id
            )

        if not run_triage:
            # Detect mode: persist and project only, zero provider calls.
            return initial_state

        routing_metrics["total_incidents"] += 1
        decision, incident_events = _route_incident(
            bundle, hydrated.event_map, hydrated.signal_map, det_settings
        )
        self._stash_routing_on_row(row, decision)
        _annotate_routing(initial_state, decision, bundle.confidence)
        # Only fresh (status "new") incidents get an initial lifecycle
        # transition; an already-triaged or analyst-managed canonical
        # incident keeps its status on a re-triage.
        allow_transition = str(row.status) == "new"

        if decision.route == "individual_triage":
            routing_metrics["individual_triage_count"] += 1
            if not self.llm_enabled:
                initial_state["llm_invoked"] = False
                initial_state["triage_verdict"] = "needs_review"
                initial_state["review_reason"] = "provider_unavailable"
                initial_state["incident_type"] = bundle.incident_type
                initial_state["severity"] = "none"
                initial_state["confidence_score"] = 0.0
                self._persist_triage_outputs(
                    uow,
                    job,
                    initial_state,
                    row,
                    allow_lifecycle_transition=allow_transition,
                )
                return initial_state
            routing_metrics["provider_invocation_count"] += 1
            try:
                self._raise_if_cancelled(job_id)
                final_state = cast(IncidentState, app.invoke(initial_state))
                self._raise_if_cancelled(job_id)
                _annotate_routing(final_state, decision, bundle.confidence)
                self._persist_triage_outputs(
                    uow, job, final_state, row,
                    allow_lifecycle_transition=allow_transition,
                )
                return final_state
            except JobCancellationRequested:
                raise
            except Exception as e:
                logger.error(
                    "Error during triage",
                    exc_info=False,
                    extra={
                        "error": type(e).__name__,
                        "error_msg": str(e),
                        "incident_id": initial_state.get("incident_id"),
                    },
                )
                self._persist_triage_outputs(
                    uow, job, initial_state, row,
                    allow_lifecycle_transition=allow_transition,
                )
                return initial_state

        # Deterministic-origin routes below never call a provider.
        initial_state["incident_type"] = bundle.incident_type
        initial_state["severity"] = bundle.severity
        initial_state["confidence_score"] = bundle.confidence

        if decision.route == "deterministic_report":
            routing_metrics["deterministic_report_count"] += 1
            initial_state["final_report"] = generate_deterministic_report(
                bundle, incident_events
            )
            initial_state["triage_verdict"] = DETERMINISTIC_TRIAGE_VERDICT
            initial_state["iteration_count"] = 0
            self._persist_triage_outputs(
                uow, job, initial_state, row,
                allow_lifecycle_transition=allow_transition,
            )
        elif decision.route == "digest":
            routing_metrics["digest_incident_count"] += 1
            digest_groups.setdefault(bundle.incident_type, []).append(
                DigestMember(
                    incident_id=bundle.incident_id,
                    primary_entity=bundle.primary_entity,
                    events=incident_events,
                    first_seen=bundle.first_seen,
                    last_seen=bundle.last_seen,
                )
            )
        else:
            routing_metrics["store_only_count"] += 1

        return initial_state

    def analyze_file(self, file_path: str, *, run_triage: bool = True, source_name: Optional[str] = None, file_sha256: Optional[str] = None, idempotency_key: Optional[str] = None, pipeline_version: Optional[str] = None, analysis_mode: Optional[str] = None, job_id: Optional[str] = None, stateful_correlation_enabled: Optional[bool] = None) -> AnalysisResult:
        # 1. Check Idempotency if key is provided and job_id is NOT provided
        from agent.persistence.orm_models import IngestionJob
        import uuid
        from sqlalchemy.exc import IntegrityError
        from agent.application.errors import DuplicateAnalysisError
        from sqlalchemy.sql import func
        from agent.persistence.mappers import DataMapper
        
        if self.uow and idempotency_key and not job_id:
            with cast(UnitOfWork, self.uow) as uow:
                job = uow.session.query(IngestionJob).filter_by(idempotency_key=idempotency_key).first()
                if job:
                    if job.status == "processing":
                        raise DuplicateAnalysisError(status="processing")
                    elif job.status == "failed":
                        # Retry
                        job.status = "processing"
                        job.reused_count += 1
                        job.last_requested_at = func.now()
                        uow.session.commit()
                        job_id = job.id
                    elif job.status == "completed":
                        # Hydrate results from DB
                        job.reused_count += 1
                        job.last_requested_at = func.now()
                        uow.session.commit()
                        
                        # Hydrate Ingestion Result
                        from agent.ingestion.models import IngestionResult, IngestionMetrics, InputFormat
                        ingestion_metrics = IngestionMetrics(
                            total_records=job.total_records or 0,
                            parsed_records=job.parsed_records or 0,
                            failed_records=job.failed_records or 0,
                            unsupported_records=job.unsupported_records or 0,
                            semantically_invalid_records=job.semantically_invalid_records or 0,
                            skipped_records=job.skipped_records or 0,
                            bytes_read=job.bytes_read or 0,
                            duration_ms=job.duration_ms or 0,
                            parser_counts=job.parser_counts or {},
                            error_counts=job.error_counts or {}
                        )
                        ingestion_result = IngestionResult(
                            source_name=job.source_name,
                            input_format=InputFormat(job.input_format) if job.input_format else InputFormat.UNKNOWN,
                            events=[],
                            metrics=ingestion_metrics
                        )

                        # Build AnalysisResult from DB
                        result = AnalysisResult(
                            source_name=job.source_name,
                            job_id=job.id,
                            reused=True,
                            idempotency_status="reused_completed_result",
                            ingestion_result=ingestion_result,
                            event_map={},
                            signal_map={},
                            incidents=[]
                        )
                        # We fully reconstruct everything from the DB
                        from agent.detection.models import DetectionResult
                        from agent.detection.models import DetectionMetrics
                        
                        # Reconstruct Events
                        for ev in job.events:
                            domain_ev = DataMapper.orm_to_domain_event(ev)
                            result.event_map[domain_ev.event_id] = domain_ev
                            
                        # Reconstruct Signals
                        result.detection_result = DetectionResult(
                            signals=[], 
                            incidents=[], 
                            suppressed_signals=[], 
                            uncorrelated_event_ids=[], 
                            warnings=[], 
                            metrics=DetectionMetrics(
                                signal_count=len(job.signals), 
                                duration_ms=0.0
                            )
                        )
                        for sig in job.signals:
                            domain_sig = DataMapper.orm_to_domain_signal(sig)
                            result.detection_result.signals.append(domain_sig)
                            result.signal_map[domain_sig.signal_id] = domain_sig

                        # Reconstruct Incidents
                        routing_metrics = _new_routing_metrics()
                        digest_groups: Dict[str, List[DigestMember]] = {}
                        for inc in job.incidents:
                            domain_inc = DataMapper.orm_to_domain_incident(inc)
                            result.detection_result.incidents.append(domain_inc)

                            # Use the same exact builder logic to hydrate state
                            state = self._build_initial_state(domain_inc, result.event_map, result.signal_map)

                            # Restore the exact original routing decision from
                            # Incident.metrics when available (always true for
                            # jobs persisted after this stash was introduced);
                            # only recompute as a best-effort fallback for
                            # older rows, since hydrated canonical events do
                            # not round-trip every raw field a fresh
                            # recomputation would need.
                            decision, incident_events = _restore_or_recompute_route(
                                domain_inc,
                                result.event_map,
                                result.signal_map,
                                self.detection_engine.settings,
                            )
                            _annotate_routing(state, decision, domain_inc.confidence)
                            state["incident_type"] = domain_inc.incident_type
                            state["severity"] = domain_inc.severity
                            state["confidence_score"] = domain_inc.confidence

                            routing_metrics["total_incidents"] += 1
                            if decision.route == "individual_triage":
                                # The restored route and its llm_invoked/origin
                                # metadata describe how the stored report was
                                # ORIGINALLY produced. This is a whole-job replay
                                # served from persistence: no provider is invoked
                                # for this request, so provider_invocation_count
                                # stays 0 and is never confused with a live call.
                                routing_metrics["individual_triage_count"] += 1
                            elif decision.route == "deterministic_report":
                                routing_metrics["deterministic_report_count"] += 1
                            elif decision.route == "digest":
                                routing_metrics["digest_incident_count"] += 1
                                digest_groups.setdefault(domain_inc.incident_type, []).append(
                                    DigestMember(
                                        incident_id=domain_inc.incident_id,
                                        primary_entity=domain_inc.primary_entity,
                                        events=incident_events,
                                        first_seen=domain_inc.first_seen,
                                        last_seen=domain_inc.last_seen,
                                    )
                                )
                            else:
                                routing_metrics["store_only_count"] += 1

                            triage_runs = [tr for tr in job.triage_runs if tr.incident_id == inc.incident_id]
                            if triage_runs:
                                last_run = sorted(triage_runs, key=lambda r: r.started_at, reverse=True)[0]
                                state["triage_verdict"] = last_run.verdict
                                state["incident_type"] = last_run.incident_type
                                state["severity"] = last_run.severity
                                state["confidence_score"] = last_run.confidence_score
                                state["iteration_count"] = last_run.iteration_count
                                state["policy_adjustments"] = (
                                    (last_run.token_usage or {}).get("policy_adjustments", [])
                                )


                                reports = [rp for rp in job.reports if rp.triage_run_id == last_run.id]
                                if reports:
                                    state["final_report"] = reports[0].content
                                    state["report_content_sha256"] = reports[0].content_sha256
                                    state["mitre_techniques"] = reports[0].mitre_techniques or []
                                    state["recommendations"] = reports[0].recommended_actions or []
                                    if reports[0].entities:
                                        pass # Could load other entities if needed
                                    
                                # Hydrate Evidence
                                run_evidence = [ev for ev in job.evidence_items if ev.triage_run_id == last_run.id]
                                if run_evidence:
                                    state["candidate_evidence"] = []
                                    state["validated_evidence"] = []
                                    state["rejected_evidence"] = []
                                    for ev in run_evidence:
                                        ev_dict = {
                                            "evidence_id": ev.evidence_id,
                                            "event_id": ev.event_id,
                                            "quote": ev.quote,
                                            "reason": ev.reason,
                                            "source": ev.source,
                                            "validation_status": ev.validation_status,
                                            "rejection_reason": ev.rejection_reason
                                        }
                                        if ev.validation_status == "validated":
                                            state["validated_evidence"].append(ev_dict)
                                        elif ev.validation_status == "rejected":
                                            state["rejected_evidence"].append(ev_dict)
                                        else:
                                            state["candidate_evidence"].append(ev_dict)
                                    
                            result.incidents.append(state)

                        result.triage_digests = [
                            build_digest(incident_type, members)
                            for incident_type, members in sorted(digest_groups.items())
                        ]
                        routing_metrics["digest_count"] = len(result.triage_digests)
                        result.routing_metrics = routing_metrics

                        return result
                else:
                    # Create placeholder processing job
                    job_id = str(uuid.uuid4())
                    job = IngestionJob(
                        id=job_id,
                        idempotency_key=idempotency_key,
                        file_sha256=file_sha256,
                        pipeline_version=pipeline_version,
                        analysis_mode=analysis_mode,
                        status="processing",
                        source_name=source_name or "api"
                    )
                    uow.ingestion_jobs.add(job)
                    try:
                        uow.session.commit()
                    except IntegrityError:
                        uow.session.rollback()
                        # Race condition lost, another thread inserted it
                        raise DuplicateAnalysisError(status="processing")

        # 2. Ingestion
        self._raise_if_cancelled(job_id)
        ingest_result = self.ingest.ingest_file(file_path)
        self._raise_if_cancelled(job_id)
        
        # 3. Process Events
        res = self._process_events(
            events=ingest_result.events,
            run_triage=run_triage,
            ingestion_result=ingest_result,
            source_name=source_name or ingest_result.source_name,
            job_id=job_id,
            file_sha256=file_sha256,
            idempotency_key=idempotency_key,
            pipeline_version=pipeline_version,
            analysis_mode=analysis_mode,
            stateful_correlation_enabled=stateful_correlation_enabled,
        )
        return res

    def analyze_events(self, events: List[CanonicalLogEvent], *, run_triage: bool = True) -> AnalysisResult:
        return self._process_events(
            events=events,
            run_triage=run_triage,
            ingestion_result=None,
            source_name="api",
            job_id=None
        )

    def _process_events(self, events: List[CanonicalLogEvent], run_triage: bool, ingestion_result: Any, source_name: str, job_id: Optional[str] = None, file_sha256: Optional[str] = None, idempotency_key: Optional[str] = None, pipeline_version: Optional[str] = None, analysis_mode: Optional[str] = None, stateful_correlation_enabled: Optional[bool] = None) -> AnalysisResult:
        # 2. Filtering
        filter_result = self.filter_engine.filter_events(events)
        
        # 3. Detection
        # EventFilter assigns reporting/context roles; DetectionEngine owns
        # eligibility and rule-level relevance. Passing the original collection
        # keeps context and probable-noise events available to sequence rules.
        det_result = self.detection_engine.analyze(events, filter_result.context)
        self._raise_if_cancelled(job_id)
        
        event_map = {e.event_id: e for e in events if e.event_id}
        signal_map = {s.signal_id: s for s in det_result.signals}
        
        result = AnalysisResult(
            source_name=source_name,
            ingestion_result=ingestion_result,
            detection_result=det_result,
            event_map=event_map,
            signal_map=signal_map,
            incidents=[],
            job_id=job_id,
            file_sha256=file_sha256,
            idempotency_key=idempotency_key,
            pipeline_version=pipeline_version,
            analysis_mode=analysis_mode
        )
        
        # Phase 6E.4: when persistent cross-job correlation is enabled and a
        # UnitOfWork is present, resolve final canonical incidents inside one
        # transaction (persist events/signals -> flush -> resolve -> hydrate ->
        # route -> triage -> outbox -> commit) before returning. The legacy
        # batch-local path below is preserved verbatim when the flag is off or
        # no persistence backend is available.
        if (
            self.uow is not None
            and (
                cast(UnitOfWork, self.uow).settings.stateful_correlation_enabled
                or stateful_correlation_enabled is True
            )
        ):
            return self._process_events_stateful(
                result,
                run_triage,
                job_id,
                stateful_correlation_enabled=stateful_correlation_enabled,
            )

        # 4. Persistence setup (Optional Phase 5 integration point)
        # If we have a Unit Of Work, we can persist the canonical events, signals, and incidents here.
        # This will be done after triage, to ensure a single transaction.

        # 5. Deterministic routing and graph invocation (Triage)
        routing_metrics = _new_routing_metrics()
        digest_groups: Dict[str, List[DigestMember]] = {}

        for inc in det_result.incidents:
            initial_state = self._build_initial_state(inc, event_map, signal_map)
            if job_id and self.cancellation_checker:
                initial_state["cancellation_check"] = partial(
                    self._raise_if_cancelled, job_id
                )

            if not run_triage:
                result.incidents.append(initial_state)
                continue

            routing_metrics["total_incidents"] += 1
            decision, incident_events = _route_incident(
                inc, event_map, signal_map, self.detection_engine.settings
            )
            _stash_routing_in_incident_metrics(inc, decision)

            _annotate_routing(initial_state, decision, inc.confidence)

            if decision.route == "individual_triage":
                routing_metrics["individual_triage_count"] += 1
                if not self.llm_enabled:
                    initial_state["llm_invoked"] = False
                    initial_state["triage_verdict"] = "needs_review"
                    initial_state["review_reason"] = "provider_unavailable"
                    initial_state["incident_type"] = inc.incident_type
                    initial_state["severity"] = "none"
                    initial_state["confidence_score"] = 0.0
                    result.incidents.append(initial_state)
                    continue
                routing_metrics["provider_invocation_count"] += 1
                try:
                    self._raise_if_cancelled(job_id)
                    final_state = cast(IncidentState, app.invoke(initial_state))
                    self._raise_if_cancelled(job_id)
                    _annotate_routing(final_state, decision, inc.confidence)
                    result.incidents.append(final_state)
                except JobCancellationRequested:
                    raise
                except Exception as e:
                    logger.error("Error during triage", exc_info=False, extra={"error": type(e).__name__, "error_msg": str(e), "incident_id": initial_state.get("incident_id")})
                    result.incidents.append(initial_state)
                continue

            # Deterministic-origin routes below never call a provider.
            initial_state["incident_type"] = inc.incident_type
            initial_state["severity"] = inc.severity
            initial_state["confidence_score"] = inc.confidence

            if decision.route == "deterministic_report":
                routing_metrics["deterministic_report_count"] += 1
                initial_state["final_report"] = generate_deterministic_report(
                    inc, incident_events
                )
                initial_state["triage_verdict"] = DETERMINISTIC_TRIAGE_VERDICT
                initial_state["iteration_count"] = 0
            elif decision.route == "digest":
                routing_metrics["digest_incident_count"] += 1
                digest_groups.setdefault(inc.incident_type, []).append(
                    DigestMember(
                        incident_id=inc.incident_id,
                        primary_entity=inc.primary_entity,
                        events=incident_events,
                        first_seen=inc.first_seen,
                        last_seen=inc.last_seen,
                    )
                )
            else:
                routing_metrics["store_only_count"] += 1

            result.incidents.append(initial_state)

        result.triage_digests = [
            build_digest(incident_type, members)
            for incident_type, members in sorted(digest_groups.items())
        ]
        routing_metrics["digest_count"] = len(result.triage_digests)
        result.routing_metrics = routing_metrics

        # 6. Persistence
        if self.uow:
            try:
                self._raise_if_cancelled(job_id)
                self._persist_analysis(result, run_triage)
            except JobCancellationRequested:
                raise
            except Exception as e:
                # If we fail during persistence, mark the job as failed
                logger.error("Persistence failed", exc_info=False, extra={"error": type(e).__name__, "error_msg": str(e), "job_id": getattr(result, "job_id", None)})
                if getattr(result, "job_id", None):
                    with cast(UnitOfWork, self.uow) as uow:
                        from agent.persistence.orm_models import IngestionJob
                        job = uow.session.query(IngestionJob).get(result.job_id)
                        if job:
                            job.status = "failed"
                            # Determine machine-readable error code
                            if "IntegrityError" in str(type(e)):
                                job.error_code = "PERSISTENCE_INTEGRITY_ERROR"
                            else:
                                job.error_code = "INTERNAL_ANALYSIS_ERROR"
                            uow.session.commit()
                raise
                
        return result

    def _build_initial_state(
        self,
        incident: Any,
        event_map: Dict[str, CanonicalLogEvent],
        signal_map: Dict[str, Any],
        *,
        current_job_event_ids: Sequence[str] = (),
        current_job_signal_ids: Sequence[str] = (),
    ) -> IncidentState:
        # Reconstruct the logic that was duplicated in main.py and server.py
        if isinstance(incident, dict):
            incident_id = incident.get("incident_id")
            event_ids = incident.get("event_ids", [])
            context_event_ids = incident.get("context_event_ids", [])
            signal_ids = incident.get("signal_ids", [])
            evidence_list = incident.get("evidence", [])
            incident_bundle = incident
        else:
            incident_id = getattr(incident, 'incident_id', None)
            event_ids = getattr(incident, 'event_ids', [])
            context_event_ids = getattr(incident, 'context_event_ids', [])
            signal_ids = getattr(incident, 'signal_ids', [])
            evidence_list = getattr(incident, 'evidence', [])
            if not hasattr(incident, 'model_dump'):
                raise TypeError("incident must be a mapping or Pydantic model")
            incident_bundle = incident.model_dump(mode="json")
        
        incident_events = [event_map[eid] for eid in event_ids if eid in event_map]
        context_events = [
            event_map[eid] for eid in context_event_ids if eid in event_map
        ]
        canonical_events = [
            event.model_dump(mode="json") for event in incident_events
        ]
                
        detected_signals = []
        for sid in signal_ids:
            if sid in signal_map:
                sig = signal_map[sid]
                rule_name = getattr(sig, 'rule_name', 'Unknown')
                severity = getattr(sig, 'severity', 'low')
                confidence = getattr(sig, 'confidence', 0.0)
                detected_signals.append({
                    "signal_id": getattr(sig, 'signal_id', sid),
                    "rule_id": getattr(sig, 'rule_id', 'unknown'),
                    "detector_name": rule_name,
                    "rule_name": rule_name,
                    "signal_type": getattr(sig, 'signal_type', 'unknown'),
                    "signal_family": getattr(sig, 'signal_family', 'unknown'),
                    "status": "alert",
                    "message": f"{rule_name} detected. Severity: {severity}",
                    "description": f"{rule_name} detected",
                    "severity": severity,
                    "confidence_score": confidence,
                    "mitre_techniques": getattr(sig, 'mitre_techniques', []),
                    "matched_event_ids": getattr(sig, 'event_ids', [])
                })
                
        candidate_evidence = []
        for ev in evidence_list:
            candidate_evidence.append({
                "event_id": getattr(ev, 'event_id', ev.get('event_id') if isinstance(ev, dict) else None),
                "quote": getattr(ev, 'quote', ev.get('quote') if isinstance(ev, dict) else ""),
                "reason": getattr(ev, 'reason', ev.get('reason') if isinstance(ev, dict) else ""),
                "source": getattr(ev, 'source', ev.get('source') if isinstance(ev, dict) else ""),
                "original_fields": getattr(ev, 'original_fields', ev.get('original_fields') if isinstance(ev, dict) else {}),
                "correlation_context": getattr(ev, 'correlation_context', ev.get('correlation_context') if isinstance(ev, dict) else {})
            })
            
        triage_context = TriageIncidentContext.model_validate({
            "incident": incident_bundle,
            "events": incident_events,
            "context_events": context_events,
        })

        # The canonical primary signal and this job's provenance let the bounded
        # provider view preserve current-job evidence and the primary identity
        # instead of only the lowest-sorted historical IDs.
        primary_signal_id = None
        if isinstance(incident_bundle, dict):
            primary_signal_id = (incident_bundle.get("metrics") or {}).get(
                "primary_signal_id"
            )

        return {
            "incident": triage_context.model_dump(mode="json"),
            "incident_id": str(incident_id),
            "canonical_events": canonical_events,
            "messages": [],
            "iteration_count": 0,
            "mitre_techniques": [],
            "candidate_evidence": candidate_evidence,
            "detected_signals": detected_signals,
            "search_history": [],
            "tool_results": [],
            "errors": [],
            "detection_engine_executed": True,
            "primary_signal_id": primary_signal_id,
            "current_job_event_ids": list(current_job_event_ids),
            "current_job_signal_ids": list(current_job_signal_ids),
        }
