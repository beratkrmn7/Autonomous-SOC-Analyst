from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol, cast

from sqlalchemy import and_, delete, func, or_, select, union, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from agent.application.retention import RetentionCutoffs, RetentionEntity
from agent.persistence.orm_models import (
    AuditEvent,
    EvidenceItem,
    IncidentEvent,
    IncidentSignal,
    Report,
    RetentionCleanupProgress,
    RetentionCleanupRun,
    TriageRun,
    ingestion_job_events,
    ingestion_job_incidents,
    ingestion_job_signals,
)
from agent.persistence.retention_repository import RetentionRepository


class CleanupPersistenceError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class DependencyAuthorization(Protocol):
    def contains_all_dependencies(
        self,
        keys: Iterable[tuple[str, str]],
    ) -> bool: ...


@dataclass(frozen=True)
class CleanupBatchCounts:
    scanned: int
    deleted: int
    protected: int
    missing: int
    skipped: int = 0


@dataclass(frozen=True)
class CleanupRunSummary:
    cleanup_run_id: str
    archive_id: str
    status: str
    attempt_count: int
    deleted: int
    protected: int
    missing: int
    skipped: int


class RetentionCleanupRepository:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._retention = RetentionRepository(session)

    def add_run(self, run: RetentionCleanupRun) -> None:
        self._session.add(run)

    def add_progress(self, progress: RetentionCleanupProgress) -> None:
        self._session.add(progress)

    def flush(self) -> None:
        self._session.flush()

    def get_by_archive(self, archive_id: str) -> RetentionCleanupRun | None:
        return self._session.scalar(
            select(RetentionCleanupRun).where(
                RetentionCleanupRun.archive_id == archive_id
            )
        )

    def get(self, cleanup_run_id: str) -> RetentionCleanupRun | None:
        return self._session.get(RetentionCleanupRun, cleanup_run_id)

    def get_progress(
        self,
        cleanup_run_id: str,
        entity_type: RetentionEntity,
    ) -> RetentionCleanupProgress | None:
        return self._session.get(
            RetentionCleanupProgress,
            (cleanup_run_id, entity_type),
        )

    def claim(
        self,
        cleanup_run_id: str,
        *,
        owner: str,
        now: datetime,
        lease_seconds: int,
    ) -> bool:
        available = or_(
            RetentionCleanupRun.status.in_(("pending", "failed")),
            and_(
                RetentionCleanupRun.status == "running",
                or_(
                    RetentionCleanupRun.lease_expires_at.is_(None),
                    RetentionCleanupRun.lease_expires_at <= now,
                ),
            ),
        )
        result = cast(CursorResult[Any], self._session.execute(
            update(RetentionCleanupRun)
            .where(
                RetentionCleanupRun.cleanup_run_id == cleanup_run_id,
                available,
            )
            .values(
                status="running",
                started_at=func.coalesce(RetentionCleanupRun.started_at, now),
                updated_at=now,
                current_phase="cleanup",
                lease_owner=owner,
                lease_expires_at=now + timedelta(seconds=lease_seconds),
                attempt_count=RetentionCleanupRun.attempt_count + 1,
                sanitized_error_code=None,
                version=RetentionCleanupRun.version + 1,
            )
            .execution_options(synchronize_session=False)
        ))
        return result.rowcount == 1

    def apply_batch(
        self,
        cleanup_run_id: str,
        entity_type: RetentionEntity,
        *,
        owner: str,
        expected_version: int,
        now: datetime,
        lease_seconds: int,
        counts: CleanupBatchCounts,
        last_recorded_at: datetime,
        last_entity_id: str,
    ) -> None:
        progress_result = cast(CursorResult[Any], self._session.execute(
            update(RetentionCleanupProgress)
            .where(
                RetentionCleanupProgress.cleanup_run_id == cleanup_run_id,
                RetentionCleanupProgress.entity_type == entity_type,
                RetentionCleanupProgress.status.in_(("pending", "running")),
            )
            .values(
                status="running",
                last_recorded_at=last_recorded_at,
                last_entity_id=last_entity_id,
                scanned_count=RetentionCleanupProgress.scanned_count + counts.scanned,
                deleted_count=RetentionCleanupProgress.deleted_count + counts.deleted,
                protected_count=(
                    RetentionCleanupProgress.protected_count + counts.protected
                ),
                missing_count=RetentionCleanupProgress.missing_count + counts.missing,
                skipped_count=RetentionCleanupProgress.skipped_count + counts.skipped,
            )
            .execution_options(synchronize_session=False)
        ))
        if progress_result.rowcount != 1:
            raise CleanupPersistenceError("cleanup_progress_update_conflict")
        self._guarded_run_update(
            cleanup_run_id,
            owner=owner,
            expected_version=expected_version,
            now=now,
            values={
                "updated_at": now,
                "current_phase": "cleanup",
                "current_entity_type": entity_type,
                "lease_expires_at": now + timedelta(seconds=lease_seconds),
                "deleted_record_count": (
                    RetentionCleanupRun.deleted_record_count + counts.deleted
                ),
                "protected_record_count": (
                    RetentionCleanupRun.protected_record_count + counts.protected
                ),
                "missing_record_count": (
                    RetentionCleanupRun.missing_record_count + counts.missing
                ),
                "skipped_record_count": (
                    RetentionCleanupRun.skipped_record_count + counts.skipped
                ),
                "version": RetentionCleanupRun.version + 1,
            },
        )

    def complete_progress(
        self,
        cleanup_run_id: str,
        entity_type: RetentionEntity,
        *,
        owner: str,
        expected_version: int,
        now: datetime,
        lease_seconds: int,
        next_entity_type: RetentionEntity | None,
    ) -> None:
        progress_result = cast(CursorResult[Any], self._session.execute(
            update(RetentionCleanupProgress)
            .where(
                RetentionCleanupProgress.cleanup_run_id == cleanup_run_id,
                RetentionCleanupProgress.entity_type == entity_type,
                RetentionCleanupProgress.status.in_(("pending", "running")),
            )
            .values(status="completed", completed_at=now)
            .execution_options(synchronize_session=False)
        ))
        if progress_result.rowcount != 1:
            raise CleanupPersistenceError("cleanup_progress_update_conflict")
        self._guarded_run_update(
            cleanup_run_id,
            owner=owner,
            expected_version=expected_version,
            now=now,
            values={
                "updated_at": now,
                "current_entity_type": next_entity_type,
                "lease_expires_at": now + timedelta(seconds=lease_seconds),
                "version": RetentionCleanupRun.version + 1,
            },
        )

    def complete_run(
        self,
        cleanup_run_id: str,
        *,
        owner: str,
        expected_version: int,
        now: datetime,
    ) -> None:
        self._guarded_run_update(
            cleanup_run_id,
            owner=owner,
            expected_version=expected_version,
            now=now,
            values={
                "status": "completed",
                "updated_at": now,
                "completed_at": now,
                "current_phase": "completed",
                "current_entity_type": None,
                "lease_owner": None,
                "lease_expires_at": None,
                "sanitized_error_code": None,
                "version": RetentionCleanupRun.version + 1,
            },
        )

    def fail_run(
        self,
        cleanup_run_id: str,
        *,
        owner: str,
        now: datetime,
        error_code: str,
    ) -> bool:
        result = cast(CursorResult[Any], self._session.execute(
            update(RetentionCleanupRun)
            .where(
                RetentionCleanupRun.cleanup_run_id == cleanup_run_id,
                RetentionCleanupRun.status == "running",
                RetentionCleanupRun.lease_owner == owner,
            )
            .values(
                status="failed",
                updated_at=now,
                lease_owner=None,
                lease_expires_at=None,
                sanitized_error_code=error_code,
                version=RetentionCleanupRun.version + 1,
            )
            .execution_options(synchronize_session=False)
        ))
        return result.rowcount == 1

    def summary(self, run: RetentionCleanupRun) -> CleanupRunSummary:
        return CleanupRunSummary(
            cleanup_run_id=str(run.cleanup_run_id),
            archive_id=str(run.archive_id),
            status=str(run.status),
            attempt_count=int(run.attempt_count),
            deleted=int(run.deleted_record_count),
            protected=int(run.protected_record_count),
            missing=int(run.missing_record_count),
            skipped=int(run.skipped_record_count),
        )

    def classify(
        self,
        entity_type: RetentionEntity,
        entity_ids: tuple[str, ...],
        *,
        cutoffs: RetentionCutoffs,
        as_of: datetime,
    ) -> tuple[set[str], set[str]]:
        if not entity_ids:
            return set(), set()
        spec = self._retention.candidate_spec(entity_type, cutoffs, as_of)
        existing = {
            str(value)
            for value in self._session.scalars(
                select(spec.entity_id_column)
                .select_from(spec.model)
                .where(spec.entity_id_column.in_(entity_ids))
            )
        }
        eligible = {
            str(value)
            for value in self._session.scalars(
                select(spec.entity_id_column)
                .select_from(spec.model)
                .where(
                    spec.entity_id_column.in_(entity_ids),
                    spec.candidate,
                )
            )
        }
        return existing, eligible

    def delete_eligible(
        self,
        entity_type: RetentionEntity,
        eligible_ids: set[str],
        *,
        cutoffs: RetentionCutoffs,
        as_of: datetime,
        authorization: DependencyAuthorization,
        dependency_limit: int,
    ) -> tuple[int, int]:
        if not eligible_ids:
            return 0, 0
        if entity_type == "incident":
            safe_ids = self._safe_incidents(
                eligible_ids,
                cutoffs=cutoffs,
                as_of=as_of,
                authorization=authorization,
                dependency_limit=dependency_limit,
            )
            self._delete_incident_dependencies(safe_ids)
        elif entity_type == "ingestion_job":
            safe_ids = self._safe_jobs(
                eligible_ids,
                authorization=authorization,
                dependency_limit=dependency_limit,
            )
            self._delete_job_dependencies(safe_ids)
        elif entity_type == "canonical_event":
            safe_ids = eligible_ids - self._referenced_event_ids(eligible_ids)
        elif entity_type == "detection_signal":
            safe_ids = eligible_ids - self._referenced_signal_ids(eligible_ids)
        else:
            safe_ids = set(eligible_ids)

        if not safe_ids:
            return 0, len(eligible_ids)
        spec = self._retention.candidate_spec(entity_type, cutoffs, as_of)
        root_delete = delete(spec.model).where(
            spec.entity_id_column.in_(safe_ids),
            spec.candidate,
        )
        if entity_type == "incident":
            root_delete = root_delete.where(
                ~select(AuditEvent.id)
                .where(AuditEvent.incident_id == spec.entity_id_column)
                .exists()
            )
        result = cast(CursorResult[Any], self._session.execute(
            root_delete
        ))
        if result.rowcount != len(safe_ids):
            raise CleanupPersistenceError("cleanup_root_delete_conflict")
        return len(safe_ids), len(eligible_ids - safe_ids)

    def _guarded_run_update(
        self,
        cleanup_run_id: str,
        *,
        owner: str,
        expected_version: int,
        now: datetime,
        values: dict[str, object],
    ) -> None:
        result = cast(CursorResult[Any], self._session.execute(
            update(RetentionCleanupRun)
            .where(
                RetentionCleanupRun.cleanup_run_id == cleanup_run_id,
                RetentionCleanupRun.status == "running",
                RetentionCleanupRun.lease_owner == owner,
                RetentionCleanupRun.lease_expires_at > now,
                RetentionCleanupRun.version == expected_version,
            )
            .values(**values)
            .execution_options(synchronize_session=False)
        ))
        if result.rowcount != 1:
            raise CleanupPersistenceError("cleanup_lease_lost")

    def _safe_incidents(
        self,
        incident_ids: set[str],
        *,
        cutoffs: RetentionCutoffs,
        as_of: datetime,
        authorization: DependencyAuthorization,
        dependency_limit: int,
    ) -> set[str]:
        safe: set[str] = set()
        for incident_id in incident_ids:
            rows = self._incident_dependency_rows(incident_id, dependency_limit)
            if rows is None:
                continue
            dependency_keys, linked_job_ids = rows
            if linked_job_ids:
                existing_jobs, eligible_jobs = self.classify(
                    "ingestion_job",
                    tuple(linked_job_ids),
                    cutoffs=cutoffs,
                    as_of=as_of,
                )
                if existing_jobs != linked_job_ids or eligible_jobs != linked_job_ids:
                    continue
            if not authorization.contains_all_dependencies(dependency_keys):
                continue
            remaining_audit_event = self._session.scalar(
                select(AuditEvent.id)
                .where(AuditEvent.incident_id == incident_id)
                .limit(1)
            )
            if remaining_audit_event is not None:
                continue
            safe.add(incident_id)
        return safe

    def _safe_jobs(
        self,
        job_ids: set[str],
        *,
        authorization: DependencyAuthorization,
        dependency_limit: int,
    ) -> set[str]:
        safe: set[str] = set()
        for job_id in job_ids:
            rows = self._job_dependency_rows(job_id, dependency_limit)
            if rows is None:
                continue
            dependency_keys, has_incident_reference = rows
            if has_incident_reference:
                continue
            if authorization.contains_all_dependencies(dependency_keys):
                safe.add(job_id)
        return safe

    def _incident_dependency_rows(
        self,
        incident_id: str,
        limit: int,
    ) -> tuple[tuple[tuple[str, str], ...], set[str]] | None:
        triage = tuple(
            self._session.scalars(
                select(TriageRun)
                .where(TriageRun.incident_id == incident_id)
                .limit(limit + 1)
            )
        )
        evidence = tuple(
            self._session.scalars(
                select(EvidenceItem)
                .where(EvidenceItem.incident_id == incident_id)
                .limit(limit + 1)
            )
        )
        reports = tuple(
            self._session.scalars(
                select(Report)
                .where(Report.incident_id == incident_id)
                .limit(limit + 1)
            )
        )
        incident_events = tuple(
            self._session.scalars(
                select(IncidentEvent)
                .where(IncidentEvent.incident_id == incident_id)
                .limit(limit + 1)
            )
        )
        incident_signals = tuple(
            self._session.scalars(
                select(IncidentSignal)
                .where(IncidentSignal.incident_id == incident_id)
                .limit(limit + 1)
            )
        )
        job_incidents = tuple(
            self._session.execute(
                select(
                    ingestion_job_incidents.c.job_id,
                    ingestion_job_incidents.c.incident_id,
                )
                .where(ingestion_job_incidents.c.incident_id == incident_id)
                .limit(limit + 1)
            )
        )
        total = sum(
            len(rows)
            for rows in (
                triage,
                evidence,
                reports,
                incident_events,
                incident_signals,
                job_incidents,
            )
        )
        if total > limit:
            return None
        keys: list[tuple[str, str]] = []
        linked_jobs: set[str] = set()
        for row in triage:
            keys.append(("triage_run", str(row.triage_run_id or f"triage-row-{row.id}")))
            if row.job_id is not None:
                linked_jobs.add(str(row.job_id))
        for row in evidence:
            keys.append(
                ("evidence_item", str(row.evidence_id or f"evidence-row-{row.id}"))
            )
            if row.job_id is not None:
                linked_jobs.add(str(row.job_id))
        for row in reports:
            keys.append(("report", str(row.report_id or f"report-row-{row.id}")))
            if row.job_id is not None:
                linked_jobs.add(str(row.job_id))
        keys.extend(
            ("incident_event_association", f"{row.incident_id}:{row.event_id}")
            for row in incident_events
        )
        keys.extend(
            ("incident_signal_association", f"{row.incident_id}:{row.signal_id}")
            for row in incident_signals
        )
        for association in job_incidents:
            linked_jobs.add(str(association.job_id))
            keys.append(
                (
                    "job_incident_association",
                    f"{association.job_id}:{association.incident_id}",
                )
            )
        return tuple(keys), linked_jobs

    def _job_dependency_rows(
        self,
        job_id: str,
        limit: int,
    ) -> tuple[tuple[tuple[str, str], ...], bool] | None:
        triage = tuple(
            self._session.scalars(
                select(TriageRun).where(TriageRun.job_id == job_id).limit(limit + 1)
            )
        )
        evidence = tuple(
            self._session.scalars(
                select(EvidenceItem)
                .where(EvidenceItem.job_id == job_id)
                .limit(limit + 1)
            )
        )
        reports = tuple(
            self._session.scalars(
                select(Report).where(Report.job_id == job_id).limit(limit + 1)
            )
        )
        job_events = tuple(
            self._session.execute(
                select(ingestion_job_events.c.job_id, ingestion_job_events.c.event_id)
                .where(ingestion_job_events.c.job_id == job_id)
                .limit(limit + 1)
            )
        )
        job_signals = tuple(
            self._session.execute(
                select(
                    ingestion_job_signals.c.job_id,
                    ingestion_job_signals.c.signal_id,
                )
                .where(ingestion_job_signals.c.job_id == job_id)
                .limit(limit + 1)
            )
        )
        job_incidents = tuple(
            self._session.execute(
                select(
                    ingestion_job_incidents.c.job_id,
                    ingestion_job_incidents.c.incident_id,
                )
                .where(ingestion_job_incidents.c.job_id == job_id)
                .limit(limit + 1)
            )
        )
        total = sum(
            len(rows)
            for rows in (
                triage,
                evidence,
                reports,
                job_events,
                job_signals,
                job_incidents,
            )
        )
        if total > limit:
            return None
        has_incident_reference = (
            bool(job_incidents)
            or any(row.incident_id is not None for row in triage)
            or any(row.incident_id is not None for row in evidence)
            or any(row.incident_id is not None for row in reports)
        )
        keys: list[tuple[str, str]] = []
        keys.extend(
            ("triage_run", str(row.triage_run_id or f"triage-row-{row.id}"))
            for row in triage
        )
        keys.extend(
            ("evidence_item", str(row.evidence_id or f"evidence-row-{row.id}"))
            for row in evidence
        )
        keys.extend(
            ("report", str(row.report_id or f"report-row-{row.id}"))
            for row in reports
        )
        keys.extend(
            ("job_event_association", f"{row.job_id}:{row.event_id}")
            for row in job_events
        )
        keys.extend(
            ("job_signal_association", f"{row.job_id}:{row.signal_id}")
            for row in job_signals
        )
        return tuple(keys), has_incident_reference

    def _delete_incident_dependencies(self, incident_ids: set[str]) -> None:
        if not incident_ids:
            return
        self._session.execute(delete(Report).where(Report.incident_id.in_(incident_ids)))
        self._session.execute(
            delete(EvidenceItem).where(EvidenceItem.incident_id.in_(incident_ids))
        )
        self._session.execute(
            delete(TriageRun).where(TriageRun.incident_id.in_(incident_ids))
        )
        self._session.execute(
            delete(IncidentEvent).where(IncidentEvent.incident_id.in_(incident_ids))
        )
        self._session.execute(
            delete(IncidentSignal).where(IncidentSignal.incident_id.in_(incident_ids))
        )
        self._session.execute(
            delete(ingestion_job_incidents).where(
                ingestion_job_incidents.c.incident_id.in_(incident_ids)
            )
        )

    def _delete_job_dependencies(self, job_ids: set[str]) -> None:
        if not job_ids:
            return
        self._session.execute(delete(Report).where(Report.job_id.in_(job_ids)))
        self._session.execute(delete(EvidenceItem).where(EvidenceItem.job_id.in_(job_ids)))
        self._session.execute(delete(TriageRun).where(TriageRun.job_id.in_(job_ids)))
        self._session.execute(
            delete(ingestion_job_events).where(ingestion_job_events.c.job_id.in_(job_ids))
        )
        self._session.execute(
            delete(ingestion_job_signals).where(
                ingestion_job_signals.c.job_id.in_(job_ids)
            )
        )
        self._session.execute(
            delete(ingestion_job_incidents).where(
                ingestion_job_incidents.c.job_id.in_(job_ids)
            )
        )

    def _referenced_event_ids(self, entity_ids: set[str]) -> set[str]:
        statement = union(
            select(IncidentEvent.event_id.label("entity_id")).where(
                IncidentEvent.event_id.in_(entity_ids)
            ),
            select(ingestion_job_events.c.event_id.label("entity_id")).where(
                ingestion_job_events.c.event_id.in_(entity_ids)
            ),
            select(EvidenceItem.event_id.label("entity_id")).where(
                EvidenceItem.event_id.in_(entity_ids)
            ),
        )
        return {str(value) for value in self._session.scalars(statement)}

    def _referenced_signal_ids(self, entity_ids: set[str]) -> set[str]:
        statement = union(
            select(IncidentSignal.signal_id.label("entity_id")).where(
                IncidentSignal.signal_id.in_(entity_ids)
            ),
            select(ingestion_job_signals.c.signal_id.label("entity_id")).where(
                ingestion_job_signals.c.signal_id.in_(entity_ids)
            ),
        )
        return {str(value) for value in self._session.scalars(statement)}
