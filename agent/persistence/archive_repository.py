from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import and_, func, or_, select, union
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement
from sqlalchemy.sql.selectable import Select

from agent.application.retention import RetentionCutoffs, RetentionEntity
from agent.persistence.orm_models import (
    AuditEvent,
    CanonicalEvent,
    DetectionSignal,
    EvidenceItem,
    Incident,
    IncidentEvent,
    IncidentSignal,
    IngestionJob,
    Report,
    RetentionArchiveRun,
    TriageRun,
    ingestion_job_events,
    ingestion_job_incidents,
    ingestion_job_signals,
)
from agent.persistence.retention_repository import RetentionRepository


@dataclass(frozen=True)
class ArchiveDependencyBatch:
    entity_type: str
    rows: tuple[Any, ...]


class RetentionArchiveRunRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, run: RetentionArchiveRun) -> RetentionArchiveRun:
        self._session.add(run)
        return run

    def get(self, archive_id: str) -> RetentionArchiveRun | None:
        return self._session.get(RetentionArchiveRun, archive_id)


class ArchiveExportRepository:
    """Bounded keyset queries for archive candidates and dependency closure."""

    def __init__(self, session: Session, retention: RetentionRepository) -> None:
        self._session = session
        self._retention = retention

    def iter_candidate_batches(
        self,
        entity_type: RetentionEntity,
        cutoffs: RetentionCutoffs,
        as_of: datetime,
        batch_size: int,
    ) -> Iterator[tuple[Any, ...]]:
        yield from self._retention.iter_candidate_batches(
            entity_type,
            cutoffs,
            as_of,
            batch_size,
        )

    def iter_dependency_batches(
        self,
        cutoffs: RetentionCutoffs,
        as_of: datetime,
        batch_size: int,
    ) -> Iterator[ArchiveDependencyBatch]:
        if batch_size < 1:
            raise ValueError("archive_batch_size_invalid")
        candidate_incidents = self._candidate_ids("incident", cutoffs, as_of)
        candidate_jobs = self._candidate_ids("ingestion_job", cutoffs, as_of)
        candidate_events = self._candidate_ids("canonical_event", cutoffs, as_of)
        candidate_signals = self._candidate_ids("detection_signal", cutoffs, as_of)

        event_ids = union(
            select(IncidentEvent.event_id.label("entity_id")).where(
                IncidentEvent.incident_id.in_(candidate_incidents)
            ),
            select(ingestion_job_events.c.event_id.label("entity_id")).where(
                ingestion_job_events.c.job_id.in_(candidate_jobs)
            ),
            select(EvidenceItem.event_id.label("entity_id")).where(
                EvidenceItem.incident_id.in_(candidate_incidents),
                EvidenceItem.event_id.is_not(None),
            ),
        ).subquery()
        event_timestamp = func.coalesce(CanonicalEvent.timestamp, as_of)
        event_statement = select(CanonicalEvent).where(
            CanonicalEvent.event_id.in_(select(event_ids.c.entity_id)),
            CanonicalEvent.event_id.not_in(candidate_events),
        )
        yield from self._timestamped_batches(
            "canonical_event",
            event_statement,
            event_timestamp,
            CanonicalEvent.event_id,
            "timestamp",
            "event_id",
            batch_size,
            as_of,
        )

        signal_ids = union(
            select(IncidentSignal.signal_id.label("entity_id")).where(
                IncidentSignal.incident_id.in_(candidate_incidents)
            ),
            select(ingestion_job_signals.c.signal_id.label("entity_id")).where(
                ingestion_job_signals.c.job_id.in_(candidate_jobs)
            ),
        ).subquery()
        signal_timestamp = func.coalesce(DetectionSignal.created_at, as_of)
        signal_statement = select(DetectionSignal).where(
            DetectionSignal.signal_id.in_(select(signal_ids.c.entity_id)),
            DetectionSignal.signal_id.not_in(candidate_signals),
        )
        yield from self._timestamped_batches(
            "detection_signal",
            signal_statement,
            signal_timestamp,
            DetectionSignal.signal_id,
            "created_at",
            "signal_id",
            batch_size,
            as_of,
        )

        job_ids = union(
            select(TriageRun.job_id.label("entity_id")).where(
                TriageRun.incident_id.in_(candidate_incidents),
                TriageRun.job_id.is_not(None),
            ),
            select(EvidenceItem.job_id.label("entity_id")).where(
                EvidenceItem.incident_id.in_(candidate_incidents),
                EvidenceItem.job_id.is_not(None),
            ),
            select(Report.job_id.label("entity_id")).where(
                Report.incident_id.in_(candidate_incidents),
                Report.job_id.is_not(None),
            ),
        ).subquery()
        job_timestamp = func.coalesce(IngestionJob.completed_at, as_of)
        job_statement = select(IngestionJob).where(
            IngestionJob.id.in_(select(job_ids.c.entity_id)),
            IngestionJob.id.not_in(candidate_jobs),
        )
        yield from self._timestamped_batches(
            "ingestion_job",
            job_statement,
            job_timestamp,
            IngestionJob.id,
            "completed_at",
            "id",
            batch_size,
            as_of,
        )

        audit_spec = self._retention.candidate_spec("audit_event", cutoffs, as_of)
        incident_ids = union(
            select(ingestion_job_incidents.c.incident_id.label("entity_id")).where(
                ingestion_job_incidents.c.job_id.in_(candidate_jobs)
            ),
            select(AuditEvent.incident_id.label("entity_id"))
            .where(audit_spec.candidate, AuditEvent.incident_id.is_not(None))
            .select_from(AuditEvent),
        ).subquery()
        incident_timestamp = func.coalesce(Incident.updated_at, as_of)
        incident_statement = select(Incident).where(
            Incident.incident_id.in_(select(incident_ids.c.entity_id)),
            Incident.incident_id.not_in(candidate_incidents),
        )
        yield from self._timestamped_batches(
            "incident",
            incident_statement,
            incident_timestamp,
            Incident.incident_id,
            "updated_at",
            "incident_id",
            batch_size,
            as_of,
        )

        yield from self._single_key_batches(
            "triage_run",
            select(TriageRun).where(
                or_(
                    TriageRun.incident_id.in_(candidate_incidents),
                    TriageRun.job_id.in_(candidate_jobs),
                )
            ),
            TriageRun.id,
            "id",
            batch_size,
        )
        yield from self._single_key_batches(
            "evidence_item",
            select(EvidenceItem).where(
                or_(
                    EvidenceItem.incident_id.in_(candidate_incidents),
                    EvidenceItem.job_id.in_(candidate_jobs),
                )
            ),
            EvidenceItem.id,
            "id",
            batch_size,
        )
        yield from self._single_key_batches(
            "report",
            select(Report).where(
                or_(
                    Report.incident_id.in_(candidate_incidents),
                    Report.job_id.in_(candidate_jobs),
                )
            ),
            Report.id,
            "id",
            batch_size,
        )
        yield from self._single_key_batches(
            "incident_event_association",
            select(IncidentEvent).where(
                IncidentEvent.incident_id.in_(candidate_incidents)
            ),
            IncidentEvent.id,
            "id",
            batch_size,
        )
        yield from self._single_key_batches(
            "incident_signal_association",
            select(IncidentSignal).where(
                IncidentSignal.incident_id.in_(candidate_incidents)
            ),
            IncidentSignal.id,
            "id",
            batch_size,
        )

        yield from self._association_batches(
            "job_event_association",
            ingestion_job_events,
            "event_id",
            candidate_jobs,
            batch_size,
        )
        yield from self._association_batches(
            "job_signal_association",
            ingestion_job_signals,
            "signal_id",
            candidate_jobs,
            batch_size,
        )
        yield from self._association_batches(
            "job_incident_association",
            ingestion_job_incidents,
            "incident_id",
            candidate_jobs,
            batch_size,
            related_candidates=candidate_incidents,
        )

    def _candidate_ids(
        self,
        entity_type: RetentionEntity,
        cutoffs: RetentionCutoffs,
        as_of: datetime,
    ) -> Select[Any]:
        return self._retention.candidate_select(entity_type, cutoffs, as_of)

    def _timestamped_batches(
        self,
        entity_type: str,
        base_statement: Select[Any],
        timestamp_column: ColumnElement[datetime],
        id_column: ColumnElement[Any],
        timestamp_attribute: str,
        id_attribute: str,
        batch_size: int,
        fallback_timestamp: datetime,
    ) -> Iterator[ArchiveDependencyBatch]:
        last_timestamp: datetime | None = None
        last_id: str | None = None
        while True:
            statement = base_statement
            if last_timestamp is not None and last_id is not None:
                statement = statement.where(
                    or_(
                        timestamp_column > last_timestamp,
                        and_(timestamp_column == last_timestamp, id_column > last_id),
                    )
                )
            statement = statement.order_by(
                timestamp_column.asc(),
                id_column.asc(),
            ).limit(batch_size)
            rows = tuple(self._session.scalars(statement))
            if not rows:
                return
            yield ArchiveDependencyBatch(entity_type, rows)
            last = rows[-1]
            last_timestamp = getattr(last, timestamp_attribute) or fallback_timestamp
            last_id = str(getattr(last, id_attribute))

    def _single_key_batches(
        self,
        entity_type: str,
        base_statement: Select[Any],
        key_column: ColumnElement[Any],
        key_attribute: str,
        batch_size: int,
    ) -> Iterator[ArchiveDependencyBatch]:
        last_key: int | None = None
        while True:
            statement = base_statement
            if last_key is not None:
                statement = statement.where(key_column > last_key)
            statement = statement.order_by(key_column.asc()).limit(batch_size)
            rows = tuple(self._session.scalars(statement))
            if not rows:
                return
            yield ArchiveDependencyBatch(entity_type, rows)
            last_key = int(getattr(rows[-1], key_attribute))

    def _association_batches(
        self,
        entity_type: str,
        table: Any,
        related_column_name: str,
        candidate_jobs: Select[Any],
        batch_size: int,
        *,
        related_candidates: Select[Any] | None = None,
    ) -> Iterator[ArchiveDependencyBatch]:
        related_column = table.c[related_column_name]
        last_job_id: str | None = None
        last_related_id: str | None = None
        while True:
            membership = table.c.job_id.in_(candidate_jobs)
            if related_candidates is not None:
                membership = or_(
                    membership,
                    related_column.in_(related_candidates),
                )
            statement = select(table.c.job_id, related_column).where(membership)
            if last_job_id is not None and last_related_id is not None:
                statement = statement.where(
                    or_(
                        table.c.job_id > last_job_id,
                        and_(
                            table.c.job_id == last_job_id,
                            related_column > last_related_id,
                        ),
                    )
                )
            statement = statement.order_by(
                table.c.job_id.asc(),
                related_column.asc(),
            ).limit(batch_size)
            rows = tuple(self._session.execute(statement))
            if not rows:
                return
            yield ArchiveDependencyBatch(entity_type, rows)
            last_job_id = str(rows[-1].job_id)
            last_related_id = str(getattr(rows[-1], related_column_name))
