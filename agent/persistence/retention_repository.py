from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import String, and_, case, cast, exists, false, func, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from agent.application.retention import (
    RetentionCandidateSummary,
    RetentionCutoffs,
    RetentionEntity,
)
from agent.persistence.orm_models import (
    AuditEvent,
    CanonicalEvent,
    DetectionSignal,
    Incident,
    IncidentEvent,
    IncidentSignal,
    IngestionJob,
    RetentionHold,
    ingestion_job_events,
    ingestion_job_incidents,
    ingestion_job_signals,
)


TERMINAL_INCIDENT_STATUSES = ("resolved", "closed")
ELIGIBLE_JOB_STATUSES = ("completed",)


class RetentionRepository:
    """Builds aggregate-only retention summaries without loading entity IDs."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def summarize(
        self,
        *,
        cutoffs: RetentionCutoffs,
        as_of: datetime,
    ) -> tuple[RetentionCandidateSummary, ...]:
        return (
            self._summarize_canonical_events(cutoffs.canonical_event, as_of),
            self._summarize_detection_signals(cutoffs.detection_signal, as_of),
            self._summarize_ingestion_jobs(cutoffs.ingestion_job, as_of),
            self._summarize_incidents(cutoffs.incident, as_of),
            self._summarize_audit_events(cutoffs.audit_event, as_of),
        )

    def _active_hold(
        self,
        entity_type: RetentionEntity,
        entity_id: ColumnElement[Any],
        as_of: datetime,
    ) -> ColumnElement[bool]:
        return exists(
            select(1).where(
                RetentionHold.entity_type == entity_type,
                RetentionHold.entity_id == entity_id,
                RetentionHold.released_at.is_(None),
                or_(
                    RetentionHold.expires_at.is_(None),
                    RetentionHold.expires_at > as_of,
                ),
            )
        )

    @staticmethod
    def _protected_incident_status() -> ColumnElement[bool]:
        return or_(
            Incident.status.is_(None),
            Incident.status.not_in(TERMINAL_INCIDENT_STATUSES),
        )

    @staticmethod
    def _protected_job_status() -> ColumnElement[bool]:
        return or_(
            IngestionJob.status.is_(None),
            IngestionJob.status.not_in(ELIGIBLE_JOB_STATUSES),
        )

    def _summarize_canonical_events(
        self,
        cutoff: datetime,
        as_of: datetime,
    ) -> RetentionCandidateSummary:
        active_incident = exists(
            select(1)
            .select_from(IncidentEvent)
            .join(Incident, Incident.incident_id == IncidentEvent.incident_id)
            .where(
                IncidentEvent.event_id == CanonicalEvent.event_id,
                self._protected_incident_status(),
            )
        )
        active_job = exists(
            select(1)
            .select_from(ingestion_job_events)
            .join(IngestionJob, IngestionJob.id == ingestion_job_events.c.job_id)
            .where(
                ingestion_job_events.c.event_id == CanonicalEvent.event_id,
                self._protected_job_status(),
            )
        )
        hold = self._active_hold(
            "canonical_event",
            CanonicalEvent.event_id,
            as_of,
        )
        aged = and_(
            CanonicalEvent.timestamp.is_not(None),
            CanonicalEvent.timestamp < cutoff,
        )
        protected = or_(active_incident, active_job)
        return self._aggregate(
            entity_type="canonical_event",
            model=CanonicalEvent,
            date_column=CanonicalEvent.timestamp,
            cutoff=cutoff,
            candidate=and_(aged, ~protected, ~hold),
            protected_active=and_(aged, protected),
            protected_hold=and_(aged, hold),
        )

    def _summarize_detection_signals(
        self,
        cutoff: datetime,
        as_of: datetime,
    ) -> RetentionCandidateSummary:
        active_incident = exists(
            select(1)
            .select_from(IncidentSignal)
            .join(Incident, Incident.incident_id == IncidentSignal.incident_id)
            .where(
                IncidentSignal.signal_id == DetectionSignal.signal_id,
                self._protected_incident_status(),
            )
        )
        active_job = exists(
            select(1)
            .select_from(ingestion_job_signals)
            .join(IngestionJob, IngestionJob.id == ingestion_job_signals.c.job_id)
            .where(
                ingestion_job_signals.c.signal_id == DetectionSignal.signal_id,
                self._protected_job_status(),
            )
        )
        hold = self._active_hold(
            "detection_signal",
            DetectionSignal.signal_id,
            as_of,
        )
        aged = and_(
            DetectionSignal.created_at.is_not(None),
            DetectionSignal.created_at < cutoff,
        )
        protected = or_(active_incident, active_job)
        return self._aggregate(
            entity_type="detection_signal",
            model=DetectionSignal,
            date_column=DetectionSignal.created_at,
            cutoff=cutoff,
            candidate=and_(aged, ~protected, ~hold),
            protected_active=and_(aged, protected),
            protected_hold=and_(aged, hold),
        )

    def _summarize_ingestion_jobs(
        self,
        cutoff: datetime,
        as_of: datetime,
    ) -> RetentionCandidateSummary:
        active_incident = exists(
            select(1)
            .select_from(ingestion_job_incidents)
            .join(Incident, Incident.incident_id == ingestion_job_incidents.c.incident_id)
            .where(
                ingestion_job_incidents.c.job_id == IngestionJob.id,
                self._protected_incident_status(),
            )
        )
        hold = self._active_hold("ingestion_job", IngestionJob.id, as_of)
        aged = and_(
            IngestionJob.completed_at.is_not(None),
            IngestionJob.completed_at < cutoff,
        )
        eligible_status = IngestionJob.status.in_(ELIGIBLE_JOB_STATUSES)
        protected = or_(self._protected_job_status(), active_incident)
        return self._aggregate(
            entity_type="ingestion_job",
            model=IngestionJob,
            date_column=IngestionJob.completed_at,
            cutoff=cutoff,
            candidate=and_(aged, eligible_status, ~active_incident, ~hold),
            protected_active=and_(aged, protected),
            protected_hold=and_(aged, eligible_status, hold),
        )

    def _summarize_incidents(
        self,
        cutoff: datetime,
        as_of: datetime,
    ) -> RetentionCandidateSummary:
        hold = self._active_hold("incident", Incident.incident_id, as_of)
        aged = and_(Incident.updated_at.is_not(None), Incident.updated_at < cutoff)
        eligible_status = Incident.status.in_(TERMINAL_INCIDENT_STATUSES)
        protected_status = self._protected_incident_status()
        return self._aggregate(
            entity_type="incident",
            model=Incident,
            date_column=Incident.updated_at,
            cutoff=cutoff,
            candidate=and_(aged, eligible_status, ~hold),
            protected_active=and_(aged, protected_status),
            protected_hold=and_(aged, eligible_status, hold),
        )

    def _summarize_audit_events(
        self,
        cutoff: datetime,
        as_of: datetime,
    ) -> RetentionCandidateSummary:
        hold_id = case(
            (
                AuditEvent.audit_event_id.is_not(None),
                AuditEvent.audit_event_id,
            ),
            else_=cast(AuditEvent.id, String),
        )
        hold = self._active_hold("audit_event", hold_id, as_of)
        aged = and_(
            AuditEvent.timestamp.is_not(None),
            AuditEvent.timestamp < cutoff,
        )
        return self._aggregate(
            entity_type="audit_event",
            model=AuditEvent,
            date_column=AuditEvent.timestamp,
            cutoff=cutoff,
            candidate=and_(aged, ~hold),
            protected_active=false(),
            protected_hold=and_(aged, hold),
        )

    def _aggregate(
        self,
        *,
        entity_type: RetentionEntity,
        model: type[Any],
        date_column: ColumnElement[datetime],
        cutoff: datetime,
        candidate: ColumnElement[bool],
        protected_active: ColumnElement[bool],
        protected_hold: ColumnElement[bool],
    ) -> RetentionCandidateSummary:
        statement = select(
            func.coalesce(func.sum(case((candidate, 1), else_=0)), 0),
            func.min(case((candidate, date_column), else_=None)),
            func.max(case((candidate, date_column), else_=None)),
            func.coalesce(func.sum(case((protected_active, 1), else_=0)), 0),
            func.coalesce(func.sum(case((protected_hold, 1), else_=0)), 0),
        ).select_from(model)
        row = self._session.execute(statement).one()
        return RetentionCandidateSummary(
            entity_type=entity_type,
            cutoff=cutoff,
            candidate_count=int(row[0]),
            oldest_candidate_at=row[1],
            newest_candidate_at=row[2],
            protected_by_active_relationship_count=int(row[3]),
            protected_by_legal_hold_count=int(row[4]),
        )
