from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from sqlalchemy import func, select, text

from agent.application.cleanup import CLEANUP_ENTITY_ORDER
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
    RetentionCleanupProgress,
    RetentionCleanupRun,
    RetentionHold,
    TriageRun,
    ingestion_job_incidents,
)
from tests.cleanup.conftest import ARCHIVE_ID, NOW


def test_verified_archive_cleanup_is_dependency_safe_and_idempotent(cleanup_env) -> None:
    result = cleanup_env.service().execute(ARCHIVE_ID)

    assert result.status == "completed"
    assert result.deleted_record_count == 2
    assert result.protected_record_count == 3
    assert result.missing_record_count == 0
    assert result.completed_entity_phases == CLEANUP_ENTITY_ORDER

    with cleanup_env.archive.session_factory() as session:
        assert session.get(Incident, "incident-old-candidate") is None
        assert session.get(AuditEvent, 1) is None
        assert session.get(IngestionJob, "job-old-candidate") is not None
        assert session.get(CanonicalEvent, "event-old-candidate") is not None
        assert session.get(DetectionSignal, "signal-old-candidate") is not None
        assert session.scalar(select(func.count()).select_from(TriageRun)) == 0
        assert session.scalar(select(func.count()).select_from(EvidenceItem)) == 0
        assert session.scalar(select(func.count()).select_from(Report)) == 0
        assert session.scalar(select(func.count()).select_from(IncidentEvent)) == 1
        assert session.scalar(select(func.count()).select_from(IncidentSignal)) == 0
        assert session.scalar(
            select(func.count())
            .select_from(ingestion_job_incidents)
            .where(ingestion_job_incidents.c.incident_id == "incident-old-candidate")
        ) == 0
        assert tuple(session.execute(text("PRAGMA foreign_key_check"))) == ()
        assert session.scalar(
            select(func.count())
            .select_from(IncidentEvent)
            .outerjoin(
                CanonicalEvent,
                CanonicalEvent.event_id == IncidentEvent.event_id,
            )
            .where(CanonicalEvent.event_id.is_(None))
        ) == 0
        run = session.scalar(select(RetentionCleanupRun))
        assert run is not None
        assert run.status == "completed"
        assert run.lease_owner is None
        assert run.lease_expires_at is None
        progress = tuple(
            session.scalars(
                select(RetentionCleanupProgress).order_by(
                    RetentionCleanupProgress.entity_type
                )
            )
        )
        assert len(progress) == len(CLEANUP_ENTITY_ORDER)
        assert all(row.status == "completed" for row in progress)
        audit_types = tuple(
            session.scalars(
                select(AuditEvent.event_type).where(
                    AuditEvent.entity_type == "retention_cleanup"
                )
            )
        )
        assert audit_types == (
            "retention_cleanup_started",
            "retention_cleanup_completed",
        )

    archive_files = cleanup_env.archive.store.list_files(ARCHIVE_ID)
    second = cleanup_env.service().execute(ARCHIVE_ID)
    assert second == result
    assert cleanup_env.archive.store.list_files(ARCHIVE_ID) == archive_files
    assert not tuple(
        Path(cleanup_env.settings.retention_archive_root).glob(".cleanup-index-*")
    )
    with cleanup_env.archive.session_factory() as session:
        assert session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.entity_type == "retention_cleanup")
        ) == 2


def test_new_legal_hold_after_archive_protects_candidate(cleanup_env) -> None:
    with cleanup_env.archive.session_factory() as session:
        session.add(
            RetentionHold(
                hold_id="hold-cleanup-race",
                entity_type="incident",
                entity_id="incident-old-candidate",
                reason="Investigation reopened",
                created_at=NOW + timedelta(minutes=1),
            )
        )
        session.commit()

    result = cleanup_env.service().execute(ARCHIVE_ID)

    assert result.deleted_record_count == 1
    assert result.protected_record_count == 4
    with cleanup_env.archive.session_factory() as session:
        assert session.get(Incident, "incident-old-candidate") is not None
        assert session.scalar(select(func.count()).select_from(TriageRun)) == 1


def test_reopened_incident_and_dependency_records_are_not_direct_candidates(
    cleanup_env,
) -> None:
    with cleanup_env.archive.session_factory() as session:
        incident = session.get(Incident, "incident-old-candidate")
        assert incident is not None
        incident.status = "needs_review"
        session.commit()

    result = cleanup_env.service().execute(ARCHIVE_ID)

    assert result.deleted_record_count == 1
    with cleanup_env.archive.session_factory() as session:
        assert session.get(Incident, "incident-old-candidate") is not None
        assert session.get(CanonicalEvent, "event-young-dependency") is not None
        assert session.get(DetectionSignal, "signal-young-dependency") is not None


def test_dependency_created_after_archive_protects_root(cleanup_env) -> None:
    with cleanup_env.archive.session_factory() as session:
        session.add(
            Report(
                report_id="report-created-after-archive",
                incident_id="incident-old-candidate",
                generated_at=NOW + timedelta(minutes=1),
                format="markdown",
                content="safe new report",
            )
        )
        session.commit()

    result = cleanup_env.service().execute(ARCHIVE_ID)

    assert result.deleted_record_count == 1
    assert result.protected_record_count == 4
    with cleanup_env.archive.session_factory() as session:
        assert session.get(Incident, "incident-old-candidate") is not None
        assert session.scalar(
            select(Report).where(
                Report.report_id == "report-created-after-archive"
            )
        ) is not None
