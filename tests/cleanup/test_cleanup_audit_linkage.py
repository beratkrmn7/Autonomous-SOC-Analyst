from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select, text

from agent.application.cleanup import CLEANUP_ENTITY_ORDER, CleanupOperationError
from agent.persistence.cleanup_repository import RetentionCleanupRepository
from agent.persistence.orm_models import (
    AuditEvent,
    Incident,
    RetentionCleanupProgress,
    RetentionCleanupRun,
    RetentionHold,
)
from tests.archive.conftest import ARCHIVE_ID, NOW, make_environment
from tests.cleanup.conftest import CleanupEnvironment


INCIDENT_ID = "incident-audit-linkage"
AUDIT_ID = "audit-incident-linkage"


def _environment(
    root: Path,
    *,
    audit_timestamp: datetime | None,
    audit_held: bool = False,
    batch_size: int = 2,
) -> CleanupEnvironment:
    archive = make_environment(root)
    with archive.session_factory() as session:
        incident = Incident(
            incident_id=INCIDENT_ID,
            title="Terminal incident with audit history",
            status="resolved",
            created_at=NOW - timedelta(days=520),
            updated_at=NOW - timedelta(days=500),
        )
        session.add(incident)
        if audit_timestamp is not None:
            session.add(
                AuditEvent(
                    audit_event_id=AUDIT_ID,
                    incident=incident,
                    timestamp=audit_timestamp,
                    event_type="status_transition",
                    entity_type="incident",
                    entity_id=INCIDENT_ID,
                    action="status_change",
                )
            )
            if audit_held:
                session.add(
                    RetentionHold(
                        hold_id="hold-audit-linkage",
                        entity_type="audit_event",
                        entity_id=AUDIT_ID,
                        reason="Preserve audit chain",
                        created_at=NOW - timedelta(days=10),
                    )
                )
        session.commit()
    archive.service().create()
    settings = archive.settings.model_copy(
        update={
            "retention_cleanup_batch_size": batch_size,
            "retention_cleanup_lease_seconds": 300,
        }
    )
    return CleanupEnvironment(archive, settings)


def test_cleanup_orders_audit_events_before_incidents() -> None:
    assert CLEANUP_ENTITY_ORDER == (
        "audit_event",
        "incident",
        "ingestion_job",
        "detection_signal",
        "canonical_event",
    )


def test_recent_audit_event_protects_old_terminal_incident(tmp_path) -> None:
    environment = _environment(
        tmp_path,
        audit_timestamp=NOW - timedelta(days=1),
    )
    try:
        result = environment.service().execute(ARCHIVE_ID)

        assert result.deleted_record_count == 0
        assert result.protected_record_count == 1
        with environment.archive.session_factory() as session:
            assert session.get(Incident, INCIDENT_ID) is not None
            audit = session.scalar(
                select(AuditEvent).where(AuditEvent.audit_event_id == AUDIT_ID)
            )
            assert audit is not None
            assert audit.incident_id == INCIDENT_ID
    finally:
        environment.archive.engine.dispose()


def test_held_old_audit_event_protects_incident_and_linkage(tmp_path) -> None:
    environment = _environment(
        tmp_path,
        audit_timestamp=NOW - timedelta(days=500),
        audit_held=True,
    )
    try:
        result = environment.service().execute(ARCHIVE_ID)

        assert result.deleted_record_count == 0
        assert result.protected_record_count == 1
        with environment.archive.session_factory() as session:
            assert session.get(Incident, INCIDENT_ID) is not None
            audit = session.scalar(
                select(AuditEvent).where(AuditEvent.audit_event_id == AUDIT_ID)
            )
            assert audit is not None
            assert audit.incident_id == INCIDENT_ID
    finally:
        environment.archive.engine.dispose()


def test_eligible_archived_audit_is_deleted_before_terminal_incident(
    tmp_path,
) -> None:
    environment = _environment(
        tmp_path,
        audit_timestamp=NOW - timedelta(days=500),
    )
    try:
        result = environment.service().execute(ARCHIVE_ID)

        assert result.deleted_record_count == 2
        assert result.protected_record_count == 0
        with environment.archive.session_factory() as session:
            assert session.get(Incident, INCIDENT_ID) is None
            assert session.scalar(
                select(AuditEvent).where(AuditEvent.audit_event_id == AUDIT_ID)
            ) is None

        repeated = environment.service().execute(ARCHIVE_ID)
        assert repeated.deleted_record_count == 2
        assert repeated.protected_record_count == 0
    finally:
        environment.archive.engine.dispose()


def test_audit_added_after_archive_protects_incident_without_detaching(
    tmp_path,
) -> None:
    environment = _environment(tmp_path, audit_timestamp=None)
    try:
        with environment.archive.session_factory() as session:
            incident = session.get(Incident, INCIDENT_ID)
            assert incident is not None
            session.add(
                AuditEvent(
                    audit_event_id=AUDIT_ID,
                    incident=incident,
                    timestamp=NOW - timedelta(days=500),
                    event_type="late_insert",
                    entity_type="incident",
                    entity_id=INCIDENT_ID,
                    action="late_insert",
                )
            )
            session.commit()

        result = environment.service().execute(ARCHIVE_ID)

        assert result.deleted_record_count == 0
        assert result.protected_record_count == 1
        with environment.archive.session_factory() as session:
            assert session.get(Incident, INCIDENT_ID) is not None
            audit = session.scalar(
                select(AuditEvent).where(AuditEvent.audit_event_id == AUDIT_ID)
            )
            assert audit is not None
            assert audit.incident_id == INCIDENT_ID
    finally:
        environment.archive.engine.dispose()


def test_audit_that_loses_current_eligibility_protects_incident(tmp_path) -> None:
    environment = _environment(
        tmp_path,
        audit_timestamp=NOW - timedelta(days=500),
    )
    try:
        with environment.archive.session_factory() as session:
            session.add(
                RetentionHold(
                    hold_id="hold-added-after-archive",
                    entity_type="audit_event",
                    entity_id=AUDIT_ID,
                    reason="New investigation hold",
                    created_at=NOW,
                )
            )
            session.commit()

        result = environment.service().execute(ARCHIVE_ID)

        assert result.deleted_record_count == 0
        assert result.protected_record_count == 2
        with environment.archive.session_factory() as session:
            assert session.get(Incident, INCIDENT_ID) is not None
            audit = session.scalar(
                select(AuditEvent).where(AuditEvent.audit_event_id == AUDIT_ID)
            )
            assert audit is not None
            assert audit.incident_id == INCIDENT_ID
    finally:
        environment.archive.engine.dispose()


def test_failure_after_audit_batch_resumes_before_incident_without_double_count(
    tmp_path,
) -> None:
    environment = _environment(
        tmp_path,
        audit_timestamp=NOW - timedelta(days=500),
    )

    def fail_after_audit_batch(batch_number: int) -> None:
        if batch_number == 1:
            raise RuntimeError("controlled phase boundary failure")

    try:
        with pytest.raises(CleanupOperationError):
            environment.service(
                batch_committed_hook=fail_after_audit_batch
            ).execute(ARCHIVE_ID)

        with environment.archive.session_factory() as session:
            run = session.scalar(select(RetentionCleanupRun))
            assert run is not None
            assert run.deleted_record_count == 1
            assert session.get(Incident, INCIDENT_ID) is not None
            assert session.scalar(
                select(AuditEvent).where(AuditEvent.audit_event_id == AUDIT_ID)
            ) is None
            audit_progress = session.get(
                RetentionCleanupProgress,
                (run.cleanup_run_id, "audit_event"),
            )
            incident_progress = session.get(
                RetentionCleanupProgress,
                (run.cleanup_run_id, "incident"),
            )
            assert audit_progress is not None
            assert audit_progress.scanned_count == 1
            assert audit_progress.deleted_count == 1
            assert audit_progress.last_entity_id == AUDIT_ID
            assert incident_progress is not None
            assert incident_progress.scanned_count == 0

        resumed = environment.service().execute(ARCHIVE_ID)
        assert resumed.resumed is True
        assert resumed.deleted_record_count == 2
        assert resumed.protected_record_count == 0
        with environment.archive.session_factory() as session:
            run = session.scalar(select(RetentionCleanupRun))
            assert run is not None
            assert session.get(Incident, INCIDENT_ID) is None
            audit_progress = session.get(
                RetentionCleanupProgress,
                (run.cleanup_run_id, "audit_event"),
            )
            incident_progress = session.get(
                RetentionCleanupProgress,
                (run.cleanup_run_id, "incident"),
            )
            assert audit_progress is not None
            assert audit_progress.scanned_count == 1
            assert audit_progress.deleted_count == 1
            assert incident_progress is not None
            assert incident_progress.scanned_count == 1
            assert incident_progress.deleted_count == 1
    finally:
        environment.archive.engine.dispose()


def test_foreign_keys_remain_valid_and_audit_link_is_never_silently_null(
    tmp_path,
) -> None:
    environment = _environment(tmp_path, audit_timestamp=None)
    try:
        with environment.archive.session_factory() as session:
            incident = session.get(Incident, INCIDENT_ID)
            assert incident is not None
            session.add(
                AuditEvent(
                    audit_event_id=AUDIT_ID,
                    incident=incident,
                    timestamp=NOW,
                    event_type="concurrent_history",
                    entity_type="incident",
                    entity_id=INCIDENT_ID,
                    action="preserve",
                )
            )
            session.commit()

        environment.service().execute(ARCHIVE_ID)

        with environment.archive.session_factory() as session:
            assert session.execute(text("PRAGMA foreign_key_check")).all() == []
            audit = session.scalar(
                select(AuditEvent).where(AuditEvent.audit_event_id == AUDIT_ID)
            )
            assert audit is not None
            assert audit.incident_id == INCIDENT_ID
            assert session.get(Incident, INCIDENT_ID) is not None
    finally:
        environment.archive.engine.dispose()


def test_audit_insert_racing_incident_delete_rolls_back_batch(
    tmp_path,
    monkeypatch,
) -> None:
    environment = _environment(tmp_path, audit_timestamp=None)
    original_delete_dependencies = (
        RetentionCleanupRepository._delete_incident_dependencies
    )

    def insert_audit_before_root_delete(
        repository: RetentionCleanupRepository,
        incident_ids: set[str],
    ) -> None:
        original_delete_dependencies(repository, incident_ids)
        repository._session.add(
            AuditEvent(
                audit_event_id="audit-racing-root-delete",
                incident_id=INCIDENT_ID,
                timestamp=NOW,
                event_type="concurrent_history",
                entity_type="incident",
                entity_id=INCIDENT_ID,
                action="race",
            )
        )
        repository._session.flush()

    monkeypatch.setattr(
        RetentionCleanupRepository,
        "_delete_incident_dependencies",
        insert_audit_before_root_delete,
    )
    try:
        with pytest.raises(CleanupOperationError) as error:
            environment.service().execute(ARCHIVE_ID)
        assert error.value.code == "cleanup_root_delete_conflict"

        with environment.archive.session_factory() as session:
            run = session.scalar(select(RetentionCleanupRun))
            assert run is not None
            assert run.status == "failed"
            assert run.deleted_record_count == 0
            assert session.get(Incident, INCIDENT_ID) is not None
            assert session.scalar(
                select(AuditEvent).where(
                    AuditEvent.audit_event_id == "audit-racing-root-delete"
                )
            ) is None
            assert session.execute(text("PRAGMA foreign_key_check")).all() == []
    finally:
        environment.archive.engine.dispose()
