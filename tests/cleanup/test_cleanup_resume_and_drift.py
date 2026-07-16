from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select

from agent.application.cleanup import CleanupOperationError
from agent.persistence.orm_models import (
    AuditEvent,
    RetentionCleanupProgress,
    RetentionCleanupRun,
)
from tests.archive.conftest import ARCHIVE_ID, NOW
from tests.cleanup.conftest import make_cleanup_environment


def _audit_environment(tmp_path, count: int = 5):
    environment = make_cleanup_environment(
        tmp_path,
        seed_graph=False,
        cleanup_batch_size=2,
    )
    return environment


def _seed_then_archive(tmp_path, count: int = 5):
    from tests.archive.conftest import make_environment

    archive = make_environment(tmp_path)
    with archive.session_factory() as session:
        session.add_all(
            [
                AuditEvent(
                    audit_event_id=f"audit-{index:05d}",
                    timestamp=NOW - timedelta(days=500, seconds=count - index),
                    event_type="old",
                    action="old",
                )
                for index in range(count)
            ]
        )
        session.commit()
    archive.service().create()
    settings = archive.settings.model_copy(
        update={
            "retention_cleanup_batch_size": 2,
            "retention_cleanup_lease_seconds": 300,
        }
    )
    from tests.cleanup.conftest import CleanupEnvironment

    return CleanupEnvironment(archive, settings)


def test_failure_after_committed_batch_resumes_without_double_count(tmp_path) -> None:
    environment = _seed_then_archive(tmp_path)

    def fail_after_first_batch(batch_number: int) -> None:
        if batch_number == 1:
            raise RuntimeError("secret raw exception")

    with pytest.raises(CleanupOperationError):
        environment.service(batch_committed_hook=fail_after_first_batch).execute(
            ARCHIVE_ID
        )
    with environment.archive.session_factory() as session:
        assert session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.event_type == "old")
        ) == 3
        run = session.scalar(select(RetentionCleanupRun))
        assert run is not None
        assert run.status == "failed"
        assert run.deleted_record_count == 2
        progress = session.get(
            RetentionCleanupProgress,
            (run.cleanup_run_id, "audit_event"),
        )
        assert progress is not None
        assert progress.scanned_count == 2
        assert progress.deleted_count == 2
        assert progress.last_entity_id == "audit-00001"
        cleanup_audits = tuple(
            session.scalars(
                select(AuditEvent).where(
                    AuditEvent.entity_type == "retention_cleanup"
                )
            )
        )
        persisted = repr(
            (
                run.archive_snapshot,
                run.sanitized_error_code,
                progress.last_entity_id,
                tuple(audit.details for audit in cleanup_audits),
            )
        )
        assert "secret raw exception" not in persisted
        assert environment.settings.database_url not in persisted
        assert environment.settings.retention_archive_root not in persisted

    resumed = environment.service().execute(ARCHIVE_ID)
    assert resumed.status == "completed"
    assert resumed.resumed is True
    assert resumed.deleted_record_count == 5
    with environment.archive.session_factory() as session:
        remaining_old = session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.event_type == "old")
        )
        assert remaining_old == 0
        run = session.scalar(select(RetentionCleanupRun))
        assert run is not None
        progress = session.get(
            RetentionCleanupProgress,
            (run.cleanup_run_id, "audit_event"),
        )
        assert progress is not None
        assert progress.scanned_count == 5
        assert progress.deleted_count == 5
    environment.archive.engine.dispose()


def test_manifest_drift_stops_next_batch_and_preserves_cursor(tmp_path) -> None:
    environment = _seed_then_archive(tmp_path)
    manifest = (
        Path(environment.settings.retention_archive_root)
        / ARCHIVE_ID
        / "manifest.json"
    )

    def mutate_after_first_batch(batch_number: int) -> None:
        if batch_number == 1:
            manifest.write_bytes(manifest.read_bytes() + b" ")

    with pytest.raises(CleanupOperationError) as error:
        environment.service(batch_committed_hook=mutate_after_first_batch).execute(
            ARCHIVE_ID
        )
    assert error.value.code == "cleanup_archive_integrity_failed"
    with environment.archive.session_factory() as session:
        run = session.scalar(select(RetentionCleanupRun))
        assert run is not None
        assert run.status == "failed"
        assert run.deleted_record_count == 2
        progress = session.get(
            RetentionCleanupProgress,
            (run.cleanup_run_id, "audit_event"),
        )
        assert progress is not None
        assert progress.scanned_count == 2
        assert progress.last_entity_id == "audit-00001"
        assert session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.event_type == "old")
        ) == 3
    environment.archive.engine.dispose()


@pytest.mark.parametrize("mode", ["payload_size", "unexpected_file"])
def test_payload_or_file_set_drift_stops_next_batch(tmp_path, mode) -> None:
    environment = _seed_then_archive(tmp_path)
    directory = Path(environment.settings.retention_archive_root) / ARCHIVE_ID

    def mutate_after_first_batch(batch_number: int) -> None:
        if batch_number != 1:
            return
        if mode == "payload_size":
            payload = directory / "audit_events.ndjson.gz"
            payload.write_bytes(payload.read_bytes() + b"changed")
        else:
            (directory / "unexpected.private").write_bytes(b"unexpected")

    with pytest.raises(CleanupOperationError):
        environment.service(batch_committed_hook=mutate_after_first_batch).execute(
            ARCHIVE_ID
        )
    with environment.archive.session_factory() as session:
        run = session.scalar(select(RetentionCleanupRun))
        assert run is not None
        assert run.status == "failed"
        assert run.deleted_record_count == 2
        assert session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.event_type == "old")
        ) == 3
    environment.archive.engine.dispose()
