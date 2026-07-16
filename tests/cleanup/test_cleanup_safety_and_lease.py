from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
import threading

import pytest
from sqlalchemy import func, select

from agent.application.cleanup import CleanupOperationError
from agent.persistence.cleanup_repository import (
    CleanupBatchCounts,
    CleanupPersistenceError,
)
from agent.persistence.orm_models import (
    AuditEvent,
    CanonicalEvent,
    DetectionSignal,
    Incident,
    IncidentEvent,
    IncidentSignal,
    IngestionJob,
    RetentionArchiveRun,
    RetentionCleanupProgress,
    RetentionCleanupRun,
    RetentionHold,
)
from agent.persistence.unit_of_work import UnitOfWork
from tests.archive.conftest import ARCHIVE_ID, NOW, make_environment
from tests.cleanup.conftest import CleanupEnvironment
from tests.cleanup.test_cleanup_resume_and_drift import _seed_then_archive


@pytest.mark.parametrize("status", ["creating", "completed", "failed"])
def test_unverified_archive_status_never_starts_cleanup(cleanup_env, status) -> None:
    with cleanup_env.archive.session_factory() as session:
        archive = session.get(RetentionArchiveRun, ARCHIVE_ID)
        assert archive is not None
        archive.status = status
        session.commit()

    with pytest.raises(CleanupOperationError) as error:
        cleanup_env.service().execute(ARCHIVE_ID)
    assert error.value.code == "cleanup_archive_not_verified"
    with cleanup_env.archive.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(RetentionCleanupRun)) == 0
        assert session.get(Incident, "incident-old-candidate") is not None


def test_unknown_archive_never_creates_cleanup_run(cleanup_env) -> None:
    with pytest.raises(CleanupOperationError) as error:
        cleanup_env.service().execute("ARC-ffffffffffffffffffffffffffffffff")
    assert error.value.code == "cleanup_archive_not_found"
    with cleanup_env.archive.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(RetentionCleanupRun)) == 0


def test_corrupt_payload_fails_before_cleanup_metadata_or_delete(cleanup_env) -> None:
    payload = (
        Path(cleanup_env.settings.retention_archive_root)
        / ARCHIVE_ID
        / "audit_events.ndjson.gz"
    )
    content = bytearray(payload.read_bytes())
    content[-1] ^= 1
    payload.write_bytes(bytes(content))

    with pytest.raises(CleanupOperationError) as error:
        cleanup_env.service().execute(ARCHIVE_ID)
    assert error.value.code == "cleanup_archive_integrity_failed"
    with cleanup_env.archive.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(RetentionCleanupRun)) == 0
        assert session.get(Incident, "incident-old-candidate") is not None


def test_database_known_manifest_checksum_mismatch_fails_closed(cleanup_env) -> None:
    with cleanup_env.archive.session_factory() as session:
        archive = session.get(RetentionArchiveRun, ARCHIVE_ID)
        assert archive is not None
        archive.manifest_sha256 = "0" * 64
        session.commit()
    with pytest.raises(CleanupOperationError) as error:
        cleanup_env.service().execute(ARCHIVE_ID)
    assert error.value.code == "cleanup_archive_integrity_failed"
    with cleanup_env.archive.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(RetentionCleanupRun)) == 0
        assert session.get(Incident, "incident-old-candidate") is not None


def test_new_active_incident_relation_protects_archived_event(cleanup_env) -> None:
    with cleanup_env.archive.session_factory() as session:
        active = session.get(Incident, "incident-needs-review")
        assert active is not None
        active.events.append(IncidentEvent(event_id="event-old-candidate"))
        session.commit()

    result = cleanup_env.service().execute(ARCHIVE_ID)

    assert result.protected_record_count >= 3
    with cleanup_env.archive.session_factory() as session:
        assert session.get(Incident, "incident-needs-review") is not None
        assert session.get(CanonicalEvent, "event-old-candidate") is not None


def test_needs_review_incident_relation_protects_archived_signal(cleanup_env) -> None:
    with cleanup_env.archive.session_factory() as session:
        active = session.get(Incident, "incident-needs-review")
        assert active is not None
        active.signals.append(IncidentSignal(signal_id="signal-old-candidate"))
        session.commit()
    cleanup_env.service().execute(ARCHIVE_ID)
    with cleanup_env.archive.session_factory() as session:
        assert session.get(DetectionSignal, "signal-old-candidate") is not None


@pytest.mark.parametrize("status", ["processing", "queued", "cancel_requested"])
def test_job_status_changed_after_archive_is_protected(tmp_path, status) -> None:
    archive = make_environment(tmp_path)
    with archive.session_factory() as session:
        session.add(
            IngestionJob(
                id="job-status-race",
                status="completed",
                created_at=NOW - timedelta(days=130),
                completed_at=NOW - timedelta(days=120),
            )
        )
        session.commit()
    archive.service().create()
    with archive.session_factory() as session:
        job = session.get(IngestionJob, "job-status-race")
        assert job is not None
        job.status = status
        session.commit()
    settings = archive.settings.model_copy(
        update={"retention_cleanup_batch_size": 2}
    )
    result = CleanupEnvironment(archive, settings).service().execute(ARCHIVE_ID)
    assert result.deleted_record_count == 0
    assert result.protected_record_count == 1
    with archive.session_factory() as session:
        assert session.get(IngestionJob, "job-status-race") is not None
    archive.engine.dispose()


def test_archive_candidate_missing_from_database_is_not_counted_deleted(tmp_path) -> None:
    archive = make_environment(tmp_path)
    with archive.session_factory() as session:
        session.add(
            AuditEvent(
                audit_event_id="audit-missing-before-cleanup",
                timestamp=NOW - timedelta(days=500),
                event_type="old",
                action="old",
            )
        )
        session.commit()
    archive.service().create()
    with archive.session_factory() as session:
        audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.audit_event_id == "audit-missing-before-cleanup"
            )
        )
        assert audit is not None
        session.delete(audit)
        session.commit()
    settings = archive.settings.model_copy(
        update={"retention_cleanup_batch_size": 2}
    )
    result = CleanupEnvironment(archive, settings).service().execute(ARCHIVE_ID)
    assert result.deleted_record_count == 0
    assert result.missing_record_count == 1
    assert result.protected_record_count == 0
    archive.engine.dispose()


def test_expired_hold_added_after_archive_does_not_block_current_eligibility(
    cleanup_env,
) -> None:
    with cleanup_env.archive.session_factory() as session:
        session.add(
            RetentionHold(
                hold_id="hold-expiring-after-archive",
                entity_type="incident",
                entity_id="incident-old-candidate",
                reason="Temporary review",
                created_at=NOW + timedelta(minutes=1),
                expires_at=NOW + timedelta(minutes=2),
            )
        )
        session.commit()

    result = cleanup_env.service(
        clock=lambda: NOW + timedelta(minutes=3)
    ).execute(ARCHIVE_ID)

    assert result.deleted_record_count == 2
    with cleanup_env.archive.session_factory() as session:
        assert session.get(Incident, "incident-old-candidate") is None


def test_active_lease_rejects_second_executor_and_expired_lease_resumes(
    tmp_path,
) -> None:
    environment = _seed_then_archive(tmp_path)

    def stop(batch_number: int) -> None:
        if batch_number == 1:
            raise RuntimeError("controlled")

    with pytest.raises(CleanupOperationError):
        environment.service(batch_committed_hook=stop).execute(ARCHIVE_ID)
    with environment.archive.session_factory() as session:
        run = session.scalar(select(RetentionCleanupRun))
        assert run is not None
        run.status = "running"
        run.lease_owner = "a" * 32
        run.lease_expires_at = NOW + timedelta(minutes=5)
        session.commit()

    with pytest.raises(CleanupOperationError) as error:
        environment.service().execute(ARCHIVE_ID)
    assert error.value.code == "cleanup_lease_active"

    with environment.archive.session_factory() as session:
        run = session.scalar(select(RetentionCleanupRun))
        assert run is not None
        run.lease_expires_at = NOW - timedelta(seconds=1)
        session.commit()
    result = environment.service().execute(ARCHIVE_ID)
    assert result.status == "completed"
    assert result.resumed is True
    environment.archive.engine.dispose()


def test_atomic_claim_allows_only_one_concurrent_owner(tmp_path) -> None:
    environment = _seed_then_archive(tmp_path)

    def stop(batch_number: int) -> None:
        if batch_number == 1:
            raise RuntimeError("controlled")

    with pytest.raises(CleanupOperationError):
        environment.service(batch_committed_hook=stop).execute(ARCHIVE_ID)
    with environment.archive.session_factory() as session:
        run = session.scalar(select(RetentionCleanupRun))
        assert run is not None
        cleanup_run_id = str(run.cleanup_run_id)
        run.status = "failed"
        run.lease_owner = None
        run.lease_expires_at = None
        session.commit()

    barrier = threading.Barrier(2)

    def claim(owner: str) -> bool:
        barrier.wait()
        with UnitOfWork(environment.archive.session_factory) as uow:
            return uow.cleanup.claim(
                cleanup_run_id,
                owner=owner,
                now=NOW,
                lease_seconds=300,
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(
            future.result()
            for future in (
                executor.submit(claim, "b" * 32),
                executor.submit(claim, "c" * 32),
            )
        )
    assert sorted(results) == [False, True]
    with environment.archive.session_factory() as session:
        run = session.get(RetentionCleanupRun, cleanup_run_id)
        assert run is not None
        version = int(run.version)
        before = session.get(
            RetentionCleanupProgress,
            (cleanup_run_id, "audit_event"),
        )
        assert before is not None
        before_scanned = int(before.scanned_count)
        before_cursor = before.last_entity_id
    with pytest.raises(CleanupPersistenceError, match="cleanup_lease_lost"):
        with UnitOfWork(environment.archive.session_factory) as uow:
            uow.cleanup.apply_batch(
                cleanup_run_id,
                "audit_event",
                owner="d" * 32,
                expected_version=version,
                now=NOW,
                lease_seconds=300,
                counts=CleanupBatchCounts(1, 0, 1, 0),
                last_recorded_at=NOW,
                last_entity_id="not-committed",
            )
    with environment.archive.session_factory() as session:
        run = session.get(RetentionCleanupRun, cleanup_run_id)
        assert run is not None
        progress = session.get(
            RetentionCleanupProgress,
            (cleanup_run_id, "audit_event"),
        )
        assert progress is not None
        assert progress.scanned_count == before_scanned
        assert progress.last_entity_id == before_cursor
    environment.archive.engine.dispose()
