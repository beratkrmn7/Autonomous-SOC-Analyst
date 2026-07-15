import datetime
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, inspect
from sqlalchemy.orm import sessionmaker

from agent.api.deps import get_dispatcher, get_staging_store, get_uow
from agent.application.analysis_service import AnalysisService
from agent.application.cancellation import (
    DatabaseJobCancellationChecker,
    JobCancellationRequested,
    JobCancellationService,
)
from agent.application.staging import LocalFileStagingStore
from agent.persistence.database import Base
from agent.persistence.orm_models import (
    AuditEvent,
    EvidenceItem,
    Incident,
    IngestionJob,
    Report,
    TriageRun,
)
from agent.persistence.unit_of_work import UnitOfWork
from agent.queue.dispatchers import DatabasePollingDispatcher
from agent.workers.analysis_worker import AnalysisWorker


@pytest.fixture
def session_factory(tmp_path):
    db_path = tmp_path / "cancellation.db"
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    yield factory
    engine.dispose()


@pytest.fixture
def staging_store(tmp_path):
    return LocalFileStagingStore(str(tmp_path / "staging"))


@pytest.fixture
def client(session_factory, staging_store):
    from server import app

    app.dependency_overrides[get_uow] = lambda: UnitOfWork(session_factory)
    app.dependency_overrides[get_staging_store] = lambda: staging_store
    app.dependency_overrides[get_dispatcher] = lambda: DatabasePollingDispatcher()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def create_job(session_factory, *, status="queued", attempt_count=0):
    job_id = str(uuid.uuid4())
    session = session_factory()
    try:
        session.add(IngestionJob(
            id=job_id,
            source_name="test",
            original_filename="safe.json",
            status=status,
            attempt_count=attempt_count,
            queued_at=datetime.datetime.now(datetime.timezone.utc),
        ))
        session.commit()
    finally:
        session.close()
    return job_id


def stage_job(staging_store, job_id, content=b"[]"):
    path = staging_store.staging_dir / job_id
    path.write_bytes(content)
    return path


def get_job(session_factory, job_id):
    session = session_factory()
    try:
        job = session.get(IngestionJob, job_id)
        assert job is not None
        session.expunge(job)
        return job
    finally:
        session.close()


def set_processing_lease(session_factory, job_id, lease_expires_at):
    session = session_factory()
    try:
        job = session.get(IngestionJob, job_id)
        assert job is not None
        job.worker_id = "disappeared-worker"
        job.lease_expires_at = lease_expires_at
        job.next_retry_at = lease_expires_at
        session.commit()
    finally:
        session.close()


def cancel_url(job_id):
    return f"/api/v1/analysis-jobs/{job_id}/cancel"


def test_cancellation_migration_upgrades_and_downgrades(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from agent.config import get_settings

    db_path = tmp_path / "migration.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    get_settings.cache_clear()
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")

    try:
        command.upgrade(config, "head")
        engine = create_engine(f"sqlite:///{db_path}")
        columns = {column["name"] for column in inspect(engine).get_columns("ingestion_jobs")}
        assert {
            "cancel_requested_at",
            "cancelled_at",
            "cancel_reason_code",
            "cancel_requested_by",
        }.issubset(columns)

        command.downgrade(config, "df0f1324b1ad")
        columns = {column["name"] for column in inspect(engine).get_columns("ingestion_jobs")}
        assert "cancel_requested_at" not in columns
        engine.dispose()
    finally:
        get_settings.cache_clear()


def test_queued_job_cancellation_returns_cancelled(client, session_factory, staging_store):
    job_id = create_job(session_factory)
    stage_job(staging_store, job_id)

    response = client.post(
        cancel_url(job_id),
        json={"reason": "free text must be ignored", "actor": "attacker"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"
    assert response.json()["cancel_requested_at"]
    assert response.json()["cancelled_at"]
    job = get_job(session_factory, job_id)
    assert job.cancel_reason_code == "user_requested"
    assert job.cancel_requested_by == "local-development"


def test_queued_cancellation_removes_staged_file(client, session_factory, staging_store):
    job_id = create_job(session_factory)
    staged_path = stage_job(staging_store, job_id)

    client.post(cancel_url(job_id))

    assert not staged_path.exists()


def test_queued_cancelled_job_is_never_claimed(client, session_factory, staging_store):
    job_id = create_job(session_factory)
    stage_job(staging_store, job_id)
    client.post(cancel_url(job_id))
    worker = AnalysisWorker(str(staging_store.staging_dir), session_factory=session_factory)

    with patch.object(AnalysisService, "analyze_file") as analyze:
        status = worker.process_job(job_id)

    assert status == "ignored"
    analyze.assert_not_called()
    assert get_job(session_factory, job_id).attempt_count == 0


def test_processing_job_becomes_cancel_requested(client, session_factory, staging_store):
    job_id = create_job(session_factory, status="processing", attempt_count=1)
    staged_path = stage_job(staging_store, job_id)

    response = client.post(cancel_url(job_id))

    assert response.status_code == 202
    assert response.json()["status"] == "cancel_requested"
    assert staged_path.exists()
    assert get_job(session_factory, job_id).cancelled_at is None


def test_missing_job_returns_safe_not_found(client):
    response = client.post(cancel_url(str(uuid.uuid4())))

    assert response.status_code == 404
    assert response.json() == {"code": "job_not_found"}


def test_worker_observes_cancellation_checkpoint(
    session_factory, staging_store
):
    job_id = create_job(session_factory)
    stage_job(staging_store, job_id)
    worker = AnalysisWorker(str(staging_store.staging_dir), session_factory=session_factory)

    class TriggerCancellationChecker:
        def __init__(self):
            self.calls = 0

        def raise_if_cancelled(self, current_job_id):
            self.calls += 1
            if self.calls == 2:
                JobCancellationService(
                    UnitOfWork(session_factory), staging_store
                ).cancel(current_job_id)
                raise JobCancellationRequested(current_job_id)

    checker = TriggerCancellationChecker()
    worker.cancellation_checker = checker

    status = worker.process_job(job_id)

    assert status == "cancelled"
    assert checker.calls == 2
    assert get_job(session_factory, job_id).status == "cancelled"


def test_cancellation_rolls_back_partial_analysis_records(
    session_factory, staging_store
):
    job_id = create_job(session_factory)
    stage_job(staging_store, job_id)
    worker = AnalysisWorker(str(staging_store.staging_dir), session_factory=session_factory)
    incident_id = f"INC-{uuid.uuid4().hex}"

    def write_then_cancel(*args, **kwargs):
        JobCancellationService(UnitOfWork(session_factory), staging_store).cancel(job_id)
        with UnitOfWork(session_factory) as uow:
            assert uow.session is not None
            incident = Incident(incident_id=incident_id, status="new")
            uow.session.add(incident)
            uow.session.flush()
            triage = TriageRun(
                triage_run_id=f"TR-{uuid.uuid4().hex}",
                job_id=job_id,
                incident_id=incident_id,
            )
            uow.session.add(triage)
            uow.session.flush()
            uow.session.add(EvidenceItem(
                evidence_id=f"EV-{uuid.uuid4().hex}",
                job_id=job_id,
                incident_id=incident_id,
                triage_run_id=triage.id,
                event_id="event-1",
            ))
            uow.session.add(Report(
                report_id=f"RP-{uuid.uuid4().hex}",
                job_id=job_id,
                incident_id=incident_id,
                triage_run_id=triage.id,
                content="partial",
            ))
            raise JobCancellationRequested(job_id)

    with patch.object(AnalysisService, "analyze_file", side_effect=write_then_cancel):
        assert worker.process_job(job_id) == "cancelled"

    session = session_factory()
    try:
        assert session.query(Incident).filter_by(incident_id=incident_id).count() == 0
        assert session.query(TriageRun).filter_by(job_id=job_id).count() == 0
        assert session.query(EvidenceItem).filter_by(job_id=job_id).count() == 0
        assert session.query(Report).filter_by(job_id=job_id).count() == 0
    finally:
        session.close()


def test_processing_cancellation_eventually_becomes_cancelled(
    client, session_factory, staging_store
):
    job_id = create_job(session_factory, status="processing", attempt_count=1)
    staged_path = stage_job(staging_store, job_id)
    assert client.post(cancel_url(job_id)).status_code == 202
    worker = AnalysisWorker(str(staging_store.staging_dir), session_factory=session_factory)

    with patch.object(AnalysisService, "analyze_file") as analyze:
        status = worker.process_job(job_id)

    assert status == "cancelled"
    analyze.assert_not_called()
    assert get_job(session_factory, job_id).status == "cancelled"
    assert not staged_path.exists()


def test_stale_cancellation_request_is_finalized_without_analysis(
    client, session_factory, staging_store
):
    attempt_count = 2
    job_id = create_job(
        session_factory, status="processing", attempt_count=attempt_count
    )
    expired = datetime.datetime.now(
        datetime.timezone.utc
    ) - datetime.timedelta(seconds=10)
    set_processing_lease(session_factory, job_id, expired)
    staged_path = stage_job(staging_store, job_id)

    response = client.post(cancel_url(job_id))
    assert response.status_code == 202
    assert response.json()["status"] == "cancel_requested"

    worker = AnalysisWorker(
        str(staging_store.staging_dir), session_factory=session_factory
    )
    with patch.object(AnalysisService, "analyze_file") as analyze:
        assert worker.recover_stale_jobs() == 1

    analyze.assert_not_called()
    job = get_job(session_factory, job_id)
    assert job.status == "cancelled"
    assert job.cancelled_at is not None
    assert job.worker_id is None
    assert job.lease_expires_at is None
    assert job.next_retry_at is None
    assert job.attempt_count == attempt_count
    assert not staged_path.exists()

    session = session_factory()
    try:
        assert session.query(AuditEvent).filter_by(
            entity_id=job_id, event_type="job_cancelled"
        ).count() == 1
        assert session.query(Incident).count() == 0
        assert session.query(TriageRun).filter_by(job_id=job_id).count() == 0
        assert session.query(EvidenceItem).filter_by(job_id=job_id).count() == 0
        assert session.query(Report).filter_by(job_id=job_id).count() == 0
    finally:
        session.close()


def test_unexpired_cancellation_request_is_not_recovered(
    client, session_factory, staging_store
):
    job_id = create_job(
        session_factory, status="processing", attempt_count=1
    )
    unexpired = datetime.datetime.now(
        datetime.timezone.utc
    ) + datetime.timedelta(minutes=5)
    set_processing_lease(session_factory, job_id, unexpired)
    staged_path = stage_job(staging_store, job_id)
    assert client.post(cancel_url(job_id)).status_code == 202
    worker = AnalysisWorker(
        str(staging_store.staging_dir), session_factory=session_factory
    )

    assert worker.recover_stale_jobs() == 0

    job = get_job(session_factory, job_id)
    assert job.status == "cancel_requested"
    assert job.cancelled_at is None
    assert job.worker_id == "disappeared-worker"
    assert job.lease_expires_at is not None
    assert staged_path.exists()


def test_stale_cancellation_recovery_is_idempotent(
    client, session_factory, staging_store
):
    job_id = create_job(
        session_factory, status="processing", attempt_count=1
    )
    expired = datetime.datetime.now(
        datetime.timezone.utc
    ) - datetime.timedelta(seconds=10)
    set_processing_lease(session_factory, job_id, expired)
    stage_job(staging_store, job_id)
    assert client.post(cancel_url(job_id)).status_code == 202
    worker = AnalysisWorker(
        str(staging_store.staging_dir), session_factory=session_factory
    )

    assert worker.recover_stale_jobs() == 1
    assert worker.recover_stale_jobs() == 0

    session = session_factory()
    try:
        assert session.query(AuditEvent).filter_by(
            entity_id=job_id, event_type="job_cancelled"
        ).count() == 1
    finally:
        session.close()


def test_repeated_cancellation_is_idempotent(client, session_factory, staging_store):
    job_id = create_job(session_factory)
    stage_job(staging_store, job_id)

    first = client.post(cancel_url(job_id))
    second = client.post(cancel_url(job_id))

    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    session = session_factory()
    try:
        request_events = session.query(AuditEvent).filter_by(
            entity_id=job_id, event_type="job_cancellation_requested"
        ).count()
        finish_events = session.query(AuditEvent).filter_by(
            entity_id=job_id, event_type="job_cancelled"
        ).count()
        assert request_events == 1
        assert finish_events == 1
    finally:
        session.close()


@pytest.mark.parametrize("terminal_status", ["completed", "failed"])
def test_terminal_job_returns_job_not_cancellable(
    client, session_factory, terminal_status
):
    job_id = create_job(session_factory, status=terminal_status)

    response = client.post(cancel_url(job_id))

    assert response.status_code == 409
    assert response.json() == {
        "code": "job_not_cancellable",
        "status": terminal_status,
    }
    assert get_job(session_factory, job_id).status == terminal_status


def test_cancelled_duplicate_celery_delivery_is_ignored(
    client, session_factory, staging_store
):
    from agent.queue.tasks import analyze_job_task

    job_id = create_job(session_factory)
    stage_job(staging_store, job_id)
    client.post(cancel_url(job_id))
    worker = AnalysisWorker(str(staging_store.staging_dir), session_factory=session_factory)

    with (
        patch("agent.queue.tasks.AnalysisWorker", return_value=worker),
        patch.object(AnalysisService, "analyze_file") as analyze,
    ):
        status = analyze_job_task.run(job_id)

    assert status == "ignored"
    analyze.assert_not_called()


def test_attempt_count_does_not_increase_after_cancellation(
    client, session_factory, staging_store
):
    job_id = create_job(session_factory, attempt_count=2)
    stage_job(staging_store, job_id)
    client.post(cancel_url(job_id))
    worker = AnalysisWorker(str(staging_store.staging_dir), session_factory=session_factory)

    worker.process_job(job_id)

    assert get_job(session_factory, job_id).attempt_count == 2


def test_cancel_vs_claim_race_has_only_valid_outcomes(session_factory, staging_store):
    job_id = create_job(session_factory)
    stage_job(staging_store, job_id)
    barrier = threading.Barrier(2)

    def claim_job():
        session = session_factory()
        try:
            barrier.wait()
            now = datetime.datetime.now(datetime.timezone.utc)
            updated = session.query(IngestionJob).filter(
                IngestionJob.id == job_id,
                IngestionJob.status == "queued",
                (IngestionJob.next_retry_at.is_(None))
                | (IngestionJob.next_retry_at <= func.now()),
            ).update({
                "status": "processing",
                "attempt_count": IngestionJob.attempt_count + 1,
                "worker_id": "race-worker",
                "lease_expires_at": now + datetime.timedelta(minutes=1),
            }, synchronize_session=False)
            session.commit()
            return updated
        finally:
            session.close()

    def cancel_job():
        barrier.wait()
        return JobCancellationService(
            UnitOfWork(session_factory), staging_store
        ).cancel(job_id).status

    with ThreadPoolExecutor(max_workers=2) as executor:
        claim_future = executor.submit(claim_job)
        cancel_future = executor.submit(cancel_job)
        claim_count = claim_future.result()
        cancellation_status = cancel_future.result()

    job = get_job(session_factory, job_id)
    assert cancellation_status in ("cancel_requested", "cancelled")
    assert job.status in ("cancel_requested", "cancelled")
    if job.status == "cancelled":
        assert claim_count == 0
        assert job.attempt_count == 0
    else:
        assert claim_count == 1
        assert job.attempt_count == 1
        JobCancellationService(UnitOfWork(session_factory), staging_store).finalize(job_id)


def test_result_endpoint_reports_cancellation_states(
    client, session_factory, staging_store
):
    processing_id = create_job(session_factory, status="processing", attempt_count=1)
    stage_job(staging_store, processing_id)
    client.post(cancel_url(processing_id))

    requested = client.get(f"/api/v1/analysis-jobs/{processing_id}/result")
    assert requested.status_code == 202
    assert requested.json()["status"] == "cancel_requested"

    JobCancellationService(UnitOfWork(session_factory), staging_store).finalize(
        processing_id
    )
    cancelled = client.get(f"/api/v1/analysis-jobs/{processing_id}/result")
    assert cancelled.status_code == 200
    assert cancelled.json() == {"status": "cancelled"}
    assert "incident_ids" not in cancelled.json()
    assert "reports" not in cancelled.json()


def test_api_never_exposes_paths_secrets_or_raw_errors(
    client, session_factory, staging_store
):
    job_id = create_job(session_factory)
    stage_job(staging_store, job_id)
    secret_values = [
        str(staging_store.staging_dir),
        "redis://secret-password@broker:6379/0",
        "sqlite:///private.db",
        "RAW_EXCEPTION_SECRET",
    ]

    responses = [
        client.post(cancel_url(job_id)),
        client.get(f"/api/v1/analysis-jobs/{job_id}"),
        client.get(f"/api/v1/analysis-jobs/{job_id}/result"),
    ]
    rendered = " ".join(response.text for response in responses)

    assert all(secret not in rendered for secret in secret_values)


def test_staging_cleanup_failure_keeps_cancelled_state_and_logs_safe_category(
    client, session_factory, staging_store
):
    job_id = create_job(session_factory)
    stage_job(staging_store, job_id)

    with (
        patch.object(
            staging_store,
            "remove_file",
            side_effect=Exception("C:/private/path RAW_EXCEPTION_SECRET"),
        ),
        patch("agent.application.cancellation.logger.warning") as warning,
    ):
        response = client.post(cancel_url(job_id))

    assert response.status_code == 200
    assert get_job(session_factory, job_id).status == "cancelled"
    warning.assert_called_once_with("staging_cleanup_failed")


def test_checker_uses_database_source_of_truth(session_factory):
    job_id = create_job(session_factory, status="cancel_requested")
    checker = DatabaseJobCancellationChecker(session_factory)

    with pytest.raises(JobCancellationRequested):
        checker.raise_if_cancelled(job_id)
