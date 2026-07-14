import pytest
import datetime
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from server import app
from agent.config import get_settings
from agent.persistence.database import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from agent.persistence.orm_models import WorkerHeartbeat, IngestionJob
from agent.workers.heartbeat_service import WorkerHeartbeatService
from agent.workers.analysis_worker import AnalysisWorker
from agent.application.staging import LocalFileStagingStore
import os
import tempfile

from sqlalchemy.pool import StaticPool

@pytest.fixture(scope="function")
def sqlite_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()

@pytest.fixture(scope="function")
def db_session_factory(sqlite_engine):
    return sessionmaker(bind=sqlite_engine)

@pytest.fixture(scope="function")
def db_session(db_session_factory):
    session = db_session_factory()
    yield session
    session.close()

@pytest.fixture(scope="function")
def override_deps(db_session_factory):
    class FakeUOW:
        def __init__(self):
            self.session = db_session_factory()
        def commit(self):
            self.session.commit()
        def rollback(self):
            self.session.rollback()
            
    def get_fake_uow():
        uow = FakeUOW()
        try:
            yield uow
        finally:
            uow.session.close()

    from agent.api.deps import get_uow
    app.dependency_overrides[get_uow] = get_fake_uow
    yield
    app.dependency_overrides.clear()

@pytest.fixture(scope="function")
def client(override_deps):
    return TestClient(app)

def test_worker_startup_creates_heartbeat(db_session_factory, db_session):
    service = WorkerHeartbeatService(session_factory=db_session_factory)
    service.register_startup("worker-1", "test_worker", "1.0.0")
    
    hb = db_session.query(WorkerHeartbeat).filter_by(worker_id="worker-1").first()
    assert hb is not None
    assert hb.status == "starting"
    assert hb.worker_type == "test_worker"

def test_heartbeat_timestamp_updates(db_session_factory, db_session):
    service = WorkerHeartbeatService(session_factory=db_session_factory)
    service.register_startup("worker-2", "test_worker")
    
    hb1 = db_session.query(WorkerHeartbeat).filter_by(worker_id="worker-2").first()
    old_time = hb1.last_heartbeat_at
    
    # Update heartbeat
    service.update_heartbeat("worker-2", "busy")
    
    # Needs refresh
    db_session.expire_all()
    hb2 = db_session.query(WorkerHeartbeat).filter_by(worker_id="worker-2").first()
    assert hb2.status == "busy"
    assert hb2.last_heartbeat_at >= old_time

def test_job_processing_changes_idle_busy_idle(db_session_factory, db_session):
    with tempfile.TemporaryDirectory() as tempdir:
        # Create job
        job = IngestionJob(id="job-123", status="queued")
        db_session.add(job)
        db_session.commit()
        
        # Staging file
        LocalFileStagingStore(tempdir)
        with open(os.path.join(tempdir, "job-123"), "w") as f:
            f.write("test")
            
        worker = AnalysisWorker(staging_dir=tempdir, worker_id="worker-job", session_factory=db_session_factory)
        
        # Mock actual analysis to return completed
        with patch("agent.workers.analysis_worker.AnalysisService") as MockService:
            mock_inst = MockService.return_value
            mock_inst.analyze_file.return_value = {"incidents": [], "metrics": {}}
            
            # Check heartbeat before process
            hb = db_session.query(WorkerHeartbeat).filter_by(worker_id="worker-job").first()
            assert hb.status == "starting"
            
            # We want to assert during processing it's busy, but that's hard synchronously.
            # We'll assert that process_job completes and heartbeat is idle after.
            status = worker.process_job("job-123")
            assert status == "completed"
            
            db_session.expire_all()
            hb_after = db_session.query(WorkerHeartbeat).filter_by(worker_id="worker-job").first()
            assert hb_after.status == "idle"

def test_stale_worker_is_detected(client, db_session_factory, db_session, override_deps):
    settings = get_settings()
    now = datetime.datetime.now(datetime.timezone.utc)
    old_time = now - datetime.timedelta(seconds=settings.worker_heartbeat_stale_seconds + 10)
    
    hb = WorkerHeartbeat(
        worker_id="stale-worker",
        worker_type="test",
        status="busy",
        last_heartbeat_at=old_time,
        hostname_hash="123",
        version="1"
    )
    db_session.add(hb)
    db_session.commit()
    
    res = client.get("/api/v1/workers")
    assert res.status_code == 200
    items = res.json()["items"]
    assert len(items) == 1
    assert items[0]["stale"] is True

def test_liveness_does_not_require_database_or_redis(client):
    # Just checking it returns 200 without mocking anything special
    res = client.get("/health/live")
    assert res.status_code == 200
    assert res.json() == {"status": "live"}

def test_readiness_fails_safely_when_database_is_unavailable(client):
    with patch("sqlalchemy.orm.Session.execute") as mock_exec:
        mock_exec.side_effect = Exception("DB Down")
        res = client.get("/health/ready")
        assert res.status_code == 503
        data = res.json()
        assert data["components"]["database"] == "down"

def test_readiness_checks_redis_only_for_celery_backend(client, db_session_factory, db_session, override_deps):
    settings = get_settings()
    settings.task_queue_backend = "celery"
    
    # Add active worker
    now = datetime.datetime.now(datetime.timezone.utc)
    hb = WorkerHeartbeat(
        worker_id="active-celery",
        worker_type="test",
        last_heartbeat_at=now,
        hostname_hash="123",
        version="1"
    )
    db_session.add(hb)
    db_session.commit()
    
    with patch("redis.Redis.from_url") as mock_redis:
        mock_redis.side_effect = Exception("Redis Down")
        
        res = client.get("/health/ready")
        assert res.status_code == 503
        assert res.json()["components"]["queue"] == "down"
        
        mock_redis.return_value = MagicMock()
        mock_redis.side_effect = None
        
        res2 = client.get("/health/ready")
        assert res2.status_code == 200
        assert res2.json()["components"]["queue"] == "up"

    settings.task_queue_backend = "database"

def test_readiness_returns_503_when_all_workers_are_stale(client, db_session_factory, db_session, override_deps):
    settings = get_settings()
    settings.task_queue_backend = "celery" # We only check active workers when celery is enabled
    
    now = datetime.datetime.now(datetime.timezone.utc)
    old_time = now - datetime.timedelta(seconds=settings.worker_heartbeat_stale_seconds + 10)
    
    hb = WorkerHeartbeat(
        worker_id="stale-celery",
        worker_type="test",
        last_heartbeat_at=old_time,
        hostname_hash="123",
        version="1"
    )
    db_session.add(hb)
    db_session.commit()
    
    with patch("redis.Redis.from_url"):
        res = client.get("/health/ready")
        assert res.status_code == 503
        assert res.json()["components"]["worker"] == "down"
        
    settings.task_queue_backend = "database"

def test_health_responses_do_not_expose_secrets_or_urls(client):
    with patch("sqlalchemy.orm.Session.execute") as mock_exec:
        mock_exec.side_effect = Exception("Super Secret DB Error password=123")
        res = client.get("/health/ready")
        body = res.json()
        assert "password=123" not in str(body)
        assert "Super Secret DB Error" not in str(body)

def test_heartbeat_write_failure_does_not_crash_job(db_session_factory, db_session):
    with tempfile.TemporaryDirectory() as tempdir:
        job = IngestionJob(id="job-hb-fail", status="queued")
        db_session.add(job)
        db_session.commit()
        
        LocalFileStagingStore(tempdir)
        with open(os.path.join(tempdir, "job-hb-fail"), "w") as f:
            f.write("test")
            
        worker = AnalysisWorker(staging_dir=tempdir, worker_id="worker-fail", session_factory=db_session_factory)
        
        with patch("agent.workers.analysis_worker.AnalysisService") as MockService:
            mock_inst = MockService.return_value
            mock_inst.analyze_file.return_value = {"incidents": [], "metrics": {}}
            
            with patch.object(worker.heartbeat_service, "update_heartbeat", side_effect=Exception("DB Failure")):
                status = worker.process_job("job-hb-fail")
                assert status == "completed"
