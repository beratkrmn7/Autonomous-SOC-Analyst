import pytest
from fastapi.testclient import TestClient

from agent.persistence.orm_models import IngestionJob
from agent.workers.analysis_worker import AnalysisWorker
import uuid
from io import BytesIO
import os

@pytest.fixture(scope="module")
def isolated_db():
    import tempfile
    import os
    from alembic.config import Config
    from alembic import command
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from agent.config import get_settings
    
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name
    
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    get_settings.cache_clear()
    
    alembic_cfg = Config("alembic.ini")
    alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    command.upgrade(alembic_cfg, "head")
    
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    yield SessionLocal
    
    # Cleanup
    engine.dispose()
    try:
        os.remove(db_path)
    except PermissionError:
        pass

@pytest.fixture(scope="module")
def client(isolated_db):
    # Since we need to test API endpoints, we import the server
    from server import app
    from agent.api.deps import get_staging_store, get_uow
    from agent.persistence.unit_of_work import UnitOfWork
    from agent.application.staging import LocalFileStagingStore
    import tempfile
    
    test_staging_dir = tempfile.mkdtemp()
    
    def override_get_staging_store():
        return LocalFileStagingStore(staging_dir=test_staging_dir)
        
    def override_get_uow():
        return UnitOfWork(session_factory=isolated_db)
        
    app.dependency_overrides[get_staging_store] = override_get_staging_store
    app.dependency_overrides[get_uow] = override_get_uow
    
    with TestClient(app) as c:
        c.test_staging_dir = test_staging_dir
        yield c
        
    app.dependency_overrides.clear()

@pytest.fixture(scope="function")
def db_session(isolated_db):
    # For a completely clean database per test, we might want to drop all or rollback
    # We will just yield a session and clean up created jobs manually
    session = isolated_db()
    yield session
    session.close()

@pytest.fixture(scope="function")
def staging_dir(client):
    # Use the same directory as the client override
    return client.test_staging_dir

@pytest.fixture(scope="function")
def worker(staging_dir, isolated_db):
    return AnalysisWorker(staging_dir=staging_dir, session_factory=isolated_db)

def test_submit_returns_202_and_queued_job_is_persisted(client, db_session):
    test_content = b'{"event_type": "test"}'
    
    response = client.post(
        "/api/v1/analysis-jobs/file",
        files={"file": ("test.json", BytesIO(test_content), "application/json")}
    )
    
    assert response.status_code == 202
    data = response.json()
    assert "job_id" in data
    assert data["status"] == "queued"
    
    job_id = data["job_id"]
    
    # Check DB
    job = db_session.query(IngestionJob).get(job_id)
    assert job is not None
    assert job.status == "queued"
    assert job.original_filename == "test.json"
    assert job.queued_at is not None

def test_worker_processes_queued_job(client, db_session, worker, staging_dir):
    # Cleanup any pending jobs to avoid picking up the one from the previous test
    db_session.query(IngestionJob).delete()
    db_session.commit()
    
    # Submit job
    test_content = b'{"timestamp": "2023-01-01T12:00:00Z", "message": "Test event"}'
    response = client.post(
        "/api/v1/analysis-jobs/file",
        files={"file": ("test.json", BytesIO(test_content), "application/json")}
    )
    job_id = response.json()["job_id"]
    
    # Ensure file is in staging
    assert os.path.exists(os.path.join(staging_dir, job_id))
    
    # Run worker until queue is empty
    while worker.run_once():
        pass
    
    
    # Check DB
    db_session.expire_all()
    job = db_session.query(IngestionJob).get(job_id)
    assert job.status in ("completed", "failed")
    assert job.attempt_count == 1
    assert job.worker_id is not None
    
    # Check API
    res = client.get(f"/api/v1/analysis-jobs/{job_id}/result")
    assert res.status_code == 200
    
    # Ensure staging file is removed
    assert not os.path.exists(os.path.join(staging_dir, job_id))

def test_failed_worker_execution_stores_safe_error(db_session, worker, staging_dir):
    # Insert a job with a missing file (which should cause analysis to fail or staging to fail)
    job_id = str(uuid.uuid4())
    job = IngestionJob(
        id=job_id,
        status="queued",
        source_name="test"
    )
    db_session.add(job)
    db_session.commit()
    
    # Run worker
    worker.run_once()
    
    # Reload job
    db_session.refresh(job)
    assert job.status == "failed"
    assert job.error_code == "WORKER_EXECUTION_FAILED"

def test_api_never_returns_staged_local_path(client, db_session):
    test_content = b'test'
    response = client.post(
        "/api/v1/analysis-jobs/file",
        files={"file": ("test.json", BytesIO(test_content), "application/json")}
    )
    job_id = response.json()["job_id"]
    
    # Check status endpoint
    res = client.get(f"/api/v1/analysis-jobs/{job_id}")
    data = res.json()
    # verify staged path is nowhere in response
    assert "tmp" not in str(data).lower()
    
    # Check result endpoint
    res2 = client.get(f"/api/v1/analysis-jobs/{job_id}/result")
    data2 = res2.json()
    assert "tmp" not in str(data2).lower()
