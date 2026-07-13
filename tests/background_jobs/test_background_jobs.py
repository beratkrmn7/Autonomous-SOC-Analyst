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

def test_idempotent_submit(client, db_session):
    # Ensure clean state
    db_session.query(IngestionJob).delete()
    db_session.commit()

    test_content = b'{"event_type": "idempotent_test"}'
    
    # First submit
    res1 = client.post(
        "/api/v1/analysis-jobs/file",
        files={"file": ("test.json", BytesIO(test_content), "application/json")}
    )
    assert res1.status_code == 202
    data1 = res1.json()
    assert data1["reused"] is False
    job_id1 = data1["job_id"]
    
    # Second submit
    res2 = client.post(
        "/api/v1/analysis-jobs/file",
        files={"file": ("test.json", BytesIO(test_content), "application/json")}
    )
    assert res2.status_code == 202
    data2 = res2.json()
    assert data2["reused"] is True
    job_id2 = data2["job_id"]
    
    # Assert same job
    assert job_id1 == job_id2
    
    # Assert exactly one job in DB
    jobs = db_session.query(IngestionJob).all()
    assert len(jobs) == 1
    assert jobs[0].id == job_id1

def test_worker_processes_queued_job(client, db_session, worker, staging_dir):
    # Cleanup any pending jobs to avoid picking up the one from the previous test
    db_session.query(IngestionJob).delete()
    db_session.commit()
    
    # Submit job with a valid empty JSON array, which parses successfully to 0 records
    test_content = b'[]'
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
    assert job.status == "completed"
    assert job.attempt_count == 1
    assert job.worker_id is not None
    
    # Check API
    res = client.get(f"/api/v1/analysis-jobs/{job_id}/result")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "completed"
    assert "incident_ids" in data
    assert "reports" in data
    
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

def test_failed_job_retry_staging(client, db_session, worker, staging_dir):
    # Ensure clean state
    db_session.query(IngestionJob).delete()
    db_session.commit()
    
    # 1. Submit a valid file
    test_content = b'[]'
    res1 = client.post(
        "/api/v1/analysis-jobs/file",
        files={"file": ("test.json", BytesIO(test_content), "application/json")}
    )
    data1 = res1.json()
    job_id = data1["job_id"]
    
    # 2. Simulate job becoming failed
    job = db_session.query(IngestionJob).get(job_id)
    job.status = "failed"
    job.error_code = "SOME_ERROR"
    db_session.commit()
    
    # 3. Remove its original staged file
    staged_file_path = os.path.join(staging_dir, job_id)
    if os.path.exists(staged_file_path):
        os.remove(staged_file_path)
        
    # 4. Submit identical file again
    res2 = client.post(
        "/api/v1/analysis-jobs/file",
        files={"file": ("test.json", BytesIO(test_content), "application/json")}
    )
    data2 = res2.json()
    
    # Assertions
    assert data2["reused"] is True
    assert data2["job_id"] == job_id
    assert data2["status"] == "queued"
    
    # 5. Assert staged file exists under existing job_id
    assert os.path.exists(staged_file_path)
    
    # Refresh job to check error code is cleared
    db_session.expire_all()
    job = db_session.query(IngestionJob).get(job_id)
    assert job.error_code is None
    
    # 6. Run the worker
    while worker.run_once():
        pass
        
    # 7. Assert status=completed and staged file removed
    db_session.expire_all()
    job = db_session.query(IngestionJob).get(job_id)
    assert job.status == "completed"
    assert not os.path.exists(staged_file_path)
