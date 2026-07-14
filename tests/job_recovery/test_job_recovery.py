import pytest
import datetime
import uuid
import os
from agent.persistence.orm_models import IngestionJob
from agent.workers.analysis_worker import AnalysisWorker
from agent.config import get_settings
from agent.errors import RetryableJobError, PermanentJobError
from unittest.mock import patch
from agent.persistence.database import Base, create_engine_factory, create_session_factory

@pytest.fixture
def isolated_db():
    import tempfile
    settings = get_settings()
    
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name
        
    settings.database_url = f"sqlite:///{db_path}"
    engine = create_engine_factory(settings)
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)
    
    yield session_factory
    
    engine.dispose()
    try:
        os.unlink(db_path)
    except OSError:
        pass

@pytest.fixture
def mock_staging(tmp_path):
    d = tmp_path / "staging"
    d.mkdir()
    yield str(d)

@pytest.fixture
def isolated_worker(isolated_db, mock_staging):
    return AnalysisWorker(staging_dir=mock_staging, session_factory=isolated_db)

def create_job(db, status="queued", attempt_count=0, next_retry_at=None, lease_expires_at=None):
    job_id = str(uuid.uuid4())
    job = IngestionJob(
        id=job_id,
        status=status,
        attempt_count=attempt_count,
        next_retry_at=next_retry_at,
        lease_expires_at=lease_expires_at,
        source_name="test"
    )
    db.add(job)
    db.commit()
    return job_id

def stage_file(staging_dir, job_id, content=b"data"):
    path = os.path.join(staging_dir, job_id)
    with open(path, "wb") as f:
        f.write(content)
    return path

def test_temporary_failure_schedules_retry_and_keeps_staging(isolated_worker, isolated_db, mock_staging):
    db = isolated_db()
    job_id = create_job(db)
    stage_file(mock_staging, job_id)
    
    with patch("agent.workers.analysis_worker.AnalysisService.analyze_file", side_effect=RetryableJobError("timeout")):
        status = isolated_worker.process_job(job_id)
        
    assert status == "retry"
    
    # Check DB
    db.expire_all()
    job = db.query(IngestionJob).get(job_id)
    assert job.status == "queued"
    assert job.error_code == "RetryableJobError"
    assert job.attempt_count == 1
    assert job.next_retry_at is not None
    assert job.worker_id is None
    assert job.lease_expires_at is None
    
    # Check staging file remains
    assert os.path.exists(os.path.join(mock_staging, job_id))

def test_retry_succeeds_on_second_attempt(isolated_worker, isolated_db, mock_staging):
    db = isolated_db()
    # Simulate a job that was already tried once and is now ready for retry
    job_id = create_job(db, attempt_count=1, next_retry_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1))
    stage_file(mock_staging, job_id)
    
    with patch("agent.workers.analysis_worker.AnalysisService.analyze_file") as mock_analyze:
        # Worker polls
        processed = isolated_worker.run_once()
        
    assert processed is True
    assert mock_analyze.call_count == 1
    
    # Check DB
    db.expire_all()
    job = db.query(IngestionJob).get(job_id)
    assert job.status == "completed"
    assert job.attempt_count == 2
    assert job.next_retry_at is None
    
    # Check staging file removed
    assert not os.path.exists(os.path.join(mock_staging, job_id))

def test_maximum_attempts_produces_terminal_failed(isolated_worker, isolated_db, mock_staging):
    db = isolated_db()
    settings = get_settings()
    # Set attempt count to one less than max, so this attempt will hit max
    job_id = create_job(db, attempt_count=settings.job_max_attempts - 1)
    stage_file(mock_staging, job_id)
    
    with patch("agent.workers.analysis_worker.AnalysisService.analyze_file", side_effect=RetryableJobError("timeout")):
        status = isolated_worker.process_job(job_id)
        
    assert status == "failed"
    
    # Check DB
    db.expire_all()
    job = db.query(IngestionJob).get(job_id)
    assert job.status == "failed"
    assert job.error_code == "max_attempts_reached"
    assert job.attempt_count == settings.job_max_attempts
    
    # Check staging file removed
    assert not os.path.exists(os.path.join(mock_staging, job_id))

def test_permanent_failure_produces_terminal_failed(isolated_worker, isolated_db, mock_staging):
    db = isolated_db()
    job_id = create_job(db, attempt_count=0)
    stage_file(mock_staging, job_id)
    
    with patch("agent.workers.analysis_worker.AnalysisService.analyze_file", side_effect=PermanentJobError("invalid_input")):
        status = isolated_worker.process_job(job_id)
        
    assert status == "failed"
    
    # Check DB
    db.expire_all()
    job = db.query(IngestionJob).get(job_id)
    assert job.status == "failed"
    assert job.error_code == "invalid_input"
    assert job.attempt_count == 1
    
    # Check staging file removed
    assert not os.path.exists(os.path.join(mock_staging, job_id))

def test_stale_processing_job_is_requeued(isolated_worker, isolated_db, mock_staging):
    db = isolated_db()
    # A job that is processing but its lease expired
    job_id = create_job(
        db, 
        status="processing", 
        attempt_count=1,
        lease_expires_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=10)
    )
    stage_file(mock_staging, job_id)
    
    count = isolated_worker.recover_stale_jobs()
    assert count == 1
    
    db.expire_all()
    job = db.query(IngestionJob).get(job_id)
    assert job.status == "queued"
    assert job.attempt_count == 1  # doesn't increment on recovery
    assert job.next_retry_at is not None
    assert job.lease_expires_at is None
    
    assert os.path.exists(os.path.join(mock_staging, job_id))

def test_stale_processing_job_at_max_attempts_becomes_failed(isolated_worker, isolated_db, mock_staging):
    db = isolated_db()
    settings = get_settings()
    job_id = create_job(
        db, 
        status="processing", 
        attempt_count=settings.job_max_attempts,
        lease_expires_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=10)
    )
    stage_file(mock_staging, job_id)
    
    count = isolated_worker.recover_stale_jobs()
    assert count == 1
    
    db.expire_all()
    job = db.query(IngestionJob).get(job_id)
    assert job.status == "failed"
    assert job.error_code == "processing_lease_expired"
    assert job.attempt_count == settings.job_max_attempts
    
    assert not os.path.exists(os.path.join(mock_staging, job_id))

def test_completed_job_is_not_processed_again(isolated_worker, isolated_db, mock_staging):
    db = isolated_db()
    job_id = create_job(db, status="completed")
    
    status = isolated_worker.process_job(job_id)
    assert status == "ignored"

def test_raw_exception_text_is_not_stored_or_returned(isolated_worker, isolated_db, mock_staging):
    db = isolated_db()
    job_id = create_job(db)
    stage_file(mock_staging, job_id)
    
    # A generic exception that we shouldn't leak
    secret_text = "SECRET_DATABASE_PASSWORD_FAILED"
    with patch("agent.workers.analysis_worker.AnalysisService.analyze_file", side_effect=Exception(secret_text)):
        status = isolated_worker.process_job(job_id)
        
    assert status == "failed"
    
    db.expire_all()
    job = db.query(IngestionJob).get(job_id)
    assert job.status == "failed"
    assert job.error_code == "worker_execution_failed" # generic code
    assert secret_text not in str(job.error_code)
