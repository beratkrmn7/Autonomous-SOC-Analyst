import pytest
import time
import os
import io
from agent.config import get_settings
from agent.persistence.database import create_engine_factory, create_session_factory
from agent.persistence.unit_of_work import UnitOfWork
from agent.application.staging import LocalFileStagingStore
from agent.application.background_service import BackgroundAnalysisService
from agent.persistence.orm_models import Base, IngestionJob
from agent.queue.dispatchers import CeleryAnalysisJobDispatcher
from agent.queue.celery_app import celery_app

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
        os.remove(db_path)
    except PermissionError:
        pass

@pytest.fixture
def staging_store(tmp_path):
    return LocalFileStagingStore(staging_dir=str(tmp_path))

@pytest.fixture
def background_service(isolated_db, staging_store):
    uow = UnitOfWork(session_factory=isolated_db)
    dispatcher = CeleryAnalysisJobDispatcher()
    return BackgroundAnalysisService(uow=uow, staging_store=staging_store, dispatcher=dispatcher)

@pytest.mark.integration
def test_celery_redis_integration_pipeline(background_service, isolated_db, staging_store, monkeypatch):
    import redis
    from celery.contrib.testing.worker import start_worker

    # Ensure celery worker uses our isolated DB
    from agent.workers import analysis_worker
    monkeypatch.setattr(analysis_worker, "default_session_factory", isolated_db)
    
    settings = get_settings()
    settings.llm_enabled = False
    settings.staging_dir = str(staging_store.staging_dir)

    try:
        r = redis.Redis.from_url(settings.celery_broker_url)
        r.ping()
    except redis.ConnectionError:
        pytest.skip("Redis is not available")

    # Start an isolated Celery worker
    with start_worker(celery_app, perform_ping_check=False, pool="solo"):
        # Submit a deterministic offline fixture
        stream = io.BytesIO(b"Test evidence data")
        job_id, reused, status = background_service.submit_file(
            stream=stream,
            original_filename="test.txt",
            source_name="test",
            pipeline_version="1.0.0",
            analysis_mode="analyze"
        )
        assert status == "queued"
        
        # Poll the database with a bounded timeout
        timeout = 10
        start_time = time.time()
        job = None
        
        db = isolated_db()
        try:
            while time.time() - start_time < timeout:
                db.expire_all()
                job = db.query(IngestionJob).get(job_id)
                if job and job.status in ("completed", "failed"):
                    break
                time.sleep(0.5)
            
            assert job is not None
            assert job.status in ("completed", "failed")
            assert job.attempt_count == 1
            
            # Assert staged file is removed
            assert not os.path.exists(staging_store.get_file_path(job_id))
        finally:
            db.close()
