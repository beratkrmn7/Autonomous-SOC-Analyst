import pytest
import tempfile
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from fastapi.testclient import TestClient
from server import app
from agent.persistence.unit_of_work import UnitOfWork
from agent.persistence.orm_models import Base, IngestionJob
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def _reset_test_rate_limiter() -> None:
    """Keep the legacy global-app tests isolated from process-local counters."""
    limiter = app.state.rate_limit_manager.limiter
    windows = getattr(limiter, "_windows", None)
    if isinstance(windows, dict):
        windows.clear()


# Create a file-backed DB for all idempotency tests to correctly simulate cross-thread blocking and parallel writes
# We create a new file-backed SQLite database for each test session to avoid WinError 32 issues
@pytest.fixture
def temp_db():
    _reset_test_rate_limiter()
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    
    def override_get_uow():
        uow = UnitOfWork(session_factory=TestingSessionLocal)
        yield uow
        
    app.dependency_overrides[__import__('agent.api.deps', fromlist=['get_uow']).get_uow] = override_get_uow
    
    yield path, TestingSessionLocal
    
    app.dependency_overrides.clear()
    engine.dispose()
    os.remove(path)

@pytest.fixture
def api_client(temp_db):
    yield TestClient(app, base_url="http://localhost")

def create_temp_log(content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path

def test_idempotency_exact_duplicate(api_client, temp_db):
    path_db, SessionLocal = temp_db
    log_content = '{"event_id": "1", "timestamp": "2023-10-10T10:00:00Z", "suspicious": true}\\n'
    path = create_temp_log(log_content)
    
    try:
        from agent.application.analysis_service import IngestionPipeline, DetectionEngine
        import agent.graph
        from agent.persistence.orm_models import CanonicalEvent, DetectionSignal, Incident, TriageRun, EvidenceItem, Report
        from unittest.mock import patch
        
        orig_ingest = IngestionPipeline.ingest_file
        orig_detect = DetectionEngine.analyze
        orig_triage = agent.graph.app.invoke
        
        with patch.object(IngestionPipeline, 'ingest_file', autospec=True, side_effect=orig_ingest) as mock_ingest, \
             patch.object(DetectionEngine, 'analyze', autospec=True, side_effect=orig_detect) as mock_detect, \
             patch.object(agent.graph.app, 'invoke', autospec=True, side_effect=orig_triage) as mock_triage:
             
            with open(path, "rb") as f:
                res1 = api_client.post("/analyze/file", files={"file": f})
            assert res1.status_code == 200, res1.text
            assert res1.json().get("reused") is False
            
            # Save DB counts
            uow = UnitOfWork(session_factory=SessionLocal)
            with uow:
                assert uow.session is not None
                assert uow.session.query(IngestionJob).count() == 1
                events_count = uow.session.query(CanonicalEvent).count()
                signals_count = uow.session.query(DetectionSignal).count()
                incidents_count = uow.session.query(Incident).count()
                triage_count = uow.session.query(TriageRun).count()
                evidence_count = uow.session.query(EvidenceItem).count()
                reports_count = uow.session.query(Report).count()
                
            ingest_calls_first = mock_ingest.call_count
            detect_calls_first = mock_detect.call_count
            triage_calls_first = mock_triage.call_count

            # Second request
            with open(path, "rb") as f:
                res2 = api_client.post("/analyze/file", files={"file": f})
            assert res2.status_code == 200
            assert res2.json().get("reused") is True
            
            # Assert counts didn't change
            assert mock_ingest.call_count == ingest_calls_first
            assert mock_detect.call_count == detect_calls_first
            assert mock_triage.call_count == triage_calls_first
            
            with uow:
                assert uow.session.query(IngestionJob).count() == 1
                assert uow.session.query(CanonicalEvent).count() == events_count
                assert uow.session.query(DetectionSignal).count() == signals_count
                assert uow.session.query(Incident).count() == incidents_count
                assert uow.session.query(TriageRun).count() == triage_count
                assert uow.session.query(EvidenceItem).count() == evidence_count
                assert uow.session.query(Report).count() == reports_count
    finally:
        os.remove(path)

def test_idempotency_file_mutated(api_client, temp_db):
    path_db, SessionLocal = temp_db
    log_content1 = '{"event_id": "1", "timestamp": "2023-10-10T10:00:00Z"}\n'
    log_content2 = '{"event_id": "2", "timestamp": "2023-10-10T10:00:00Z"}\n'
    
    path1 = create_temp_log(log_content1)
    path2 = create_temp_log(log_content2)
    
    try:
        with open(path1, "rb") as f:
            res1 = api_client.post("/analyze/file", files={"file": f})
        assert res1.status_code == 200
        
        with open(path2, "rb") as f:
            res2 = api_client.post("/analyze/file", files={"file": f})
        assert res2.status_code == 200
        assert res2.json().get("reused") is False
        
        uow = UnitOfWork(session_factory=SessionLocal)
        with uow:
            assert uow.session is not None
            assert uow.session.query(IngestionJob).count() == 2
    finally:
        os.remove(path1)
        os.remove(path2)

def test_idempotency_pipeline_version(api_client, temp_db):
    path_db, SessionLocal = temp_db
    log_content = '{"event_id": "1", "timestamp": "2023-10-10T10:00:00Z"}\n'
    path = create_temp_log(log_content)
    
    # Seed a completed result using the pre-hardening pipeline version, then
    # prove the 1.1.0 pipeline creates once and reuses only its own result.
    from agent.config import Settings, get_settings

    try:
        app.dependency_overrides[get_settings] = lambda: Settings(
            pipeline_version="1.0.0"
        )
        with open(path, "rb") as f:
            old_result = api_client.post("/analyze/file", files={"file": f})
        assert old_result.status_code == 200
        assert old_result.json().get("reused") is False

        app.dependency_overrides[get_settings] = lambda: Settings(
            pipeline_version="1.1.0"
        )
        try:
            with open(path, "rb") as f:
                first_new = api_client.post("/analyze/file", files={"file": f})
            assert first_new.status_code == 200
            assert first_new.json().get("reused") is False

            with open(path, "rb") as f:
                repeated_new = api_client.post("/analyze/file", files={"file": f})
            assert repeated_new.status_code == 200
            assert repeated_new.json().get("reused") is True

            uow = UnitOfWork(session_factory=SessionLocal)
            with uow:
                assert uow.session is not None
                assert uow.session.query(IngestionJob).count() == 2
                assert {
                    str(job.pipeline_version)
                    for job in uow.session.query(IngestionJob).all()
                } == {"1.0.0", "1.1.0"}
        finally:
            app.dependency_overrides.pop(get_settings, None)
    finally:
        os.remove(path)

def test_idempotency_cross_mode(api_client, temp_db):
    # Test POST /detect/file and then POST /analyze/file
    path_db, SessionLocal = temp_db
    log_content = '{"event_id": "1", "timestamp": "2023-10-10T10:00:00Z"}\n'
    path = create_temp_log(log_content)
    
    try:
        with open(path, "rb") as f:
            res1 = api_client.post("/detect/file", files={"file": f})
        assert res1.status_code == 200
        assert res1.json().get("reused") is False
        
        with open(path, "rb") as f:
            res2 = api_client.post("/analyze/file", files={"file": f})
        assert res2.status_code == 200
        assert res2.json().get("reused") is False  # Because different mode
        
        uow = UnitOfWork(session_factory=SessionLocal)
        with uow:
            assert uow.session is not None
            assert uow.session.query(IngestionJob).count() == 2
    finally:
        os.remove(path)

def test_idempotency_parallel_submission(api_client, temp_db):
    # Send 5 parallel requests for the exact same file
    path_db, SessionLocal = temp_db
    log_content = '{"event_id": "1", "timestamp": "2023-10-10T10:00:00Z", "suspicious": true}\\n'
    path = create_temp_log(log_content)
    
    barrier = threading.Barrier(5)
    
    def parallel_worker():
        # Each worker must get its own session context to correctly simulate parallel API calls
        from server import app
        from fastapi.testclient import TestClient
        client = TestClient(app, base_url="http://localhost")
        barrier.wait()
        with open(path, "rb") as f:
            return client.post("/analyze/file", files={"file": f})
            
    try:
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(parallel_worker) for _ in range(5)]
            responses = [f.result() for f in futures]
            
        status_codes = [r.status_code for r in responses]
        reused_flags = [r.json().get("reused") for r in responses if r.status_code == 200]
        duplicate_errors = [r.status_code for r in responses if r.status_code == 409]
        
        # Exact one 200 with reused=False (meaning a new pipeline execution)
        assert reused_flags.count(False) == 1
        
        # No unexpected 500s or DB locking errors leaking
        for code in status_codes:
            assert code in (200, 409)
            
        # The remaining 4 requests should be either 409 or reused=True (if one somehow completed fast enough)
        assert duplicate_errors.count(409) + reused_flags.count(True) == 4
        
        uow = UnitOfWork(session_factory=SessionLocal)
        from agent.persistence.orm_models import CanonicalEvent, DetectionSignal, Incident, TriageRun, EvidenceItem, Report
        with uow:
            assert uow.session is not None
            # Only one job should be stored
            assert uow.session.query(IngestionJob).count() == 1
            # Child tables must have no duplicates for this simple log
            assert uow.session.query(CanonicalEvent).count() <= 1
            assert uow.session.query(DetectionSignal).count() <= 1
            assert uow.session.query(Incident).count() <= 1
            assert uow.session.query(TriageRun).count() <= 1
            assert uow.session.query(EvidenceItem).count() <= 1
            assert uow.session.query(Report).count() <= 1
    finally:
        import os
        os.remove(path)

def test_idempotency_rollback_isolation(api_client, temp_db):
    path_db, SessionLocal = temp_db
    log_content = '{"event_id": "1", "timestamp": "2023-10-10T10:00:00Z", "suspicious": true}\\n'
    path = create_temp_log(log_content)
    
    try:
        from unittest.mock import patch
        # Mock something inside the persistence flow so that it fails partially through
        with patch('agent.persistence.orm_models.IngestionJob.__init__', side_effect=Exception("DB failure simulation")):
            with open(path, "rb") as f:
                res_fail = api_client.post("/analyze/file", files={"file": f})
            assert res_fail.status_code == 500
            
        from agent.persistence.unit_of_work import UnitOfWork
        from agent.persistence.orm_models import IngestionJob, CanonicalEvent
        uow = UnitOfWork(session_factory=SessionLocal)
        with uow:
            assert uow.session is not None
            # The partial write should be rolled back completely
            assert uow.session.query(IngestionJob).count() == 0
            assert uow.session.query(CanonicalEvent).count() == 0
            
        # Try again successfully
        with open(path, "rb") as f:
            res2 = api_client.post("/analyze/file", files={"file": f})
            
        assert res2.status_code == 200
        assert res2.json().get("reused") is False # It failed previously, so we run analysis again
        
        with uow:
            assert uow.session is not None
            assert uow.session.query(IngestionJob).count() == 1
    finally:
        import os
        os.remove(path)

def setup_app_db(db_path):
    _reset_test_rate_limiter()
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from agent.persistence.orm_models import Base
    from agent.persistence.unit_of_work import UnitOfWork
    from server import app
    from fastapi.testclient import TestClient

    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    
    def override_get_uow():
        uow = UnitOfWork(session_factory=SessionLocal)
        yield uow
        
    app.dependency_overrides[__import__('agent.api.deps', fromlist=['get_uow']).get_uow] = override_get_uow
    return engine, SessionLocal, TestClient(app, base_url="http://localhost")

def test_idempotency_sqlite_reload_and_equality():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    
    # We need a log that definitely creates signals/incidents and evidence
    # A standard suspicious log:
    log_content = '{"event_id": "reload_1", "timestamp": "2023-10-10T10:00:00Z", "suspicious": true, "user": "admin"}\n'
    log_path = create_temp_log(log_content)
    
    try:
        from server import app
        engine1, SessionLocal1, client1 = setup_app_db(db_path)
        
        # 1. First request
        with open(log_path, "rb") as f:
            res1 = client1.post("/analyze/file", files={"file": f})
            
        assert res1.status_code == 200
        data1 = res1.json()
        assert data1.get("reused") is False
        
        app.dependency_overrides.clear()
        engine1.dispose()
        
        # 2. Complete reload of app context
        engine2, SessionLocal2, client2 = setup_app_db(db_path)
        
        with open(log_path, "rb") as f:
            res2 = client2.post("/analyze/file", files={"file": f})
            
        assert res2.status_code == 200
        data2 = res2.json()
        assert data2.get("reused") is True
        
        # 3. Assert deep equality
        data1.pop("reused", None)
        data2.pop("reused", None)
        
        # UUIDs in the database should remain identical on reload, so equality should be perfect
        assert data1 == data2, "Reused response must perfectly match original response!"
        
        app.dependency_overrides.clear()
        engine2.dispose()
        
    finally:
        os.remove(log_path)
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except Exception:
                pass
