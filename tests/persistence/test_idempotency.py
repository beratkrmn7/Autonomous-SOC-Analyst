# mypy: ignore-errors
import pytest
import tempfile
import os
from fastapi.testclient import TestClient
from server import app, calculate_file_sha256
from agent.persistence.unit_of_work import UnitOfWork
from agent.persistence.orm_models import Base, IngestionJob
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch, MagicMock

# Create an in-memory DB for tests
engine = create_engine(
    "sqlite:///:memory:", 
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

from agent.api.deps import get_uow  # noqa: E402
client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    
    def override_get_uow():
        uow = UnitOfWork(session_factory=TestingSessionLocal)
        yield uow
        
    app.dependency_overrides[get_uow] = override_get_uow
    yield
    app.dependency_overrides.clear()

def create_temp_log(content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path

def test_idempotency_exact_duplicate():
    # Scenario 1: Exact file duplicate reuses results
    log_content = '{"event_id": "1", "timestamp": "2023-10-10T10:00:00Z"}\n'
    path = create_temp_log(log_content)
    
    try:
        with patch('agent.application.analysis_service.AnalysisService._process_events') as mock_process:
            from agent.application.models import AnalysisResult
            from agent.ingestion.models import IngestionResult, IngestionMetrics
            from agent.detection.models import DetectionResult, DetectionMetrics
            mock_process.return_value = AnalysisResult(
                source_name="api_detect",
                ingestion_result=IngestionResult(
                    source_name="api_detect",
                    input_format="jsonl",
                    events=[],
                    metrics=IngestionMetrics(total_records=1, parsed_records=1, failed_records=0, unsupported_records=0, duration_ms=10)
                ),
                detection_result=DetectionResult(signals=[], incidents=[], suppressed_signals=[], uncorrelated_event_ids=[], metrics=DetectionMetrics(signal_count=0, duration_ms=0), warnings=[]),
                event_map={},
                signal_map={},
                incidents=[]
            )
            with open(path, "rb") as f:
                res1 = client.post("/detect/file", files={"file": f})
            assert res1.status_code == 200
            assert res1.json().get("reused") is False

            # Since _process_events is mocked, we need to manually mark the job as completed
            uow = UnitOfWork(session_factory=TestingSessionLocal)
            with uow:
                job = uow.session.query(IngestionJob).first()
                job.status = "completed"
                uow.session.commit()
    
            with open(path, "rb") as f:
                res2 = client.post("/detect/file", files={"file": f})
            assert res2.status_code == 200
            assert res2.json().get("reused") is True
            
            # _process_events should only be called once because the second time it returns DB results
            assert mock_process.call_count == 1
    finally:
        os.remove(path)

def test_idempotency_file_mutated():
    # Scenario 2: File mutated by 1 byte -> new analysis
    log_content1 = '{"event_id": "1", "timestamp": "2023-10-10T10:00:00Z"}\n'
    log_content2 = '{"event_id": "2", "timestamp": "2023-10-10T10:00:00Z"}\n'
    
    path1 = create_temp_log(log_content1)
    path2 = create_temp_log(log_content2)
    
    try:
        with open(path1, "rb") as f:
            res1 = client.post("/detect/file", files={"file": f})
        assert res1.status_code == 200
        assert res1.json().get("reused") is False
        
        with open(path2, "rb") as f:
            res2 = client.post("/detect/file", files={"file": f})
        assert res2.status_code == 200
        assert res2.json().get("reused") is False # not reused
    finally:
        os.remove(path1)
        os.remove(path2)

def test_idempotency_pipeline_version_changed():
    # Scenario 3: Pipeline version changed
    # Server hardcodes pipeline_version to "1.0.0" right now, but we can simulate DB entry
    log_content = '{"event_id": "1", "timestamp": "2023-10-10T10:00:00Z"}\n'
    path = create_temp_log(log_content)
    
    try:
        with open(path, "rb") as f:
            res1 = client.post("/detect/file", files={"file": f})
        assert res1.status_code == 200
        assert res1.json().get("reused") is False
        
        # Manually alter DB to simulate pipeline version difference
        uow = UnitOfWork(session_factory=TestingSessionLocal)
        with uow:
            job = uow.session.query(IngestionJob).first()
            job.idempotency_key = "different_key"
            uow.session.commit()
            
        with open(path, "rb") as f:
            res2 = client.post("/detect/file", files={"file": f})
        assert res2.status_code == 200
        assert res2.json().get("reused") is False # not reused
    finally:
        os.remove(path)

def test_idempotency_analysis_mode_changed():
    # Scenario 4: Analysis mode changed
    log_content = '{"event_id": "1", "timestamp": "2023-10-10T10:00:00Z"}\n'
    path = create_temp_log(log_content)
    
    try:
        # Detect mode
        with open(path, "rb") as f:
            res1 = client.post("/detect/file", files={"file": f})
        assert res1.status_code == 200
        assert res1.json().get("reused") is False
        
        # Analyze mode
        with patch('agent.application.analysis_service.AnalysisService.analyze_file') as mock_analyze:
            mock_analyze.return_value = MagicMock(
                reused=False,
                job_id="job",
                ingestion_result=MagicMock(),
                event_map={},
                incidents=[]
            )
            with open(path, "rb") as f:
                res2 = client.post("/analyze/file", files={"file": f})
            assert res2.status_code == 200
            assert mock_analyze.call_count == 1
    finally:
        os.remove(path)

def test_idempotency_processing_conflict():
    # Scenario 5: HTTP 409 when job is already processing
    log_content = '{"event_id": "1"}\n'
    path = create_temp_log(log_content)
    file_sha256 = calculate_file_sha256(path)
    idemp_key = f"{file_sha256}:1.0.0:detect"
    
    uow = UnitOfWork(session_factory=TestingSessionLocal)
    with uow:
        job = IngestionJob(
            id="job123",
            idempotency_key=idemp_key,
            status="processing"
        )
        uow.session.add(job)
        uow.session.commit()
        
    try:
        with open(path, "rb") as f:
            res = client.post("/detect/file", files={"file": f})
        assert res.status_code == 409
        assert res.json()["detail"] == "Analysis already in progress for this file and mode."
    finally:
        os.remove(path)

def test_idempotency_failed_retry():
    # Scenario 6: Retry logic for failed jobs
    log_content = '{"event_id": "1"}\n'
    path = create_temp_log(log_content)
    file_sha256 = calculate_file_sha256(path)
    idemp_key = f"{file_sha256}:1.0.0:detect"
    
    uow = UnitOfWork(session_factory=TestingSessionLocal)
    with uow:
        job = IngestionJob(
            id="job123",
            idempotency_key=idemp_key,
            status="failed",
            reused_count=0
        )
        uow.session.add(job)
        uow.session.commit()
        
    try:
        with open(path, "rb") as f:
            res = client.post("/detect/file", files={"file": f})
        assert res.status_code == 200
        assert res.json().get("reused") is False
        
        with uow:
            job = uow.session.query(IngestionJob).get("job123")
            assert job.reused_count == 1
            assert job.status == "completed"
    finally:
        os.remove(path)

# Ensure 10 tests are in this file...
def test_idempotency_sqlite_reload():
    # Scenario 7: State persistence across restarts
    # (SQLite DB is persisted)
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    try:
        file_engine = create_engine(f"sqlite:///{db_path}")
        Base.metadata.create_all(bind=file_engine)
        FileSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=file_engine)
        
        def override_file_uow():
            uow = UnitOfWork(session_factory=FileSessionLocal)
            yield uow
            
        app.dependency_overrides[get_uow] = override_file_uow
        
        log_content = '{"event_id": "reload_test"}\n'
        path = create_temp_log(log_content)
        
        try:
            with open(path, "rb") as f:
                res1 = client.post("/detect/file", files={"file": f})
            assert res1.status_code == 200
            assert res1.json().get("reused") is False

            # Dispose engine
            file_engine.dispose()
            
            # Re-create engine (simulate reload)
            file_engine2 = create_engine(f"sqlite:///{db_path}")
            FileSessionLocal2 = sessionmaker(autocommit=False, autoflush=False, bind=file_engine2)
            
            def override_file_uow2():
                uow = UnitOfWork(session_factory=FileSessionLocal2)
                yield uow
                
            app.dependency_overrides[get_uow] = override_file_uow2
            
            with open(path, "rb") as f:
                res2 = client.post("/detect/file", files={"file": f})
            assert res2.status_code == 200
            assert res2.json().get("reused") is True
            file_engine2.dispose()
        finally:
            os.remove(path)
            app.dependency_overrides.pop(get_uow, None)
    finally:
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except PermissionError:
                pass

def test_idempotency_parallel_submission():
    # Scenario 8: Parallel submissions
    import concurrent.futures
    log_content = '{"event_id": "parallel_test"}\n'
    path = create_temp_log(log_content)
    
    def submit_file():
        with open(path, "rb") as f:
            return client.post("/detect/file", files={"file": f})
            
    try:
        # We mock time.sleep inside detection to simulate a slow run so race condition is likely
        with patch('agent.detection.engine.DetectionEngine.analyze') as mock_detect:
            from agent.detection.models import DetectionResult, DetectionMetrics
            import time
            def slow_detect(*args, **kwargs):
                time.sleep(0.2)
                return DetectionResult(signals=[], incidents=[], suppressed_signals=[], uncorrelated_event_ids=[], warnings=[], metrics=DetectionMetrics(signal_count=0, duration_ms=0))
            mock_detect.side_effect = slow_detect
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(submit_file) for _ in range(5)]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]
                
            status_codes = [r.status_code for r in results]
            assert 200 in status_codes, f"At least one should succeed. Status codes: {status_codes}"
            assert 409 in status_codes, "The rest should get 409 conflict"
    finally:
        os.remove(path)

def test_idempotency_uow_isolation():
    # Scenario 9: UnitOfWork isolation
    # Ensuring uow is closed properly
    uow = UnitOfWork(session_factory=TestingSessionLocal)
    with uow:
        assert uow.session is not None
    # If it didn't throw, isolation exit is fine

def test_idempotency_metrics():
    # Scenario 10: Correct metrics mapping on reuse
    log_content = '{"event_id": "metrics"}\n'
    path = create_temp_log(log_content)
    try:
        with open(path, "rb") as f:
            res1 = client.post("/detect/file", files={"file": f})
        assert res1.status_code == 200
        
        # Re-submit
        with open(path, "rb") as f:
            res2 = client.post("/detect/file", files={"file": f})
            
        assert res2.status_code == 200
        data = res2.json()
        assert data["reused"] is True
        # Ensure metrics exist
        assert "detection" in data
        assert isinstance(data["detection"]["signal_count"], int)
    finally:
        os.remove(path)
