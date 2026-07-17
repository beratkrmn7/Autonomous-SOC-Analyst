import pytest
from datetime import datetime, timezone
import json

from agent.application.analysis_service import AnalysisService
from agent.application.models import AnalysisResult
from agent.ingestion.models import CanonicalLogEvent, IngestionResult, IngestionMetrics, InputFormat
from agent.detection.models import DetectionResult, DetectionMetrics
from agent.persistence.unit_of_work import UnitOfWork
from agent.persistence.orm_models import SearchIndexOutbox
from sqlalchemy import create_engine
from agent.persistence.database import Base

@pytest.fixture
def uow():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    from sqlalchemy.orm import sessionmaker
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return UnitOfWork(session_factory=SessionLocal)

def test_analysis_persistence_enqueues_outbox(uow, monkeypatch):
    from agent.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "opensearch_enabled", True)
    monkeypatch.setattr(settings, "opensearch_schema_version", "v1")
    
    # Mock settings globally for the test
    import agent.config
    monkeypatch.setattr(agent.config, "get_settings", lambda: settings)

    svc = AnalysisService(uow=uow)
    
    event = CanonicalLogEvent(
        event_id="test_event_1",
        timestamp=datetime.now(timezone.utc),
        safe_message_excerpt="test",
        parser_name="test_parser",
        parse_status="success"
    )
    
    ingest_result = IngestionResult(
        source_name="test_src",
        input_format=InputFormat.JSONL,
        events=[event],
        metrics=IngestionMetrics(total_records=1)
    )
    
    det_result = DetectionResult(
        signals=[],
        incidents=[],
        suppressed_signals=[],
        uncorrelated_event_ids=[],
        warnings=[],
        metrics=DetectionMetrics(signal_count=0, duration_ms=1.0)
    )
    
    result = AnalysisResult(
        source_name="test_src",
        ingestion_result=ingest_result,
        detection_result=det_result,
        event_map={event.event_id: event},
        signal_map={},
        incidents=[],
        job_id="test_job_1"
    )
    
    # Pre-create the job to satisfy foreign keys
    with uow:
        from agent.persistence.orm_models import IngestionJob
        job = IngestionJob(id="test_job_1", source_name="test_src", status="processing")
        uow.session.add(job)
        uow.commit()

    svc._persist_analysis(result, run_triage=False)
    
    with uow:
        outbox_events = uow.session.query(SearchIndexOutbox).all()
        assert len(outbox_events) == 1
        assert outbox_events[0].entity_type == "canonical_event"
        assert outbox_events[0].entity_id == "test_event_1"
        assert outbox_events[0].operation == "upsert"
        assert outbox_events[0].status == "pending"
        
        # Verify job_ids is serialized in payload
        payload = json.loads(outbox_events[0].payload)
        assert "test_job_1" in payload["job_ids"]

def test_analysis_persistence_skips_outbox_when_disabled(uow, monkeypatch):
    from agent.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "opensearch_enabled", False)
    
    import agent.config
    monkeypatch.setattr(agent.config, "get_settings", lambda: settings)

    svc = AnalysisService(uow=uow)
    
    event = CanonicalLogEvent(
        event_id="test_event_2",
        timestamp=datetime.now(timezone.utc),
        safe_message_excerpt="test",
        parser_name="test_parser",
        parse_status="success"
    )
    
    ingest_result = IngestionResult(
        source_name="test_src",
        input_format=InputFormat.JSONL,
        events=[event],
        metrics=IngestionMetrics(total_records=1)
    )
    
    det_result = DetectionResult(
        signals=[],
        incidents=[],
        suppressed_signals=[],
        uncorrelated_event_ids=[],
        warnings=[],
        metrics=DetectionMetrics(signal_count=0, duration_ms=1.0)
    )
    
    result = AnalysisResult(
        source_name="test_src",
        ingestion_result=ingest_result,
        detection_result=det_result,
        event_map={event.event_id: event},
        signal_map={},
        incidents=[],
        job_id="test_job_2"
    )
    
    with uow:
        from agent.persistence.orm_models import IngestionJob
        job = IngestionJob(id="test_job_2", source_name="test_src", status="processing")
        uow.session.add(job)
        uow.commit()

    svc._persist_analysis(result, run_triage=False)
    
    with uow:
        outbox_events = uow.session.query(SearchIndexOutbox).all()
        assert len(outbox_events) == 0
