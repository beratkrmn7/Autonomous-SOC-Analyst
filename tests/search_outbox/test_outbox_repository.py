import pytest
from datetime import datetime, timezone

from agent.opensearch.documents import CanonicalEventSearchDocument
from agent.persistence.outbox_repository import SearchIndexOutboxRepository, OutboxError
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from agent.persistence.database import Base

@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    from sqlalchemy.orm import sessionmaker
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = SessionLocal()
    yield session
    session.close()

def test_enqueue_upsert_success(session: Session):
    repo = SearchIndexOutboxRepository(session)
    doc = CanonicalEventSearchDocument(
        schema_version="v1",
        entity_id="test_event_1",
        document_version=1,
        indexed_at=datetime.now(timezone.utc),
        source_updated_at=datetime.now(timezone.utc),
        event_id="test_event_1",
        timestamp=datetime.now(timezone.utc),
    )
    
    outbox = repo.enqueue_upsert(doc)
    assert outbox is not None
    assert outbox.entity_type == "canonical_event"
    assert outbox.entity_id == "test_event_1"
    assert outbox.operation == "upsert"
    assert outbox.status == "pending"
    assert outbox.payload_size_bytes > 0
    assert outbox.payload_sha256 is not None
    assert outbox.deduplication_key is not None
    
    # check idempotency
    outbox2 = repo.enqueue_upsert(doc)
    assert outbox2.outbox_id == outbox.outbox_id

def test_enqueue_upsert_fail_closed_on_different_payload(session: Session):
    repo = SearchIndexOutboxRepository(session)
    doc1 = CanonicalEventSearchDocument(
        schema_version="v1",
        entity_id="test_event_2",
        document_version=1,
        indexed_at=datetime.now(timezone.utc),
        source_updated_at=datetime.now(timezone.utc),
        event_id="test_event_2",
        timestamp=datetime.now(timezone.utc),
        source_name="src1"
    )
    repo.enqueue_upsert(doc1)
    
    doc2 = CanonicalEventSearchDocument(
        schema_version="v1",
        entity_id="test_event_2",
        document_version=1,
        indexed_at=datetime.now(timezone.utc),
        source_updated_at=datetime.now(timezone.utc),
        event_id="test_event_2",
        timestamp=datetime.now(timezone.utc),
        source_name="src2"
    )
    with pytest.raises(OutboxError) as exc_info:
        repo.enqueue_upsert(doc2)
    assert exc_info.value.code == "opensearch_outbox_deduplication_conflict"

def test_enqueue_upsert_payload_too_large(session: Session, monkeypatch):
    repo = SearchIndexOutboxRepository(session)
    monkeypatch.setattr(repo.settings, "opensearch_outbox_max_payload_bytes", 10)
    
    doc = CanonicalEventSearchDocument(
        schema_version="v1",
        entity_id="test_event_3",
        document_version=1,
        indexed_at=datetime.now(timezone.utc),
        source_updated_at=datetime.now(timezone.utc),
        event_id="test_event_3",
        timestamp=datetime.now(timezone.utc),
    )
    with pytest.raises(OutboxError) as exc_info:
        repo.enqueue_upsert(doc)
    assert exc_info.value.code == "opensearch_outbox_payload_too_large"

def test_claim_batch(session: Session):
    repo = SearchIndexOutboxRepository(session)
    doc = CanonicalEventSearchDocument(
        schema_version="v1",
        entity_id="test_event_4",
        document_version=1,
        indexed_at=datetime.now(timezone.utc),
        source_updated_at=datetime.now(timezone.utc),
        event_id="test_event_4",
        timestamp=datetime.now(timezone.utc),
    )
    repo.enqueue_upsert(doc)
    
    claimed = repo.claim_batch("worker-1", limit=10)
    assert len(claimed) == 1
    assert claimed[0].lease_owner == "worker-1"
    assert claimed[0].status == "processing"
    
    # Second claim should be empty
    claimed2 = repo.claim_batch("worker-2", limit=10)
    assert len(claimed2) == 0
