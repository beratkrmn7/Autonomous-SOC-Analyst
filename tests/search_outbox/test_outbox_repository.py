from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker

from agent.opensearch.documents import (
    CanonicalEventSearchDocument,
    calculate_payload_sha256,
    canonical_event_document,
    canonical_payload_bytes,
    validate_search_document,
)
from agent.persistence.database import Base
from agent.persistence.orm_models import CanonicalEvent, SearchIndexOutbox
from agent.persistence.outbox_repository import (
    OutboxError,
    SearchIndexOutboxRepository,
)


NOW = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    database_session = factory()
    yield database_session
    database_session.close()
    engine.dispose()


def _repo(session: Session, *, max_payload_bytes: int = 65_536):
    return SearchIndexOutboxRepository(
        session,
        max_payload_bytes=max_payload_bytes,
        enqueue_chunk_size=100,
        max_claim_batch_size=100,
    )


def _document(
    entity_id: str,
    *,
    source_name: str = "firewall",
    document_version: int = 1,
) -> CanonicalEventSearchDocument:
    return CanonicalEventSearchDocument(
        schema_version="v1",
        entity_id=entity_id,
        document_version=document_version,
        indexed_at=NOW,
        source_updated_at=NOW,
        event_id=entity_id,
        timestamp=NOW,
        source_name=source_name,
    )


def test_enqueue_stores_json_object_and_reuses_identical_payload(session: Session) -> None:
    repository = _repo(session)
    document = _document("event-1")

    first = repository.enqueue_upsert(document)
    second = repository.enqueue_upsert(document)

    assert first.outbox_id == second.outbox_id
    assert isinstance(first.payload, dict)
    validated = validate_search_document(first.payload)
    assert validated == document
    assert first.payload_sha256 == calculate_payload_sha256(first.payload)
    assert first.payload_size_bytes == len(canonical_payload_bytes(first.payload))
    assert repository.count_by_status("pending") == 1

    with pytest.raises(ValidationError):
        validate_search_document({**first.payload, "raw_log": "forbidden"})
    with pytest.raises(ValueError, match="Out of range float values"):
        canonical_payload_bytes({"confidence": float("nan")})


def test_source_derived_indexed_at_and_projection_version_are_stable() -> None:
    row = CanonicalEvent(event_id="event-stable", timestamp=NOW)
    first = canonical_event_document(
        row,
        schema_version="v1",
        document_version=3,
        job_ids=("job-2", "job-1"),
        incident_ids=("incident-1",),
    )
    second = canonical_event_document(
        row,
        schema_version="v1",
        document_version=3,
        job_ids=("job-1", "job-2"),
        incident_ids=("incident-1",),
    )

    assert first.indexed_at == NOW
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_same_key_with_different_payload_fails_closed(session: Session) -> None:
    repository = _repo(session)
    repository.enqueue_upsert(_document("event-conflict", source_name="first"))

    with pytest.raises(OutboxError) as caught:
        repository.enqueue_upsert(_document("event-conflict", source_name="second"))

    assert caught.value.code == "opensearch_outbox_deduplication_conflict"


def test_payload_limit_error_is_code_only_and_does_not_rollback_session(
    session: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _repo(session, max_payload_bytes=10)
    rollback_calls = 0
    original_rollback = session.rollback

    def tracked_rollback() -> None:
        nonlocal rollback_calls
        rollback_calls += 1
        original_rollback()

    monkeypatch.setattr(session, "rollback", tracked_rollback)
    with pytest.raises(OutboxError) as caught:
        repository.enqueue_upsert(_document("event-secret", source_name="super-secret-token"))

    assert str(caught.value) == "opensearch_outbox_payload_too_large"
    assert caught.value.code == "opensearch_outbox_payload_too_large"
    assert rollback_calls == 0


@pytest.mark.parametrize(
    ("claimant_id", "limit", "lease_seconds", "error_code"),
    [
        ("", 1, 30, "opensearch_outbox_claimant_id_invalid"),
        (" " * 3, 1, 30, "opensearch_outbox_claimant_id_invalid"),
        ("x" * 65, 1, 30, "opensearch_outbox_claimant_id_too_long"),
        ("worker", 0, 30, "opensearch_outbox_claim_limit_invalid"),
        ("worker", 101, 30, "opensearch_outbox_claim_limit_invalid"),
        ("worker", 1, 0, "opensearch_outbox_lease_seconds_invalid"),
        ("worker", 1, 86_401, "opensearch_outbox_lease_seconds_invalid"),
    ],
)
def test_claim_inputs_are_rejected_before_database_access(
    session: Session,
    claimant_id: str,
    limit: int,
    lease_seconds: int,
    error_code: str,
) -> None:
    repository = _repo(session)
    statements = 0

    def count_statement(*_args: Any, **_kwargs: Any) -> None:
        nonlocal statements
        statements += 1

    event.listen(session.get_bind(), "before_cursor_execute", count_statement)
    try:
        with pytest.raises(ValueError, match=error_code):
            repository.claim_batch(claimant_id, limit, lease_seconds)
    finally:
        event.remove(session.get_bind(), "before_cursor_execute", count_statement)
    assert statements == 0


def test_claim_is_bounded_skips_active_lease_and_reclaims_expired(
    session: Session,
) -> None:
    repository = _repo(session)
    reference_now = datetime.now(timezone.utc)
    pending = repository.enqueue_upsert(_document("event-pending"))
    active = repository.enqueue_upsert(_document("event-active"))
    expired = repository.enqueue_upsert(_document("event-expired"))
    retry = repository.enqueue_upsert(_document("event-retry"))
    future = repository.enqueue_upsert(_document("event-future"))

    active.status = "processing"
    active.lease_owner = "active-worker"
    active.lease_expires_at = reference_now + timedelta(days=1)
    expired.status = "processing"
    expired.lease_owner = "dead-worker"
    expired.lease_expires_at = reference_now - timedelta(seconds=1)
    retry.status = "retry"
    retry.available_at = reference_now - timedelta(seconds=1)
    future.status = "retry"
    future.available_at = reference_now + timedelta(days=1)
    session.commit()

    first_batch = repository.claim_batch("worker-1", limit=2, lease_seconds=60)
    second_batch = repository.claim_batch("worker-2", limit=2, lease_seconds=60)

    claimed = first_batch + second_batch
    assert {row.outbox_id for row in claimed} == {
        pending.outbox_id,
        expired.outbox_id,
        retry.outbox_id,
    }
    assert all(row.status == "processing" for row in claimed)
    assert all(row.attempt_count == 1 for row in claimed)
    assert active.lease_owner == "active-worker"
    assert future.status == "retry"
    assert len(first_batch) <= 2
    assert len(second_batch) <= 2


def test_second_claimant_cannot_claim_an_active_row(session: Session) -> None:
    repository = _repo(session)
    repository.enqueue_upsert(_document("event-single-claim"))

    first = repository.claim_batch("worker-1", limit=1, lease_seconds=60)
    second = repository.claim_batch("worker-2", limit=1, lease_seconds=60)

    assert len(first) == 1
    assert second == []
    assert first[0].lease_owner == "worker-1"


@pytest.mark.parametrize("different_payload", [False, True])
def test_on_conflict_race_verifies_the_winning_checksum_without_rollback(
    session: Session,
    monkeypatch: pytest.MonkeyPatch,
    different_payload: bool,
) -> None:
    repository = _repo(session)
    repository.enqueue_upsert(_document("event-race", source_name="winner"))
    session.commit()
    original_select = repository._select_by_keys
    select_calls = 0

    def simulate_race(keys: list[str]) -> dict[str, SearchIndexOutbox]:
        nonlocal select_calls
        select_calls += 1
        if select_calls == 1:
            return {}
        return original_select(keys)

    rollback_calls = 0

    def fail_if_rollback() -> None:
        nonlocal rollback_calls
        rollback_calls += 1

    monkeypatch.setattr(repository, "_select_by_keys", simulate_race)
    monkeypatch.setattr(session, "rollback", fail_if_rollback)
    raced_document = _document(
        "event-race",
        source_name="loser" if different_payload else "winner",
    )

    if different_payload:
        with pytest.raises(OutboxError) as caught:
            repository.enqueue_upsert(raced_document)
        assert caught.value.code == "opensearch_outbox_deduplication_conflict"
    else:
        assert repository.enqueue_upsert(raced_document).entity_id == "event-race"

    assert rollback_calls == 0
    assert session.execute(select(func.count()).select_from(SearchIndexOutbox)).scalar_one() == 1
