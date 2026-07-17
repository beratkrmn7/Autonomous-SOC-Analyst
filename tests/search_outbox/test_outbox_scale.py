from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import sessionmaker

from agent.opensearch.documents import CanonicalEventSearchDocument
from agent.persistence.database import Base
from agent.persistence.orm_models import SearchIndexOutbox
from agent.persistence.outbox_repository import SearchIndexOutboxRepository


def test_10_000_documents_use_bounded_chunks_and_constant_queries_per_chunk(
    monkeypatch,
) -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = factory()
    repository = SearchIndexOutboxRepository(
        session,
        max_payload_bytes=65_536,
        enqueue_chunk_size=250,
        max_claim_batch_size=1_000,
    )
    flush_count = 0
    sql_count = 0
    produced_count = 0
    now = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)

    original_flush = session.flush

    def tracked_flush(*args: Any, **kwargs: Any) -> None:
        nonlocal flush_count
        flush_count += 1
        original_flush(*args, **kwargs)

    def count_outbox_sql(
        _connection: Any,
        _cursor: Any,
        statement: str,
        _parameters: Any,
        _context: Any,
        _executemany: bool,
    ) -> None:
        nonlocal sql_count
        normalized = statement.lstrip().upper()
        if "SEARCH_INDEX_OUTBOX" in normalized and normalized.startswith(
            ("SELECT", "INSERT")
        ):
            sql_count += 1

    def documents() -> Iterator[CanonicalEventSearchDocument]:
        nonlocal produced_count
        for index in range(10_000):
            produced_count += 1
            entity_id = f"scale-event-{index:05d}"
            yield CanonicalEventSearchDocument(
                schema_version="v1",
                entity_id=entity_id,
                document_version=1,
                indexed_at=now,
                source_updated_at=now,
                event_id=entity_id,
                timestamp=now,
            )

    monkeypatch.setattr(session, "flush", tracked_flush)
    event.listen(engine, "before_cursor_execute", count_outbox_sql)
    try:
        summary = repository.enqueue_many_upserts(documents())
    finally:
        event.remove(engine, "before_cursor_execute", count_outbox_sql)

    assert produced_count == 10_000
    assert summary.requested_count == 10_000
    assert summary.inserted_count == 10_000
    assert summary.reused_count == 0
    assert summary.chunk_count == 40
    assert summary.max_chunk_size == 250
    assert sql_count == summary.chunk_count * 3
    assert flush_count == 0
    assert session.execute(select(func.count()).select_from(SearchIndexOutbox)).scalar_one() == 10_000

    session.close()
    engine.dispose()
