from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from unittest.mock import MagicMock

from fastapi import Request
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from agent.opensearch.documents import (
    canonical_event_document,
    detection_signal_document,
    incident_document,
)
from agent.persistence.database import Base
from agent.persistence.orm_models import (
    AuditEvent,
    CanonicalEvent,
    DetectionSignal,
    Incident,
    SearchIndexOutbox,
)
from agent.persistence.outbox_repository import OutboxError, SearchIndexOutboxRepository
from server import global_exception_handler


NOW = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
SECRET_MARKERS = (
    "super-secret-token",
    "fake-api-key",
    "jwt-secret",
    "database-secret",
    "redis-secret",
    "private-search.example.test",
    "private\\ca.pem",
    "provider prompt secret",
    "raw exception secret",
    "raw firewall log",
)


def test_payload_metadata_logs_api_errors_and_audit_events_exclude_secrets(
    caplog,
) -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = factory()
    repository = SearchIndexOutboxRepository(
        session,
        max_payload_bytes=65_536,
        enqueue_chunk_size=100,
        max_claim_batch_size=100,
    )

    event_row = CanonicalEvent(
        event_id="event-security",
        timestamp=NOW,
        source_name="Authorization: Bearer super-secret-token",
        parser_name="api_key=fake-api-key",
        parser_version="eyJheader.jwt-secret.signature",
        safe_message_excerpt="postgresql://user:database-secret@db/soc",
        protocol="redis://:redis-secret@cache/0",
        action="OpenSearch URL=https://private-search.example.test:9200",
        user=r"C:\private\ca.pem",
    )
    signal_row = DetectionSignal(
        signal_id="signal-security",
        rule_id="rule-safe",
        rule_name="provider prompt secret",
        signal_type="network",
        severity="high",
        confidence=0.9,
        created_at=NOW,
        suppression_reason="raw exception secret",
        metrics={"secret": "fake-api-key"},
        mitre_techniques=["T1059"],
    )
    incident_row = Incident(
        incident_id="incident-security",
        title="raw firewall log Authorization: Bearer super-secret-token",
        status="new",
        version=1,
        created_at=NOW,
        updated_at=NOW,
    )
    repository.enqueue_many_upserts(
        [
            canonical_event_document(event_row, schema_version="v1"),
            detection_signal_document(signal_row, schema_version="v1"),
            incident_document(incident_row, schema_version="v1"),
        ]
    )
    session.commit()

    rows = session.execute(select(SearchIndexOutbox)).scalars().all()
    serialized_rows = json.dumps(
        [
            {
                "payload": row.payload,
                "payload_sha256": row.payload_sha256,
                "last_error_code": row.last_error_code,
            }
            for row in rows
        ],
        sort_keys=True,
    )
    lowered = serialized_rows.lower()
    for marker in SECRET_MARKERS:
        assert marker.lower() not in lowered
    assert all(row.last_error_code is None for row in rows)
    assert session.execute(select(func.count()).select_from(AuditEvent)).scalar_one() == 0

    secret_exception = OutboxError("opensearch_outbox_payload_too_large")
    request = MagicMock(spec=Request)
    request.state.request_id = "request-safe"
    with caplog.at_level("ERROR"):
        response = asyncio.run(global_exception_handler(request, secret_exception))

    assert response.status_code == 500
    assert response.body == (
        b'{"code":"internal_error","message":"The request could not be completed."}'
    )
    captured = caplog.text.lower()
    for marker in SECRET_MARKERS:
        assert marker.lower() not in captured
    assert "65536" not in str(secret_exception)
    assert "payload" not in str(secret_exception).replace(
        "opensearch_outbox_payload_too_large", ""
    )

    session.close()
    engine.dispose()
