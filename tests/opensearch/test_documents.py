from __future__ import annotations

from datetime import datetime, timezone
import json

import pytest
from pydantic import ValidationError

from agent.opensearch.documents import (
    CanonicalEventSearchDocument,
    canonical_event_document,
    detection_signal_document,
    deterministic_document_json,
    incident_document,
)
from agent.persistence.orm_models import CanonicalEvent, DetectionSignal, Incident


NOW = datetime(2026, 7, 17, 8, 30, tzinfo=timezone.utc)
SECRET = "password=do-not-index-this"


def test_canonical_event_document_is_explicit_safe_and_deterministic() -> None:
    row = CanonicalEvent(
        event_id="event-1",
        timestamp=NOW,
        observed_at=NOW,
        source_name="firewall",
        parser_name="cef",
        raw_record_hash="a" * 64,
        source_line=41,
        safe_message_excerpt=SECRET,
        src_ip="192.0.2.10",
        dst_ip="not-an-ip",
        src_port=443,
        user=SECRET,
    )

    document = canonical_event_document(
        row,
        schema_version="v1",
        indexed_at=NOW,
        job_ids=("job-1", SECRET),
        incident_ids=("incident-1",),
    )
    encoded = deterministic_document_json(document)

    assert encoded == deterministic_document_json(document)
    payload = json.loads(encoded)
    assert payload["event_id"] == "event-1"
    assert payload["src_ip"] == "192.0.2.10"
    assert payload["dst_ip"] is None
    assert payload["safe_message_excerpt"] == "[redacted]"
    assert payload["user"] == "[redacted]"
    assert payload["job_ids"] == ["job-1", "[redacted]"]
    assert "do-not-index-this" not in encoded
    assert "raw_record_hash" not in payload
    assert "source_line" not in payload


def test_signal_document_omits_metrics_and_caps_unsafe_text() -> None:
    row = DetectionSignal(
        signal_id="signal-1",
        rule_id="rule-1",
        rule_name=SECRET,
        signal_type="detection",
        signal_family="network",
        severity="high",
        confidence=0.9,
        created_at=NOW,
        suppressed=True,
        suppression_reason=SECRET,
        metrics={"token": "do-not-index-this"},
        event_ids=["raw-event-link"],
        mitre_techniques=["T1059", SECRET],
    )

    document = detection_signal_document(
        row,
        schema_version="v1",
        indexed_at=NOW,
    )
    payload = document.model_dump(mode="json")

    assert payload["rule_name"] == "[redacted]"
    assert payload["suppression_reason"] == "[redacted]"
    assert payload["mitre_techniques"] == ["T1059", "[redacted]"]
    assert "metrics" not in payload
    assert "event_ids" not in payload


def test_serializer_normalizes_utc_caps_text_and_rejects_non_finite_values() -> None:
    naive = datetime(2026, 7, 17, 8, 30)
    row = DetectionSignal(
        signal_id="signal-utc",
        rule_name="x" * 400,
        confidence=0.5,
        created_at=naive,
    )
    document = detection_signal_document(
        row,
        schema_version="v1",
        indexed_at=NOW,
    )
    assert document.created_at.tzinfo == timezone.utc
    assert len(document.rule_name or "") == 256

    for invalid_confidence in (float("nan"), float("inf"), float("-inf")):
        invalid = DetectionSignal(
            signal_id="signal-invalid",
            confidence=invalid_confidence,
            created_at=NOW,
        )
        with pytest.raises(ValidationError):
            detection_signal_document(
                invalid,
                schema_version="v1",
                indexed_at=NOW,
            )


def test_incident_document_uses_explicit_derived_relationship_flags() -> None:
    row = Incident(
        incident_id="incident-1",
        title="Known-safe title",
        status="resolved",
        severity="critical",
        confidence=0.8,
        version=4,
        created_at=NOW,
        updated_at=NOW,
        review_reason=SECRET,
        metrics={"secret": "do-not-index-this"},
    )

    document = incident_document(
        row,
        schema_version="v1",
        indexed_at=NOW,
        job_ids=("job-1",),
        has_report=True,
        has_validated_evidence=True,
    )
    payload = document.model_dump(mode="json")

    assert payload["document_version"] == 4
    assert payload["job_ids"] == ["job-1"]
    assert payload["has_report"] is True
    assert payload["has_validated_evidence"] is True
    assert "review_reason" not in payload
    assert "metrics" not in payload


def test_document_model_rejects_unknown_fields_invalid_schema_and_port() -> None:
    base = {
        "schema_version": "v1",
        "entity_id": "event-1",
        "document_version": 1,
        "indexed_at": NOW,
        "source_updated_at": NOW,
        "event_id": "event-1",
        "timestamp": NOW,
    }
    with pytest.raises(ValidationError):
        CanonicalEventSearchDocument(**base, raw_payload="forbidden")
    with pytest.raises(ValidationError):
        CanonicalEventSearchDocument(**{**base, "schema_version": "latest"})
    with pytest.raises(ValidationError):
        CanonicalEventSearchDocument(**base, src_port=70_000)
