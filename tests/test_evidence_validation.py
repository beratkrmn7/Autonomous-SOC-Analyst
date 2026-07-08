import pytest
from nodes import evidence_validation_node

def test_evidence_validation_success():
    state = {
        "incident_id": "TEST-01",
        "triage_verdict": "suspicious",
        "raw_logs": [{"event_id": "1", "raw_message": "This is a malicious payload string"}],
        "evidence": [
            {"event_id": "1", "quote": "malicious payload", "reason": "test", "source": "test"}
        ]
    }
    res = evidence_validation_node(state)
    assert len(res["validated_evidence"]) == 1
    assert len(res["rejected_evidence"]) == 0
    # Verdict should not change if evidence is valid
    assert res.get("triage_verdict") is None

def test_evidence_validation_too_short():
    state = {
        "incident_id": "TEST-01",
        "triage_verdict": "suspicious",
        "raw_logs": [{"event_id": "1", "raw_message": "This is a malicious payload string"}],
        "evidence": [
            {"event_id": "1", "quote": "malicious", "reason": "test", "source": "test"}
        ]
    }
    res = evidence_validation_node(state)
    assert len(res["validated_evidence"]) == 0
    assert len(res["rejected_evidence"]) == 1
    assert res["triage_verdict"] == "needs_review"

def test_evidence_validation_mismatch():
    state = {
        "incident_id": "TEST-01",
        "triage_verdict": "suspicious",
        "raw_logs": [{"event_id": "1", "raw_message": "This is a benign string"}],
        "evidence": [
            {"event_id": "1", "quote": "malicious payload string", "reason": "test", "source": "test"}
        ]
    }
    res = evidence_validation_node(state)
    assert len(res["validated_evidence"]) == 0
    assert len(res["rejected_evidence"]) == 1
    assert res["triage_verdict"] == "needs_review"
