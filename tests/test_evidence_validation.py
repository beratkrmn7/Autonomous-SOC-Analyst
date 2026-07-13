# mypy: ignore-errors
from agent.nodes import evidence_validation_node

def test_evidence_validation_success():
    state = {
        "incident_id": "TEST-01",
        "triage_submission": {
            "triage_verdict": "suspicious_activity",
            "incident_type": "other",
            "severity": "medium",
            "confidence_score": 0.8,
            "summary": "test",
            "selected_evidence_ids": ["E1"],
            "claims": []
        },
        "incident": {
            "incident": {
                "incident_id": "TEST-01",
                "incident_type": "test",
                "incident_family": "test",
                "title": "test",
                "severity": "low",
                "confidence": 1.0,
                "primary_entity": "unknown",
                "target_entities": [],
                "signal_ids": [],
                "evidence": [],
                "metrics": {},
                "mitre_techniques": [],
                "merge_key": "mock",
                "event_ids": ["1"],
                "context_event_ids": [],
                "first_seen": "2024-01-01T00:00:00Z",
                "last_seen": "2024-01-01T00:00:00Z"
            },
            "events": [{"event_id": "1", "timestamp": None, "observed_at": "2024-01-01T00:00:00Z", "parse_status": "success", "parser_name": "test", "source_name": "test", "safe_message_excerpt": "test", "source_line": None}],
            "context_events": []
        },
        "safe_triage_input": {
            "incident_id": "TEST-01",
            "incident_type": "other",
            "incident_family": "other",
            "title": "test",
            "deterministic_severity": "none",
            "deterministic_confidence": 0.0,
            "first_seen": "2024-01-01T00:00:00Z",
            "last_seen": "2024-01-01T00:00:00Z",
            "primary_entity": "1.1.1.1",
            "incident_type_hint": "other",
            "detected_signals": [],
            "candidate_evidence": [
                {"evidence_id": "E1", "event_id": "1", "quote": "test", "reason": "test", "source": "test", "canonical_fields": {}, "vendor_original_fields": {}}
            ],
            "limited_context_events": [
                {"event_id": "1", "event_type": "test", "source_ip": "1.1.1.1", "safe_message_excerpt": "test", "timestamp": "2024-01-01T00:00:00Z", "parser_name": "test", "source_name": "test"}
            ]
        }
    }
    res = evidence_validation_node(state)
    assert len(res["validated_evidence"]) == 1
    assert len(res["rejected_evidence"]) == 0
    # Verdict should not change if evidence is valid
    assert res.get("triage_verdict") is None

def test_evidence_validation_mismatch():
    state = {
        "incident_id": "TEST-01",
        "triage_submission": {
            "triage_verdict": "suspicious_activity",
            "incident_type": "other",
            "severity": "medium",
            "confidence_score": 0.8,
            "summary": "test",
            "selected_evidence_ids": ["E1"],
            "claims": []
        },
        "incident": {
            "incident": {
                "incident_id": "TEST-01",
                "incident_type": "test",
                "incident_family": "test",
                "title": "test",
                "severity": "low",
                "confidence": 1.0,
                "primary_entity": "unknown",
                "target_entities": [],
                "signal_ids": [],
                "evidence": [],
                "metrics": {},
                "mitre_techniques": [],
                "merge_key": "mock",
                "event_ids": ["1"],
                "context_event_ids": [],
                "first_seen": "2024-01-01T00:00:00Z",
                "last_seen": "2024-01-01T00:00:00Z"
            },
            "events": [{"event_id": "1", "timestamp": None, "observed_at": "2024-01-01T00:00:00Z", "parse_status": "success", "parser_name": "test", "source_name": "test", "safe_message_excerpt": "test", "source_line": None}],
            "context_events": []
        },
        "safe_triage_input": {
            "incident_id": "TEST-01",
            "incident_type": "other",
            "incident_family": "other",
            "title": "test",
            "deterministic_severity": "none",
            "deterministic_confidence": 0.0,
            "first_seen": "2024-01-01T00:00:00Z",
            "last_seen": "2024-01-01T00:00:00Z",
            "primary_entity": "1.1.1.1",
            "incident_type_hint": "other",
            "detected_signals": [],
            "candidate_evidence": [], # E1 doesn't exist
            "limited_context_events": []
        }
    }
    res = evidence_validation_node(state)
    assert len(res["validated_evidence"]) == 0
    assert len(res["rejected_evidence"]) == 1
    assert res["triage_verdict"] == "needs_review"

def test_evidence_validation_false_positive_missing_evidence():
    state = {
        "incident_id": "TEST-01",
        "triage_submission": {
            "triage_verdict": "false_positive",
            "incident_type": "other",
            "severity": "none",
            "confidence_score": 0.8,
            "summary": "test",
            "selected_evidence_ids": [],
            "claims": []
        },
        "incident": {
            "incident": {
                "incident_id": "TEST-01",
                "incident_type": "test",
                "incident_family": "test",
                "title": "test",
                "severity": "low",
                "confidence": 1.0,
                "primary_entity": "unknown",
                "target_entities": [],
                "signal_ids": [],
                "evidence": [],
                "metrics": {},
                "mitre_techniques": [],
                "merge_key": "mock",
                "event_ids": ["1"],
                "context_event_ids": [],
                "first_seen": "2024-01-01T00:00:00Z",
                "last_seen": "2024-01-01T00:00:00Z"
            },
            "events": [{"event_id": "1", "timestamp": None, "observed_at": "2024-01-01T00:00:00Z", "parse_status": "success", "parser_name": "test", "source_name": "test", "safe_message_excerpt": "test", "source_line": None}],
            "context_events": []
        },
        "safe_triage_input": {
            "incident_id": "TEST-01",
            "incident_type": "other",
            "incident_family": "other",
            "title": "test",
            "deterministic_severity": "none",
            "deterministic_confidence": 0.0,
            "first_seen": "2024-01-01T00:00:00Z",
            "last_seen": "2024-01-01T00:00:00Z",
            "primary_entity": "1.1.1.1",
            "incident_type_hint": "other",
            "detected_signals": [],
            "candidate_evidence": [],
            "limited_context_events": []
        }
    }
    res = evidence_validation_node(state)
    assert res.get("triage_verdict") == "needs_review"
