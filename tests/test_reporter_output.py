# mypy: ignore-errors
from agent.nodes import reporter_node

def test_reporter_sqli_format():
    state = {
        "incident_id": "TEST-01",
        "triage_submission": {
            "triage_verdict": "confirmed_incident",
            "incident_type": "sql_injection",
            "severity": "high",
            "confidence_score": 0.9,
            "summary": "This is a test summary",
            "selected_evidence_ids": ["E1", "E2"],
            "claims": []
        },
        "validated_evidence": [
            {"evidence_id": "E1", "event_id": "1", "status": "validated"},
            {"evidence_id": "E2", "event_id": "2", "status": "validated"}
        ],
        "rejected_evidence": [],
        "validated_claims": [],
        "review_reason": "none"
    }
    
    res = reporter_node(state)
    report = res["final_report"]
    
    assert "## Triage Summary" in report
    assert "## Validated Evidence" in report
    assert "## Recommended Analyst Actions" in report
    
    assert "- Evidence ID: E1" in report
    assert "- Evidence ID: E2" in report
    assert "CONFIRMED_INCIDENT" in report

def test_reporter_false_positive():
    state = {
        "incident_id": "TEST-02",
        "triage_submission": {
            "triage_verdict": "false_positive",
            "incident_type": "benign_web_traffic",
            "severity": "none",
            "confidence_score": 0.9,
            "summary": "This is benign",
            "selected_evidence_ids": [],
            "claims": []
        },
        "validated_evidence": [],
        "rejected_evidence": [],
        "validated_claims": [],
        "review_reason": "none"
    }
    
    res = reporter_node(state)
    report = res["final_report"]
    
    assert "FALSE_POSITIVE" in report
    assert "No immediate action required" in report

def test_reporter_needs_review():
    state = {
        "incident_id": "TEST-03",
        "triage_submission": {
            "triage_verdict": "needs_review",
            "incident_type": "other",
            "severity": "none",
            "confidence_score": 0.0,
            "summary": "Manual review",
            "selected_evidence_ids": [],
            "claims": []
        },
        "validated_evidence": [],
        "rejected_evidence": [],
        "validated_claims": [],
        "review_reason": "maximum_iterations_reached"
    }
    
    res = reporter_node(state)
    report = res["final_report"]
    
    assert "NEEDS_REVIEW" in report
    assert "maximum_iterations_reached" in report
