import pytest
from graph import app
import os
import json

@pytest.mark.skipif(not os.environ.get("GROQ_API_KEY"), reason="Requires GROQ API Key")
def test_graph_smoke():
    with open("mock_logs.json", "r") as f:
        mock_data = json.load(f)
        
    incident = mock_data[0] # INC-001 Standard Web Traffic
    
    processed_logs = []
    for i, log in enumerate(incident["raw_logs"]):
        log_copy = dict(log)
        log_copy["event_id"] = f"{incident['incident_id']}-E{i+1:03d}"
        processed_logs.append(log_copy)
        
    initial_state = {
        "incident_id": incident["incident_id"],
        "raw_logs": processed_logs, 
        "messages": [],
        "iteration_count": 0,
        "strategy": "",
        "mitre_techniques": [],
        "candidate_evidence": [],
        "detected_signals": [],
        "search_history": [],
        "tool_results": [],
        "errors": []
    }
    
    final_state = app.invoke(initial_state)
    assert final_state["triage_verdict"] in ["false_positive", "suspicious", "confirmed_incident", "needs_review"]
    assert "final_report" in final_state
    assert final_state["iteration_count"] > 0
