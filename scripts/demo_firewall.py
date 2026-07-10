import json
from agent.ingest import IngestPipeline
from agent.graph import app
from rich.console import Console

console = Console()

def test():
    print("Loading pfSense logs...")
    # Just load first 50 lines to test
    raw_logs = []
    with open("log_pf.range.2026-07-10.09_54.0.json", "r") as f:
        for i, line in enumerate(f):
            if i >= 1000:
                break
            raw_logs.append(json.loads(line))
            
    # Inject event ids
    for i, log in enumerate(raw_logs):
        log["event_id"] = f"PFSENSE-E{i+1:03d}"
        
    pipeline = IngestPipeline()
    processed_logs = pipeline.process_logs(raw_logs)
    
    initial_state = {
        "incident_id": "PFSENSE-TEST",
        "raw_logs": processed_logs, 
        "messages": [],
        "iteration_count": 0,
        "mitre_techniques": [],
        "candidate_evidence": [],
        "detected_signals": [],
        "search_history": [],
        "tool_results": [],
        "errors": []
    }
    
    print("Invoking graph...")
    final_state = app.invoke(initial_state)
    print(f"Verdict: {final_state.get('triage_verdict')}")
    print(f"Incident Type: {final_state.get('incident_type')}")
    if final_state.get('final_report'):
        print(f"Report:\n{final_state.get('final_report')}")

if __name__ == "__main__":
    test()
