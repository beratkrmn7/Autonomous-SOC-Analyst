import json
import os
from dotenv import load_dotenv

from graph import app

load_dotenv()

if not os.environ.get("GROQ_API_KEY"):
    print("Warning: GROQ_API_KEY is not set. Please set it in .env file.")

with open("mock_logs.json", "r") as f:
    MOCK_DATA = json.load(f)

def run_test():
    run_all = os.environ.get("RUN_ALL", "false").lower() == "true"
    
    for incident in MOCK_DATA:
        print("\n" + "="*70)
        print(f"Processing {incident['incident_id']}: {incident['description']}")
        print("="*70)
        
        # Pre-process logs to inject event_ids
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
            "search_history": [],
            "tool_results": [],
            "errors": []
        }
        
        try:
            # Invoke LangGraph app
            final_state = app.invoke(initial_state)
            
            print("\n--- FINAL STATE ---")
            print(f"Verdict: {final_state.get('triage_verdict')}")
            print(f"Incident Type: {final_state.get('incident_type')}")
            print(f"Severity: {final_state.get('severity')}")
            print(f"Iterations: {final_state.get('iteration_count')}")
            print(f"Tool Executions: {len(final_state.get('tool_results', []))}")
            
            if final_state.get('final_report'):
                print("\n--- GENERATED REPORT ---")
                print(final_state['final_report'])
            else:
                print("\n(No report generated)")
        except Exception as e:
            print(f"\n[ERROR] An error occurred while processing {incident['incident_id']}: {e}")
            import traceback
            traceback.print_exc()
            
        if not run_all:
            print("\n[INFO] Breaking early after 1 incident. Set RUN_ALL=true in .env to run all.")
            break

if __name__ == "__main__":
    run_test()
