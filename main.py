import json
import os
import datetime
import ast
from dotenv import load_dotenv

from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode

from models import IncidentState
from tools import tools_list
from nodes import (
    entity_extraction_node,
    strategy_router_node,
    triage_node, 
    process_result_node, 
    evidence_validation_node,
    action_recommendation_node,
    reporter_node, 
    route_triage, 
    route_after_process
)

load_dotenv()

if not os.environ.get("GROQ_API_KEY"):
    print("Warning: GROQ_API_KEY is not set. Please set it in .env file.")

with open("mock_logs.json", "r") as f:
    MOCK_DATA = json.load(f)

class CustomToolNode(ToolNode):
    def invoke(self, input_val, config=None, **kwargs):
        result = super().invoke(input_val, config, **kwargs)
        tool_results = []
        search_history = []
        if "messages" in result:
            for msg in result["messages"]:
                if hasattr(msg, "name"):
                    timestamp = datetime.datetime.now().isoformat()
                    content_str = msg.content
                    matched_ids = []
                    
                    # Try to parse dict from string if it's native python representation
                    try:
                        content_dict = ast.literal_eval(content_str)
                        if isinstance(content_dict, dict) and "matched_event_ids" in content_dict:
                            matched_ids = content_dict["matched_event_ids"]
                    except:
                        # Fallback to json loads if it was json dumped
                        try:
                            content_json = json.loads(content_str)
                            if "matched_event_ids" in content_json:
                                matched_ids = content_json["matched_event_ids"]
                        except:
                            pass
                            
                    tool_record = {
                        "tool_name": msg.name,
                        "timestamp": timestamp,
                        "result_summary": content_str[:200] + "..." if len(content_str) > 200 else content_str,
                        "matched_event_ids": matched_ids
                    }
                    tool_results.append(tool_record)
                    
                    if msg.name == "search_logs":
                        search_history.append(tool_record)
                        
        return {"messages": result["messages"], "tool_results": tool_results, "search_history": search_history}

# Build Graph
workflow = StateGraph(IncidentState)

# Add nodes
workflow.add_node("entity_extraction_node", entity_extraction_node)
workflow.add_node("strategy_router_node", strategy_router_node)
workflow.add_node("triage_node", triage_node)
workflow.add_node("tools", CustomToolNode(tools_list))
workflow.add_node("process_result", process_result_node)
workflow.add_node("evidence_validation_node", evidence_validation_node)
workflow.add_node("action_recommendation_node", action_recommendation_node)
workflow.add_node("reporter_node", reporter_node)

# Set entry point
workflow.set_entry_point("entity_extraction_node")

# Edges
workflow.add_edge("entity_extraction_node", "strategy_router_node")
workflow.add_edge("strategy_router_node", "triage_node")

# Add conditional edges from triage
workflow.add_conditional_edges(
    "triage_node",
    route_triage,
    {
        "tools": "tools",
        "process_result": "process_result"
    }
)

# After tools, always go back to triage_node
workflow.add_edge("tools", "triage_node")

# After processing result, route to validation
workflow.add_conditional_edges(
    "process_result",
    route_after_process,
    {
        "evidence_validation_node": "evidence_validation_node"
    }
)

workflow.add_edge("evidence_validation_node", "action_recommendation_node")
workflow.add_edge("action_recommendation_node", "reporter_node")
workflow.add_edge("reporter_node", END)

# Compile graph
app = workflow.compile()

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
