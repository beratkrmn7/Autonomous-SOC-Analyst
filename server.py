from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import json
import uvicorn

# Import the pre-compiled graph from main.py
# Note: we should structure this better in a real project, but for PoC this is fine.
from main import app as agent_app

app = FastAPI(
    title="Agentic SOC Triage Assistant",
    description="Multi-Agent SOC Triage system powered by LangGraph and Groq",
    version="1.0.0"
)

# In-memory store for incident reports (simulating a database)
incident_store: Dict[str, dict] = {}

class AnalyzeRequest(BaseModel):
    incident_id: str
    raw_logs: List[dict]

class AnalyzeResponse(BaseModel):
    incident_id: str
    triage_verdict: Optional[str]
    incident_type: Optional[str]
    severity: Optional[str]
    confidence_score: Optional[float]
    report_status: str

@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_incident(req: AnalyzeRequest):
    """
    Ingest raw logs for an incident and run the Multi-Agent Triage workflow.
    """
    # Pre-process logs to inject event_ids
    processed_logs = []
    for i, log in enumerate(req.raw_logs):
        log_copy = dict(log)
        log_copy["event_id"] = f"{req.incident_id}-E{i+1:03d}"
        processed_logs.append(log_copy)

    initial_state = {
        "incident_id": req.incident_id,
        "raw_logs": processed_logs, 
        "messages": [],
        "search_history": [],
        "tool_results": [],
        "errors": []
    }
    
    try:
        # Synchronous execution
        final_state = agent_app.invoke(initial_state)
        
        # Save to in-memory store
        incident_store[req.incident_id] = final_state
        
        return AnalyzeResponse(
            incident_id=req.incident_id,
            triage_verdict=final_state.get('triage_verdict'),
            incident_type=final_state.get('incident_type'),
            severity=final_state.get('severity'),
            confidence_score=final_state.get('confidence_score'),
            report_status="Generated" if final_state.get('final_report') else "Not Generated"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/incident/{incident_id}/report")
def get_incident_report(incident_id: str):
    """
    Fetch the detailed markdown report and structured state for a processed incident.
    """
    if incident_id not in incident_store:
        raise HTTPException(status_code=404, detail="Incident not found or not processed yet.")
        
    state = incident_store[incident_id]
    
    return {
        "incident_id": incident_id,
        "triage_verdict": state.get("triage_verdict"),
        "incident_type": state.get("incident_type"),
        "entities": state.get("entities", {}),
        "validated_evidence": state.get("validated_evidence", []),
        "recommended_actions": state.get("recommended_actions", []),
        "final_report_markdown": state.get("final_report", "No report available.")
    }

@app.get("/health")
def health_check():
    """Simple health check endpoint."""
    return {"status": "healthy", "service": "Agentic SOC Triage API"}

if __name__ == "__main__":
    print("Starting Agentic SOC API Server on http://localhost:8000")
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
