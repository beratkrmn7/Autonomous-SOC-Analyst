from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional
import json
import uvicorn
import shutil
import os
import tempfile

from agent.config import get_settings
from agent.errors import InputTooLargeError, UnsupportedInputFormatError, InvalidEncodingError
from agent.graph import app as agent_app
from agent.ingestion.pipeline import IngestionPipeline
from agent.filtering import EventFilter
from agent.correlation import CorrelationEngine

app = FastAPI(
    title="Agentic SOC Triage Assistant",
    description="Agentic SOC Triage workflow using LangGraph and Groq",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

incident_store: Dict[str, dict] = {}

@app.exception_handler(InputTooLargeError)
async def input_too_large_handler(request: Request, exc: InputTooLargeError):
    return JSONResponse(
        status_code=413,
        content={"code": "input_too_large", "message": str(exc)}
    )

@app.exception_handler(UnsupportedInputFormatError)
async def unsupported_format_handler(request: Request, exc: UnsupportedInputFormatError):
    return JSONResponse(
        status_code=415,
        content={"code": "unsupported_input_format", "message": str(exc)}
    )

@app.exception_handler(InvalidEncodingError)
async def invalid_encoding_handler(request: Request, exc: InvalidEncodingError):
    return JSONResponse(
        status_code=422,
        content={"code": "invalid_encoding", "message": str(exc)}
    )

async def secure_save_upload(file: UploadFile) -> str:
    """Safely saves an uploaded file to a temporary location using chunking and byte limits."""
    settings = get_settings()
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as temp_file:
            temp_path = temp_file.name
            total_bytes = 0
            while chunk := await file.read(8192):
                total_bytes += len(chunk)
                if total_bytes > settings.ingestion.MAX_UPLOAD_BYTES:
                    temp_file.close()
                    os.remove(temp_path)
                    raise InputTooLargeError(f"Upload exceeds maximum limit of {settings.ingestion.MAX_UPLOAD_BYTES} bytes.")
                temp_file.write(chunk)
        return temp_path
    except Exception:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        raise

class AnalyzeRequest(BaseModel):
    incident_id: str
    raw_logs: List[dict]

class AnalyzeResponse(BaseModel):
    incident_id: str
    triage_verdict: Optional[str]
    incident_type: Optional[str]
    severity: Optional[str]
    confidence_score: Optional[float]
    mitre_techniques: Optional[List[str]]
    report_status: str

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/ready")
def readiness_check():
    from agent.config import get_settings
    settings = get_settings()
    if settings.llm_enabled and not settings.groq_api_key:
        return {"status": "unready", "reason": "Missing API key for LLM"}
    return {"status": "ready"}

@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_incident(req: AnalyzeRequest):
    """
    Legacy mock endpoint: Ingest raw logs for an incident and run triage.
    """
    raw_logs = req.raw_logs
    for i, log in enumerate(raw_logs):
        if "event_id" not in log:
            log["event_id"] = f"{req.incident_id}-E{i+1:03d}"
            
    ingest_pipeline = IngestionPipeline()
    processed_logs = ingest_pipeline.ingest_records(raw_logs, source_name="mock_api").events
    canonical_events = [log.model_dump(mode="json") for log in processed_logs]

    initial_state = {
        "incident_id": req.incident_id,
        "canonical_events": canonical_events, 
        "messages": [],
        "iteration_count": 0,
        "mitre_techniques": [],
        "candidate_evidence": [],
        "detected_signals": [],
        "search_history": [],
        "tool_results": [],
        "errors": []
    }
    try:
        final_state = agent_app.invoke(initial_state)
        incident_store[req.incident_id] = final_state
        return AnalyzeResponse(
            incident_id=req.incident_id,
            triage_verdict=final_state.get('triage_verdict'),
            incident_type=final_state.get('incident_type'),
            severity=final_state.get('severity'),
            confidence_score=final_state.get('confidence_score'),
            mitre_techniques=final_state.get('mitre_techniques', []),
            report_status="Generated" if final_state.get('final_report') else "Not Generated"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/ingest/file")
async def ingest_file(file: UploadFile = File(...)):
    """
    Ingest a raw log file and return a metric summary. Does not run triage.
    """
    temp_path = await secure_save_upload(file)
        
    try:
        ingest = IngestionPipeline()
        result = ingest.ingest_file(temp_path)
        
        return {
            "source_name": result.source_name,
            "input_format": result.input_format.value,
            "metrics": result.metrics.model_dump(),
            "warnings": result.warnings
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.post("/analyze/file")
async def analyze_file(file: UploadFile = File(...)):
    """
    Analyze a raw JSONL log file, performing full ingestion, filtering, and correlation.
    """
    temp_path = await secure_save_upload(file)
        
    try:
        ingest = IngestionPipeline()
        filter_engine = EventFilter()
        correlator = CorrelationEngine()
        
        ingest_result = ingest.ingest_file(temp_path)
        filter_result = filter_engine.filter_events(ingest_result.events)
        bundles = correlator.build_incidents(filter_result.candidates, filter_result.context)
        
        incident_summaries = []
        for bundle in bundles:
            canonical_events = [log.model_dump(mode="json") for log in bundle.events]
            
            detected_signals = []
            candidate_evidence = []
            if bundle.correlation_reason:
                detected_signals.append({
                    "detector_name": "CorrelationEngine",
                    "status": "alert",
                    "message": bundle.correlation_reason,
                    "matched_event_ids": bundle.event_ids
                })
                for ev in bundle.events:
                    candidate_evidence.append({
                        "event_id": ev.event_id,
                        "quote": ev.raw_message or json.dumps(ev.original_log),
                        "original_fields": ev.original_log
                    })
                    
            initial_state = {
                "incident_id": bundle.incident_id,
                "canonical_events": canonical_events,
                "messages": [],
                "iteration_count": 0,
                "mitre_techniques": [],
                "candidate_evidence": candidate_evidence,
                "detected_signals": detected_signals,
                "search_history": [],
                "tool_results": [],
                "errors": []
            }
            final_state = agent_app.invoke(initial_state)
            incident_store[bundle.incident_id] = final_state
            
            incident_summaries.append({
                "incident_id": bundle.incident_id,
                "type_hint": bundle.incident_type_hint,
                "verdict": final_state.get('triage_verdict'),
                "severity": final_state.get('severity')
            })
            
        return {
            "total_events": ingest_result.metrics.total_records,
            "parsed_events": ingest_result.metrics.parsed_records,
            "failed_events": ingest_result.metrics.failed_records,
            "unsupported_events": ingest_result.metrics.unsupported_records,
            "noise_events": filter_result.metrics.get('noise', 0),
            "context_events": filter_result.metrics.get('context', 0),
            "candidate_events": filter_result.metrics.get('candidates', 0),
            "incidents_created": len(bundles),
            "incidents": incident_summaries
        }
    except InputTooLargeError:
        raise
    except UnsupportedInputFormatError:
        raise
    except InvalidEncodingError:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.get("/incident/{incident_id}/report")
def get_incident_report(incident_id: str):
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
        "mitre_techniques": state.get("mitre_techniques", []),
        "final_report_markdown": state.get("final_report", "No report available.")
    }



if __name__ == "__main__":
    print("Starting Agentic SOC API Server on http://localhost:8000")
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
