from fastapi import FastAPI, HTTPException, Request, UploadFile, File, Depends, Header
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import uvicorn
import os
import tempfile
import uuid
import hashlib

def calculate_file_sha256(filepath: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

from agent.config import get_settings  # noqa: E402
from agent.errors import InputTooLargeError, UnsupportedInputFormatError, InvalidEncodingError  # noqa: E402
from agent.graph import app as agent_app  # noqa: E402
from agent.ingestion.pipeline import IngestionPipeline  # noqa: E402
from agent.models import IncidentState  # noqa: E402
from agent.api.v1.incidents import router as v1_incidents_router  # noqa: E402
from agent.api.deps import get_uow  # noqa: E402
from agent.persistence.unit_of_work import UnitOfWork  # noqa: E402

app = FastAPI(
    title="Agentic SOC Triage Assistant",
    description="Agentic SOC Triage workflow using LangGraph and Groq",
    version="1.0.0"
)

app.include_router(v1_incidents_router, prefix="/api/v1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# RAM store removed to use persistent database backend
@app.exception_handler(InputTooLargeError)
async def input_too_large_handler(request: Request, exc: InputTooLargeError):
    return JSONResponse(
        status_code=413,
        content={"code": "input_too_large", "message": "The uploaded file exceeds the configured size limit.", "request_id": uuid.uuid4().hex}
    )

@app.exception_handler(UnsupportedInputFormatError)
async def unsupported_format_handler(request: Request, exc: UnsupportedInputFormatError):
    return JSONResponse(
        status_code=415,
        content={"code": "unsupported_input_format", "message": "The uploaded file format is not supported.", "request_id": uuid.uuid4().hex}
    )

@app.exception_handler(InvalidEncodingError)
async def invalid_encoding_handler(request: Request, exc: InvalidEncodingError):
    return JSONResponse(
        status_code=422,
        content={"code": "invalid_encoding", "message": "The uploaded file contains invalid text encoding.", "request_id": uuid.uuid4().hex}
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"code": "internal_error", "message": "An internal error occurred.", "request_id": uuid.uuid4().hex}
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
def analyze_incident(req: AnalyzeRequest, uow: UnitOfWork = Depends(get_uow)):
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

    from agent.detection.models import IncidentBundle as DetectionIncidentBundle
    from agent.triage.models import TriageIncidentContext
    from datetime import datetime, timezone
    event_ids = [e.event_id for e in processed_logs]
    bundle = DetectionIncidentBundle(
        incident_id=req.incident_id,
        incident_type="other",
        incident_family="other",
        title="Mock Incident",
        severity="low",
        confidence=0.5,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        primary_entity="unknown",
        target_entities=[],
        signal_ids=[],
        event_ids=event_ids,
        context_event_ids=[],
        evidence=[],
        metrics={},
        mitre_techniques=[],
        merge_key="mock"
    )
    context = TriageIncidentContext(
        incident=bundle,
        events=processed_logs,
        context_events=[]
    )

    initial_state: IncidentState = {
        "incident_id": req.incident_id,
        "incident": context.model_dump(mode="json"),
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
    final_state = agent_app.invoke(initial_state)
    # Note: legacy endpoint doesn't persist to DB by default unless UoW is used
    return AnalyzeResponse(
        incident_id=req.incident_id,
        triage_verdict=final_state.get('triage_verdict'),
        incident_type=final_state.get('incident_type'),
        severity=final_state.get('severity'),
        confidence_score=final_state.get('confidence_score'),
        mitre_techniques=final_state.get('mitre_techniques', []),
        report_status="Generated" if final_state.get('final_report') else "Not Generated"
    )

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
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


@app.post("/detect/file")
async def detect_file(file: UploadFile = File(...), uow: UnitOfWork = Depends(get_uow)):
    """
    Ingest a raw JSONL log file, parse it into Canonical Events, and return Detection Signals.
    """
    from agent.application.analysis_service import AnalysisService
    from agent.application.errors import DuplicateAnalysisError
    temp_path = await secure_save_upload(file)
        
    try:
        from agent.config import get_settings
        analysis_mode = "detect"
        file_sha256 = calculate_file_sha256(temp_path)
        idempotency_key = f"{file_sha256}:{get_settings().pipeline_version}:{analysis_mode}"
        
        svc = AnalysisService(uow=uow)
        try:
            result = svc.analyze_file(
                temp_path, 
                run_triage=False, 
                source_name="api_detect",
                file_sha256=file_sha256,
                idempotency_key=idempotency_key,
                pipeline_version=get_settings().pipeline_version,
                analysis_mode=analysis_mode
            )
        except DuplicateAnalysisError:
            raise HTTPException(status_code=409, detail="Analysis already in progress for this file and mode.")
        det_result = result.detection_result
        ingest_result = result.ingestion_result
        
        # Sanitize output for public endpoint
        safe_incidents = []
        if det_result:
            for i in det_result.incidents:
                safe_incidents.append({
                    "incident_id": i.incident_id,
                    "incident_type": i.incident_type,
                    "severity": i.severity,
                    "confidence": i.confidence,
                    "first_seen": i.first_seen.isoformat() if i.first_seen else None,
                    "last_seen": i.last_seen.isoformat() if i.last_seen else None,
                    "event_count": len(i.event_ids),
                    "signal_count": len(i.signal_ids),
                    "target_count": len(i.target_entities)
                })
                
        safe_signals = []
        if det_result:
            for s in det_result.signals:
                safe_signals.append({
                    "signal_id": s.signal_id,
                    "rule_name": s.rule_name,
                    "severity": s.severity,
                    "confidence": s.confidence,
                    "event_count": len(s.event_ids),
                    "target_count": len(s.target_entities)
                })
                
        return {
            "reused": getattr(result, "reused", False),
            "job_id": getattr(result, "job_id", None),
            "ingestion": {
                "total_records": ingest_result.metrics.total_records if ingest_result else 0,
                "parsed_records": ingest_result.metrics.parsed_records if ingest_result else 0,
                "failed_records": ingest_result.metrics.failed_records if ingest_result else 0,
                "unsupported_records": ingest_result.metrics.unsupported_records if ingest_result else 0
            },
            "detection": {
                "eligible_events": det_result.metrics.eligible_events if det_result else 0,
                "skipped_events": det_result.metrics.skipped_events if det_result else 0,
                "duplicate_events": getattr(det_result.metrics, 'duplicate_event_count', 0) if det_result else 0,
                "signal_count": det_result.metrics.signal_count if det_result else 0,
                "suppressed_signal_count": det_result.metrics.suppressed_signal_count if det_result else 0,
                "incident_count": det_result.metrics.incident_count if det_result else 0,
                "merge_count": getattr(det_result.metrics, 'merge_count', 0) if det_result else 0,
                "duration_ms": det_result.metrics.duration_ms if det_result else 0
            },
            "incidents": safe_incidents,
            "signals_summary": safe_signals,
            "warnings": det_result.warnings if det_result else []
        }
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        import logging
        logging.error(f"Error in /detect/file: {type(e).__name__} - {str(e)}", exc_info=False)
        raise HTTPException(status_code=500, detail="internal_error")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.post("/analyze/file")
async def analyze_file(file: UploadFile = File(...), uow: UnitOfWork = Depends(get_uow)):
    """
    Analyze a raw JSONL log file, performing full ingestion, filtering, correlation, and LLM triage.
    """
    from agent.application.analysis_service import AnalysisService
    from agent.application.errors import DuplicateAnalysisError
    temp_path = await secure_save_upload(file)
        
    try:
        from agent.config import get_settings
        analysis_mode = "analyze"
        file_sha256 = calculate_file_sha256(temp_path)
        idempotency_key = f"{file_sha256}:{get_settings().pipeline_version}:{analysis_mode}"
        
        svc = AnalysisService(uow=uow)
        try:
            result = svc.analyze_file(
                temp_path, 
                run_triage=True, 
                source_name="api_analyze",
                file_sha256=file_sha256,
                idempotency_key=idempotency_key,
                pipeline_version=get_settings().pipeline_version,
                analysis_mode=analysis_mode
            )
        except DuplicateAnalysisError:
            raise HTTPException(status_code=409, detail="Analysis already in progress for this file and mode.")
        
        incident_summaries = []
        for inc_state in result.incidents:
            incident_id = inc_state.get('incident_id')
            
            incident_summaries.append({
                "incident_id": incident_id,
                "triage_verdict": inc_state.get('triage_verdict'),
                "incident_type": inc_state.get('incident_type'),
                "severity": inc_state.get('severity'),
                "confidence_score": inc_state.get('confidence_score'),
                "mitre_techniques": inc_state.get('mitre_techniques', []),
                "report_status": "Generated" if inc_state.get('final_report') else "Not Generated"
            })
            
        return {
            "reused": getattr(result, "reused", False),
            "job_id": getattr(result, "job_id", None),
            "ingestion_metrics": result.ingestion_result.metrics.model_dump() if result.ingestion_result else {},
            "filtered_events": len(result.event_map),
            "incidents_generated": len(incident_summaries),
            "incidents": incident_summaries
        }
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        import logging
        logging.error(f"Error in /analyze/file: {type(e).__name__} - {str(e)}", exc_info=False)
        raise HTTPException(status_code=500, detail="internal_error")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.get("/incident/{incident_id}/report")
def get_incident_report(incident_id: str):
    from agent.persistence.unit_of_work import UnitOfWork
    
    uow = UnitOfWork()
    with uow:
        incident = uow.incidents.get(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found.")
            
        if not incident.reports:
            raise HTTPException(status_code=404, detail="Report not generated yet.")
            
        report = incident.reports[-1]
        
        # Legacy format expected by the frontend
        return {
            "incident_id": incident_id,
            "triage_verdict": incident.triage_runs[-1].verdict if incident.triage_runs else None,
            "incident_type": incident.incident_type,
            "entities": report.entities,
            "validated_evidence": [], # Would need to reconstruct from DB if needed
            "recommended_actions": report.recommended_actions,
            "mitre_techniques": report.mitre_techniques,
            "final_report_markdown": report.content
        }

if __name__ == "__main__":
    print("Starting Agentic SOC API Server on http://localhost:8000")
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
