from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
from pydantic import BaseModel
from agent.api.deps import get_uow
from agent.persistence.unit_of_work import UnitOfWork
from agent.persistence.lifecycle import IncidentLifecycle

router = APIRouter(prefix="/incidents", tags=["incidents"])

class IncidentResponse(BaseModel):
    incident_id: str
    title: str
    incident_type: str
    severity: str
    status: str
    confidence: float
    event_count: int
    signal_count: int

class StatusUpdateRequest(BaseModel):
    status: str
    expected_version: Optional[int] = None
    details: Optional[dict] = None

@router.get("/", response_model=List[IncidentResponse])
def list_incidents(
    status: Optional[str] = None, 
    skip: int = Query(0, ge=0), 
    limit: int = Query(100, ge=1, le=1000), 
    uow: UnitOfWork = Depends(get_uow)
):
    with uow:
        assert uow.session is not None
        query = uow.session.query(uow.incidents.model_cls)
        if status:
            query = query.filter(uow.incidents.model_cls.status == status)
        
        # Deterministic ordering by created_at desc
        query = query.order_by(uow.incidents.model_cls.created_at.desc())
        
        incidents = query.offset(skip).limit(limit).all()
        
        return [
            IncidentResponse(
                incident_id=i.incident_id,
                title=i.title,
                incident_type=i.incident_type,
                severity=i.severity,
                status=i.status,
                confidence=i.confidence,
                event_count=len(i.events),
                signal_count=len(i.signals)
            ) for i in incidents
        ]

@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: str, uow: UnitOfWork = Depends(get_uow)):
    with uow:
        incident = uow.incidents.get(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
            
        return IncidentResponse(
            incident_id=incident.incident_id,
            title=incident.title,
            incident_type=incident.incident_type,
            severity=incident.severity,
            status=incident.status,
            confidence=incident.confidence,
            event_count=len(incident.events),
            signal_count=len(incident.signals)
        )

@router.patch("/{incident_id}/status")
def update_status(incident_id: str, req: StatusUpdateRequest, uow: UnitOfWork = Depends(get_uow)):
    from agent.application.errors import InvalidTransitionError
    
    with uow:
        incident = uow.incidents.get(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
            
        if req.expected_version is not None and incident.version != req.expected_version:
            raise HTTPException(status_code=409, detail=f"Version conflict: expected {req.expected_version}, got {incident.version}")
            
        try:
            IncidentLifecycle.transition(incident, req.status, actor="api_user", details=req.details or {})
            incident.version += 1
            uow.commit()
        except InvalidTransitionError as e:
            raise HTTPException(status_code=409, detail=str(e))
            
        return {"status": "success", "new_status": incident.status, "version": incident.version}

@router.get("/{incident_id}/signals")
def get_signals(incident_id: str, uow: UnitOfWork = Depends(get_uow)):
    with uow:
        incident = uow.incidents.get(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
            
        return [{"signal_id": s.signal_id} for s in incident.signals]

@router.get("/{incident_id}/events")
def get_events(incident_id: str, uow: UnitOfWork = Depends(get_uow)):
    with uow:
        incident = uow.incidents.get(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
            
        return [{"event_id": e.event_id, "is_context": e.is_context} for e in incident.events]

@router.get("/{incident_id}/triage-runs")
def get_triage_runs(incident_id: str, uow: UnitOfWork = Depends(get_uow)):
    with uow:
        incident = uow.incidents.get(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
            
        return [{
            "triage_run_id": r.triage_run_id,
            "status": r.status,
            "verdict": r.verdict,
            "severity": r.severity,
            "started_at": r.started_at,
            "completed_at": r.completed_at
        } for r in incident.triage_runs]

@router.get("/{incident_id}/evidence")
def get_evidence(incident_id: str, uow: UnitOfWork = Depends(get_uow)):
    with uow:
        incident = uow.incidents.get(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
            
        evidence_list = []
        for run in incident.triage_runs:
            for ev in run.evidence_items:
                evidence_list.append({
                    "evidence_id": ev.evidence_id,
                    "triage_run_id": run.triage_run_id,
                    "event_id": ev.event_id,
                    "quote": ev.quote,
                    "reason": ev.reason
                })
        return evidence_list

@router.get("/{incident_id}/report")
def get_report(incident_id: str, uow: UnitOfWork = Depends(get_uow)):
    with uow:
        incident = uow.incidents.get(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
            
        if not incident.reports:
            raise HTTPException(status_code=404, detail="Report not generated yet")
            
        report = incident.reports[-1] # Get latest
        return {
            "incident_id": incident_id,
            "report_id": report.report_id,
            "format": report.format,
            "content": report.content,
            "generated_at": report.generated_at
        }
        
@router.get("/{incident_id}/timeline")
def get_timeline(incident_id: str, uow: UnitOfWork = Depends(get_uow)):
    with uow:
        incident = uow.incidents.get(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
            
        events = incident.audit_events
        
        return [
            {
                "id": e.id,
                "action": e.action,
                "old_status": e.old_status,
                "new_status": e.new_status,
                "actor": e.actor,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "details": e.details
            } for e in sorted(events, key=lambda x: x.timestamp, reverse=True)
        ]
