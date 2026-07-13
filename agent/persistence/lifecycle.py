from agent.persistence.orm_models import Incident, AuditEvent
from datetime import datetime, timezone
from typing import Optional
from fastapi import HTTPException

class IncidentLifecycle:
    # Full lifecycle: new -> triaged -> needs_review -> assigned -> investigating -> confirmed -> false_positive -> resolved -> closed -> reopened
    VALID_TRANSITIONS = {
        "new": ["triaged", "closed", "needs_review"],
        "triaged": ["investigating", "assigned", "needs_review", "resolved", "false_positive"],
        "needs_review": ["assigned", "investigating", "triaged"],
        "assigned": ["investigating"],
        "investigating": ["confirmed", "resolved", "false_positive"],
        "confirmed": ["resolved"],
        "resolved": ["closed", "reopened"],
        "false_positive": ["closed", "reopened"],
        "closed": ["reopened"],
        "reopened": ["investigating", "assigned", "needs_review"]
    }

    @staticmethod
    def transition(incident: Incident, new_status: str, actor: str = "system", details: Optional[dict] = None) -> Optional[AuditEvent]:
        old_status = str(incident.status)
        
        if old_status == new_status:
            # no-op
            return None
            
        allowed = IncidentLifecycle.VALID_TRANSITIONS.get(old_status, [])
        if new_status not in allowed:
            raise HTTPException(
                status_code=409, 
                detail={
                    "code": "invalid_incident_transition", 
                    "message": f"Cannot transition from {old_status} to {new_status}"
                }
            )
            
        incident.status = new_status # type: ignore
        # Optimistic concurrency check handled in service/repo if version needed, else just increment version
        incident.version = (incident.version or 1) + 1 # type: ignore
        
        audit = AuditEvent(
            incident_id=incident.incident_id,
            action="status_change",
            old_status=old_status,
            new_status=new_status,
            actor=actor,
            details=details or {},
            timestamp=datetime.now(timezone.utc)
        )
        incident.audit_events.append(audit)
        
        return audit
