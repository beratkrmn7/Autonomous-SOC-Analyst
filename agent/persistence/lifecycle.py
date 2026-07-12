from agent.persistence.orm_models import Incident, AuditEvent
from agent.application.errors import InvalidTransitionError
from datetime import datetime, timezone

class IncidentLifecycle:
    # new -> triaged -> investigating -> resolved/false_positive
    VALID_TRANSITIONS = {
        "new": ["triaged", "closed"],
        "triaged": ["investigating", "resolved", "false_positive"],
        "investigating": ["resolved", "false_positive"],
        "resolved": ["new"], # reopen
        "false_positive": ["new"], # reopen
        "closed": ["new"]
    }

    @staticmethod
    def transition(incident: Incident, new_status: str, actor: str = "system", details: dict = None) -> AuditEvent:
        old_status = incident.status
        
        if old_status == new_status:
            # no-op
            return None
            
        allowed = IncidentLifecycle.VALID_TRANSITIONS.get(old_status, [])
        if new_status not in allowed:
            raise InvalidTransitionError(incident.incident_id, old_status, new_status)
            
        incident.status = new_status
        
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
