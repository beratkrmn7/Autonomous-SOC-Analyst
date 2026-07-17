from sqlalchemy.orm import Session
from agent.persistence.orm_models import (
    ApiCredential, Incident, DetectionSignal, CanonicalEvent,
    TriageRun, EvidenceItem, Report, AuditEvent,
    IngestionJob
)
from agent.persistence.exceptions import RecordNotFoundError
from typing import List

class GenericRepository:
    def __init__(self, session: Session, model_cls):
        self.session = session
        self.model_cls = model_cls
        
    def add(self, entity):
        self.session.add(entity)
        return entity
        
    def get(self, id_val):
        # We assume standard primary key name or use session.get
        return self.session.get(self.model_cls, id_val)

    def get_for_update(self, id_val):
        """Load and lock an existing source row for projection-safe mutation."""
        return self.session.get(self.model_cls, id_val, with_for_update=True)
        
    def get_or_404(self, id_val):
        entity = self.get(id_val)
        if not entity:
            raise RecordNotFoundError(self.model_cls.__name__, str(id_val))
        return entity

    def list(self, skip: int = 0, limit: int = 100):
        return self.session.query(self.model_cls).offset(skip).limit(limit).all()

class IncidentRepository(GenericRepository):
    def __init__(self, session: Session):
        super().__init__(session, Incident)
        
    def get_by_status(self, status: str) -> List[Incident]:
        return self.session.query(Incident).filter(Incident.status == status).all()

class AuditEventRepository(GenericRepository):
    def __init__(self, session: Session):
        super().__init__(session, AuditEvent)
        
    def get_by_incident(self, incident_id: str) -> List[AuditEvent]:
        return self.session.query(AuditEvent).filter(AuditEvent.incident_id == incident_id).order_by(AuditEvent.timestamp.desc()).all()

class IngestionJobRepository(GenericRepository):
    def __init__(self, session: Session):
        super().__init__(session, IngestionJob)


class ApiCredentialRepository(GenericRepository):
    def __init__(self, session: Session):
        super().__init__(session, ApiCredential)

    def get_by_prefix(self, key_prefix: str) -> List[ApiCredential]:
        return (
            self.session.query(ApiCredential)
            .filter(ApiCredential.key_prefix == key_prefix)
            .all()
        )

    def list_for_administration(self) -> List[ApiCredential]:
        return (
            self.session.query(ApiCredential)
            .order_by(ApiCredential.created_at.asc(), ApiCredential.credential_id.asc())
            .all()
        )

class CanonicalEventRepository(GenericRepository):
    def __init__(self, session: Session):
        super().__init__(session, CanonicalEvent)

class DetectionSignalRepository(GenericRepository):
    def __init__(self, session: Session):
        super().__init__(session, DetectionSignal)

class TriageRunRepository(GenericRepository):
    def __init__(self, session: Session):
        super().__init__(session, TriageRun)

class EvidenceRepository(GenericRepository):
    def __init__(self, session: Session):
        super().__init__(session, EvidenceItem)

class ReportRepository(GenericRepository):
    def __init__(self, session: Session):
        super().__init__(session, Report)
