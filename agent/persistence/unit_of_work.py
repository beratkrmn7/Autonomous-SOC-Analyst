from typing import Optional
from sqlalchemy.orm import Session
from agent.persistence.database import create_engine_factory, create_session_factory
from agent.config import get_settings
from agent.persistence.repositories import (
    IncidentRepository, AuditEventRepository, IngestionJobRepository,
    CanonicalEventRepository, DetectionSignalRepository, TriageRunRepository,
    EvidenceRepository, ReportRepository
)

class UnitOfWork:
    def __init__(self, session_factory=None):
        if not session_factory:
            # Default to settings-based factory if none provided
            engine = create_engine_factory(get_settings())
            session_factory = create_session_factory(engine)
        self.session_factory = session_factory
        self.session: Optional[Session] = None
        
    def __enter__(self):
        self.session = self.session_factory()
        self.incidents = IncidentRepository(self.session)
        self.audit_events = AuditEventRepository(self.session)
        self.ingestion_jobs = IngestionJobRepository(self.session)
        self.canonical_events = CanonicalEventRepository(self.session)
        self.detection_signals = DetectionSignalRepository(self.session)
        self.triage_runs = TriageRunRepository(self.session)
        self.evidence = EvidenceRepository(self.session)
        self.reports = ReportRepository(self.session)
        return self
        
    def __exit__(self, exc_type, exc_val, traceback):
        if exc_type is not None:
            self.rollback()
        else:
            self.commit()
        if self.session:
            self.session.close()
        
    def commit(self):
        if self.session:
            self.session.commit()
            
    def rollback(self):
        if self.session:
            self.session.rollback()
