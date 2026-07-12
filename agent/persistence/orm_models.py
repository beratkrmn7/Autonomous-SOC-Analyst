from sqlalchemy import Column, String, Integer, Float, DateTime, Boolean, JSON, ForeignKey, Table
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from agent.persistence.database import Base

class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"
    
    id = Column(String, primary_key=True)
    source_name = Column(String, index=True)
    input_format = Column(String)
    started_at = Column(DateTime(timezone=True), default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    total_records = Column(Integer, default=0)
    parsed_records = Column(Integer, default=0)
    failed_records = Column(Integer, default=0)
    unsupported_records = Column(Integer, default=0)
    
    duration_ms = Column(Integer, default=0)
    parser_counts = Column(JSON, default=dict)
    error_counts = Column(JSON, default=dict)

class CanonicalEvent(Base):
    __tablename__ = "canonical_events"
    
    event_id = Column(String, primary_key=True)
    job_id = Column(String, ForeignKey("ingestion_jobs.id"), nullable=True, index=True)
    source_name = Column(String, index=True)
    parser_name = Column(String)
    timestamp = Column(DateTime(timezone=True), index=True)
    
    raw_message = Column(String)
    original_log = Column(JSON)
    normalized_fields = Column(JSON)
    
    src_ip = Column(String, index=True, nullable=True)
    dst_ip = Column(String, index=True, nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    action = Column(String, nullable=True)
    user = Column(String, index=True, nullable=True)

class DetectionSignal(Base):
    __tablename__ = "detection_signals"
    
    signal_id = Column(String, primary_key=True)
    rule_id = Column(String, index=True)
    rule_name = Column(String)
    signal_type = Column(String)
    severity = Column(String)
    confidence = Column(Float)
    created_at = Column(DateTime(timezone=True), default=func.now())
    
    metrics = Column(JSON, default=dict)
    mitre_techniques = Column(JSON, default=list)
    target_entities = Column(JSON, default=list)
    
    # Associated events via secondary or json? JSON for simple list since we might not query via event
    event_ids = Column(JSON, default=list)

class Incident(Base):
    __tablename__ = "incidents"
    
    incident_id = Column(String, primary_key=True)
    title = Column(String)
    incident_type = Column(String)
    incident_family = Column(String)
    status = Column(String, index=True, default="new")
    
    severity = Column(String)
    confidence = Column(Float)
    
    first_seen = Column(DateTime(timezone=True))
    last_seen = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    
    primary_entity = Column(String, index=True)
    target_entities = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)
    metrics = Column(JSON, default=dict)
    
    events = relationship("IncidentEvent", back_populates="incident", cascade="all, delete-orphan")
    signals = relationship("IncidentSignal", back_populates="incident", cascade="all, delete-orphan")
    triage_runs = relationship("TriageRun", back_populates="incident", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="incident", cascade="all, delete-orphan")
    audit_events = relationship("AuditEvent", back_populates="incident", cascade="all, delete-orphan")

class IncidentEvent(Base):
    __tablename__ = "incident_events"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String, ForeignKey("incidents.incident_id"), index=True)
    event_id = Column(String, index=True)
    is_context = Column(Boolean, default=False)
    
    incident = relationship("Incident", back_populates="events")

class IncidentSignal(Base):
    __tablename__ = "incident_signals"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String, ForeignKey("incidents.incident_id"), index=True)
    signal_id = Column(String, ForeignKey("detection_signals.signal_id"), index=True)
    
    incident = relationship("Incident", back_populates="signals")

class TriageRun(Base):
    __tablename__ = "triage_runs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String, ForeignKey("incidents.incident_id"), index=True)
    started_at = Column(DateTime(timezone=True), default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    verdict = Column(String, nullable=True)
    severity = Column(String, nullable=True)
    confidence_score = Column(Float, nullable=True)
    incident_type = Column(String, nullable=True)
    
    iteration_count = Column(Integer, default=0)
    messages = Column(JSON, default=list)
    search_history = Column(JSON, default=list)
    errors = Column(JSON, default=list)
    
    incident = relationship("Incident", back_populates="triage_runs")
    evidence_items = relationship("EvidenceItem", back_populates="triage_run", cascade="all, delete-orphan")

class EvidenceItem(Base):
    __tablename__ = "evidence_items"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    triage_run_id = Column(Integer, ForeignKey("triage_runs.id"), index=True)
    event_id = Column(String)
    quote = Column(String)
    reason = Column(String)
    source = Column(String)
    original_fields = Column(JSON)
    correlation_context = Column(JSON)
    
    triage_run = relationship("TriageRun", back_populates="evidence_items")

class Report(Base):
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String, ForeignKey("incidents.incident_id"), index=True)
    generated_at = Column(DateTime(timezone=True), default=func.now())
    
    content = Column(String)
    entities = Column(JSON, default=dict)
    recommended_actions = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)
    
    incident = relationship("Incident", back_populates="reports")

class AuditEvent(Base):
    __tablename__ = "audit_events"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String, ForeignKey("incidents.incident_id"), index=True)
    timestamp = Column(DateTime(timezone=True), default=func.now())
    
    action = Column(String)
    old_status = Column(String, nullable=True)
    new_status = Column(String, nullable=True)
    actor = Column(String, default="system")
    details = Column(JSON, default=dict)
    
    incident = relationship("Incident", back_populates="audit_events")

# Also need LogSource just in case
class LogSource(Base):
    __tablename__ = "log_sources"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    source_name = Column(String, unique=True, index=True)
    first_seen = Column(DateTime(timezone=True), default=func.now())
    last_seen = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    total_events = Column(Integer, default=0)
