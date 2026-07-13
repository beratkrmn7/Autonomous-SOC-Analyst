from sqlalchemy import Column, String, Integer, Float, DateTime, Boolean, JSON, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from agent.persistence.database import Base

class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"
    
    id = Column(String, primary_key=True)
    source_name = Column(String, index=True)
    original_filename = Column(String, nullable=True)
    file_sha256 = Column(String, nullable=True)
    status = Column(String, default="pending")
    error_code = Column(String, nullable=True)
    input_format = Column(String)
    
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    started_at = Column(DateTime(timezone=True), nullable=True)
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
    parser_version = Column(String, nullable=True)
    
    timestamp = Column(DateTime(timezone=True), index=True)
    observed_at = Column(DateTime(timezone=True), nullable=True)
    
    source_line = Column(Integer, nullable=True)
    raw_record_hash = Column(String, nullable=True)
    safe_message_excerpt = Column(String)
    
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
    rule_version = Column(String, nullable=True)
    signal_family = Column(String, nullable=True)
    signal_type = Column(String)
    severity = Column(String)
    confidence = Column(Float)
    
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=func.now())
    
    suppressed = Column(Boolean, default=False)
    suppression_reason = Column(String, nullable=True)
    
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
    
    version = Column(Integer, default=1)
    merge_key = Column(String, nullable=True)
    review_reason = Column(String, nullable=True)
    
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

from sqlalchemy import UniqueConstraint

class IncidentEvent(Base):
    __tablename__ = "incident_events"
    __table_args__ = (UniqueConstraint('incident_id', 'event_id', name='uq_incident_event'),)
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String, ForeignKey("incidents.incident_id"), index=True)
    event_id = Column(String, index=True)
    is_context = Column(Boolean, default=False)
    
    incident = relationship("Incident", back_populates="events")

class IncidentSignal(Base):
    __tablename__ = "incident_signals"
    __table_args__ = (UniqueConstraint('incident_id', 'signal_id', name='uq_incident_signal'),)
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String, ForeignKey("incidents.incident_id"), index=True)
    signal_id = Column(String, ForeignKey("detection_signals.signal_id"), index=True)
    
    incident = relationship("Incident", back_populates="signals")

class TriageRun(Base):
    __tablename__ = "triage_runs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    triage_run_id = Column(String, nullable=True, unique=True, index=True)
    incident_id = Column(String, ForeignKey("incidents.incident_id"), index=True)
    started_at = Column(DateTime(timezone=True), default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    status = Column(String, default="running")
    provider = Column(String, nullable=True)
    model = Column(String, nullable=True)
    prompt_version = Column(String, nullable=True)
    schema_version = Column(String, nullable=True)
    
    verdict = Column(String, nullable=True)
    severity = Column(String, nullable=True)
    confidence_score = Column(Float, nullable=True)
    incident_type = Column(String, nullable=True)
    review_reason = Column(String, nullable=True)
    
    cache_hit = Column(Boolean, default=False)
    iteration_count = Column(Integer, default=0)
    search_count = Column(Integer, default=0)
    tool_count = Column(Integer, default=0)
    retry_count = Column(Integer, default=0)
    
    latency_ms = Column(Integer, default=0)
    token_usage = Column(JSON, default=dict)
    estimated_cost = Column(Float, default=0.0)
    
    messages = Column(JSON, default=list)
    search_history = Column(JSON, default=list)
    errors = Column(JSON, default=list)
    
    incident = relationship("Incident", back_populates="triage_runs")
    evidence_items = relationship("EvidenceItem", back_populates="triage_run", cascade="all, delete-orphan")

class EvidenceItem(Base):
    __tablename__ = "evidence_items"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    evidence_id = Column(String, nullable=True, unique=True, index=True)
    incident_id = Column(String, ForeignKey("incidents.incident_id"), nullable=True, index=True)
    triage_run_id = Column(Integer, ForeignKey("triage_runs.id"), index=True)
    
    event_id = Column(String)
    quote = Column(String)
    reason = Column(String)
    source = Column(String)
    
    validation_status = Column(String, nullable=True)
    rejection_reason = Column(String, nullable=True)
    
    original_fields = Column(JSON)
    correlation_context = Column(JSON)
    
    triage_run = relationship("TriageRun", back_populates="evidence_items")

class Report(Base):
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(String, nullable=True, unique=True, index=True)
    incident_id = Column(String, ForeignKey("incidents.incident_id"), index=True)
    triage_run_id = Column(Integer, ForeignKey("triage_runs.id"), nullable=True)
    generated_at = Column(DateTime(timezone=True), default=func.now())
    
    format = Column(String, default="markdown")
    content = Column(String)
    content_sha256 = Column(String, nullable=True)
    
    entities = Column(JSON, default=dict)
    recommended_actions = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)
    
    incident = relationship("Incident", back_populates="reports")

class AuditEvent(Base):
    __tablename__ = "audit_events"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    audit_event_id = Column(String, nullable=True, unique=True, index=True)
    incident_id = Column(String, ForeignKey("incidents.incident_id"), index=True)
    timestamp = Column(DateTime(timezone=True), default=func.now())
    
    event_type = Column(String, nullable=True)
    entity_type = Column(String, nullable=True)
    entity_id = Column(String, nullable=True)
    
    action = Column(String)
    old_status = Column(String, nullable=True)
    new_status = Column(String, nullable=True)
    
    actor_type = Column(String, nullable=True)
    actor_id = Column(String, nullable=True)
    actor = Column(String, default="system")
    
    old_values_json = Column(JSON, nullable=True)
    new_values_json = Column(JSON, nullable=True)
    request_id = Column(String, nullable=True)
    
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
