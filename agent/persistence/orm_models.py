from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    Index,
    JSON,
    String,
    Table,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from agent.persistence.database import Base
from agent.security.authorization import Role

ingestion_job_events = Table(
    "ingestion_job_events",
    Base.metadata,
    Column("job_id", String, ForeignKey("ingestion_jobs.id"), primary_key=True),
    Column("event_id", String, ForeignKey("canonical_events.event_id"), primary_key=True)
)

ingestion_job_signals = Table(
    "ingestion_job_signals",
    Base.metadata,
    Column("job_id", String, ForeignKey("ingestion_jobs.id"), primary_key=True),
    Column("signal_id", String, ForeignKey("detection_signals.signal_id"), primary_key=True)
)

ingestion_job_incidents = Table(
    "ingestion_job_incidents",
    Base.metadata,
    Column("job_id", String, ForeignKey("ingestion_jobs.id"), primary_key=True),
    Column("incident_id", String, ForeignKey("incidents.incident_id"), primary_key=True)
)


class ApiCredential(Base):
    __tablename__ = "api_credentials"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'revoked', 'expired')",
            name="ck_api_credentials_status",
        ),
        CheckConstraint(
            "role IN ('viewer', 'analyst', 'service', 'admin')",
            name="ck_api_credentials_role",
        ),
    )

    credential_id = Column(String(45), primary_key=True)
    name = Column(String(120), nullable=False)
    key_prefix = Column(String(32), nullable=False, index=True)
    key_hash = Column(String(64), nullable=False, unique=True)
    status = Column(String(16), nullable=False, default="active", index=True)
    role = Column(
        String(16),
        nullable=False,
        default=Role.SERVICE.value,
        server_default=Role.SERVICE.value,
        index=True,
    )
    created_at = Column(DateTime(timezone=True), nullable=False, default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_by_type = Column(String(32), nullable=False)
    created_by_id = Column(String(128), nullable=False)
    description = Column(String(500), nullable=True)
    version = Column(Integer, nullable=False, default=1)

    __mapper_args__ = {"version_id_col": version}

class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"
    __table_args__ = (
        Index("ix_ingestion_jobs_created_id", "created_at", "id"),
        Index("ix_ingestion_jobs_status_created", "status", "created_at"),
        Index("ix_ingestion_jobs_mode_created", "analysis_mode", "created_at"),
        Index("ix_ingestion_jobs_completed_id", "completed_at", "id"),
        Index("ix_ingestion_jobs_source_created", "source_name", "created_at"),
    )
    
    id = Column(String, primary_key=True)
    idempotency_key = Column(String, unique=True, index=True, nullable=True)
    source_name = Column(String, index=True)
    original_filename = Column(String, nullable=True)
    file_sha256 = Column(String, nullable=True)
    pipeline_version = Column(String, nullable=True)
    analysis_mode = Column(String, nullable=True)
    status = Column(String, default="pending")
    error_code = Column(String, nullable=True)
    
    # Metrics
    semantically_invalid_records = Column(Integer, default=0)
    skipped_records = Column(Integer, default=0)
    bytes_read = Column(Integer, default=0)
    
    input_format = Column(String)
    reused_count = Column(Integer, default=0)
    last_requested_at = Column(DateTime(timezone=True), nullable=True)
    
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    queued_at = Column(DateTime(timezone=True), nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Background job specific fields
    attempt_count = Column(Integer, default=0)
    worker_id = Column(String, nullable=True)
    next_retry_at = Column(DateTime(timezone=True), nullable=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    last_attempt_at = Column(DateTime(timezone=True), nullable=True)
    cancel_requested_at = Column(DateTime(timezone=True), nullable=True)
    cancelled_at = Column(DateTime(timezone=True), nullable=True)
    cancel_reason_code = Column(String, nullable=True)
    cancel_requested_by = Column(String, nullable=True)
    
    total_records = Column(Integer, default=0)
    parsed_records = Column(Integer, default=0)
    failed_records = Column(Integer, default=0)
    unsupported_records = Column(Integer, default=0)
    
    duration_ms = Column(Integer, default=0)
    parser_counts = Column(JSON, default=dict)
    error_counts = Column(JSON, default=dict)
    
    events = relationship("CanonicalEvent", secondary=ingestion_job_events, back_populates="jobs")
    signals = relationship("DetectionSignal", secondary=ingestion_job_signals, back_populates="jobs")
    incidents = relationship("Incident", secondary=ingestion_job_incidents, back_populates="jobs")
    triage_runs = relationship("TriageRun", back_populates="job", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="job", cascade="all, delete-orphan")
    evidence_items = relationship("EvidenceItem", back_populates="job", cascade="all, delete-orphan")

class CanonicalEvent(Base):
    __tablename__ = "canonical_events"
    __table_args__ = (
        Index("ix_canonical_events_timestamp_id", "timestamp", "event_id"),
        Index("ix_canonical_events_src_timestamp", "src_ip", "timestamp"),
        Index("ix_canonical_events_dst_timestamp", "dst_ip", "timestamp"),
        Index("ix_canonical_events_source_timestamp", "source_name", "timestamp"),
    )
    
    event_id = Column(String, primary_key=True)
    
    jobs = relationship("IngestionJob", secondary=ingestion_job_events, back_populates="events")
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
    __table_args__ = (
        Index("ix_detection_signals_created_id", "created_at", "signal_id"),
        Index("ix_detection_signals_rule_created", "rule_id", "created_at"),
        Index("ix_detection_signals_severity_created", "severity", "created_at"),
        Index("ix_detection_signals_first_seen_id", "first_seen", "signal_id"),
        Index("ix_detection_signals_last_seen_id", "last_seen", "signal_id"),
        Index("ix_detection_signals_suppressed_created", "suppressed", "created_at"),
    )
    
    signal_id = Column(String, primary_key=True)
    
    jobs = relationship("IngestionJob", secondary=ingestion_job_signals, back_populates="signals")
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
    __table_args__ = (
        Index("ix_incidents_created_id", "created_at", "incident_id"),
        Index("ix_incidents_status_created", "status", "created_at"),
        Index("ix_incidents_severity_created", "severity", "created_at"),
        Index("ix_incidents_type_created", "incident_type", "created_at"),
        Index("ix_incidents_first_seen_id", "first_seen", "incident_id"),
        Index("ix_incidents_last_seen_id", "last_seen", "incident_id"),
    )
    
    incident_id = Column(String, primary_key=True)
    
    jobs = relationship("IngestionJob", secondary=ingestion_job_incidents, back_populates="incidents")
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
    job_id = Column(String, ForeignKey("ingestion_jobs.id"), nullable=True, index=True)
    job = relationship("IngestionJob", back_populates="triage_runs")
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
    job_id = Column(String, ForeignKey("ingestion_jobs.id"), nullable=True, index=True)
    job = relationship("IngestionJob", back_populates="evidence_items")
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
    job_id = Column(String, ForeignKey("ingestion_jobs.id"), nullable=True, index=True)
    job = relationship("IngestionJob", back_populates="reports")
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


class RetentionArchiveRun(Base):
    __tablename__ = "retention_archive_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('creating', 'completed', 'verified', 'failed')",
            name="ck_retention_archive_runs_status",
        ),
        CheckConstraint(
            "candidate_record_count >= 0 AND dependency_record_count >= 0 "
            "AND total_record_count >= 0",
            name="ck_retention_archive_runs_nonnegative_counts",
        ),
        CheckConstraint(
            "total_record_count = candidate_record_count + dependency_record_count",
            name="ck_retention_archive_runs_total_count",
        ),
        CheckConstraint(
            "manifest_sha256 IS NULL OR length(manifest_sha256) = 64",
            name="ck_retention_archive_runs_manifest_sha256",
        ),
        Index("ix_retention_archive_runs_status", "status"),
        Index("ix_retention_archive_runs_archive_as_of", "archive_as_of"),
    )

    archive_id = Column(String(45), primary_key=True)
    policy_version = Column(String(32), nullable=False)
    schema_version = Column(String(64), nullable=False)
    status = Column(String(16), nullable=False, default="creating")
    archive_as_of = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    storage_key = Column(String(64), nullable=False, unique=True)
    manifest_sha256 = Column(String(64), nullable=True)
    candidate_record_count = Column(Integer, nullable=False, default=0)
    dependency_record_count = Column(Integer, nullable=False, default=0)
    total_record_count = Column(Integer, nullable=False, default=0)
    sanitized_error_code = Column(String(64), nullable=True)


class RetentionCleanupRun(Base):
    __tablename__ = "retention_cleanup_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed')",
            name="ck_retention_cleanup_runs_status",
        ),
        CheckConstraint(
            "attempt_count >= 0 AND deleted_record_count >= 0 "
            "AND protected_record_count >= 0 AND missing_record_count >= 0 "
            "AND skipped_record_count >= 0",
            name="ck_retention_cleanup_runs_nonnegative_counts",
        ),
        CheckConstraint("version >= 1", name="ck_retention_cleanup_runs_version"),
        CheckConstraint(
            "length(manifest_sha256) = 64",
            name="ck_retention_cleanup_runs_manifest_sha256",
        ),
        Index(
            "ix_retention_cleanup_runs_status_lease",
            "status",
            "lease_expires_at",
        ),
    )

    cleanup_run_id = Column(String(45), primary_key=True)
    archive_id = Column(
        String(45),
        ForeignKey("retention_archive_runs.archive_id"),
        nullable=False,
        unique=True,
    )
    status = Column(String(16), nullable=False, default="pending")
    policy_version = Column(String(32), nullable=False)
    archive_schema_version = Column(String(64), nullable=False)
    manifest_sha256 = Column(String(64), nullable=False)
    archive_as_of = Column(DateTime(timezone=True), nullable=False)
    archive_snapshot = Column(JSON, nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    current_phase = Column(String(32), nullable=False, default="pending")
    current_entity_type = Column(String(32), nullable=True)
    lease_owner = Column(String(64), nullable=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    attempt_count = Column(Integer, nullable=False, default=0)
    deleted_record_count = Column(Integer, nullable=False, default=0)
    protected_record_count = Column(Integer, nullable=False, default=0)
    missing_record_count = Column(Integer, nullable=False, default=0)
    skipped_record_count = Column(Integer, nullable=False, default=0)
    sanitized_error_code = Column(String(64), nullable=True)
    version = Column(Integer, nullable=False, default=1)


class RetentionCleanupProgress(Base):
    __tablename__ = "retention_cleanup_progress"
    __table_args__ = (
        CheckConstraint(
            "entity_type IN ('audit_event', 'incident', 'ingestion_job', "
            "'detection_signal', 'canonical_event')",
            name="ck_retention_cleanup_progress_entity_type",
        ),
        CheckConstraint(
            "status IN ('pending', 'running', 'completed')",
            name="ck_retention_cleanup_progress_status",
        ),
        CheckConstraint(
            "scanned_count >= 0 AND deleted_count >= 0 "
            "AND protected_count >= 0 AND missing_count >= 0 "
            "AND skipped_count >= 0",
            name="ck_retention_cleanup_progress_nonnegative_counts",
        ),
    )

    cleanup_run_id = Column(
        String(45),
        ForeignKey("retention_cleanup_runs.cleanup_run_id", ondelete="CASCADE"),
        primary_key=True,
    )
    entity_type = Column(String(32), primary_key=True)
    status = Column(String(16), nullable=False, default="pending")
    last_recorded_at = Column(DateTime(timezone=True), nullable=True)
    last_entity_id = Column(String(512), nullable=True)
    scanned_count = Column(Integer, nullable=False, default=0)
    deleted_count = Column(Integer, nullable=False, default=0)
    protected_count = Column(Integer, nullable=False, default=0)
    missing_count = Column(Integer, nullable=False, default=0)
    skipped_count = Column(Integer, nullable=False, default=0)
    completed_at = Column(DateTime(timezone=True), nullable=True)


class RetentionHold(Base):
    __tablename__ = "retention_holds"
    __table_args__ = (
        CheckConstraint(
            "entity_type IN ('canonical_event', 'detection_signal', "
            "'ingestion_job', 'incident', 'audit_event')",
            name="ck_retention_holds_entity_type",
        ),
        CheckConstraint(
            "length(trim(reason)) > 0",
            name="ck_retention_holds_reason_not_blank",
        ),
        CheckConstraint(
            "expires_at IS NULL OR expires_at > created_at",
            name="ck_retention_holds_expiry_after_creation",
        ),
        Index(
            "ix_retention_holds_entity_active",
            "entity_type",
            "entity_id",
            "released_at",
            "expires_at",
        ),
        Index("ix_retention_holds_expires_at", "expires_at"),
    )

    hold_id = Column(String(45), primary_key=True)
    entity_type = Column(String(32), nullable=False)
    entity_id = Column(String(128), nullable=False)
    reason = Column(String(500), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=True)
    released_at = Column(DateTime(timezone=True), nullable=True)


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

class WorkerHeartbeat(Base):
    __tablename__ = "worker_heartbeats"
    
    worker_id = Column(String, primary_key=True)
    worker_type = Column(String, index=True, nullable=False)
    status = Column(String, default="starting", nullable=False)
    started_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    last_heartbeat_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    current_job_id = Column(String, nullable=True)
    hostname_hash = Column(String, nullable=False)
    version = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now(), nullable=False)

