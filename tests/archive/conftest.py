from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import sessionmaker

from agent.application.archive import ArchiveService
from agent.archive.storage import LocalArchiveStore
from agent.config import Settings
from agent.persistence.orm_models import (
    AuditEvent,
    Base,
    CanonicalEvent,
    DetectionSignal,
    EvidenceItem,
    Incident,
    IncidentEvent,
    IncidentSignal,
    IngestionJob,
    Report,
    RetentionHold,
    TriageRun,
)
from agent.persistence.unit_of_work import UnitOfWork


NOW = datetime(2026, 7, 16, 15, 0, tzinfo=timezone.utc)
ARCHIVE_ID = "ARC-0123456789abcdef0123456789abcdef"
SECRETS = (
    "Authorization: Bearer super-secret-token",
    "api_key=private-api-key",
    "eyJhbGciOiJSUzI1NiJ9.cHJpdmF0ZQ.signature",
    "postgresql://admin:private@db.internal/soc",
    "redis://:private@redis.internal/0",
    "C:/private/staging/job.upload",
    "provider prompt secret",
    "raw exception secret",
)


@dataclass(frozen=True)
class ArchiveEnvironment:
    settings: Settings
    session_factory: sessionmaker
    engine: Engine
    store: LocalArchiveStore

    def service(self, archive_id: str = ARCHIVE_ID) -> ArchiveService:
        return ArchiveService(
            lambda: UnitOfWork(self.session_factory),
            self.store,
            self.settings,
            clock=lambda: NOW,
            archive_id_factory=lambda: archive_id,
        )


def make_environment(root: Path) -> ArchiveEnvironment:
    root.mkdir(parents=True, exist_ok=True)
    archive_root = root / "archives"
    staging_root = root / "staging-private"
    settings = Settings(
        _env_file=None,
        app_env="test",
        database_url=f"sqlite:///{root / 'archive.db'}",
        staging_dir=str(staging_root),
        retention_archive_root=str(archive_root),
        retention_archive_batch_size=2,
        groq_api_key="private-groq-key",
    )
    engine = create_engine(
        settings.database_url,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return ArchiveEnvironment(
        settings,
        factory,
        engine,
        LocalArchiveStore(str(archive_root)),
    )


@pytest.fixture
def archive_env(tmp_path) -> ArchiveEnvironment:
    environment = make_environment(tmp_path)
    yield environment
    environment.engine.dispose()


def seed_archive_graph(environment: ArchiveEnvironment) -> None:
    old_event = CanonicalEvent(
        event_id="event-old-candidate",
        source_name="firewall",
        parser_name=SECRETS[3],
        timestamp=NOW - timedelta(days=60),
        safe_message_excerpt=SECRETS[0],
    )
    young_event = CanonicalEvent(
        event_id="event-young-dependency",
        source_name="firewall",
        parser_name="cef",
        timestamp=NOW - timedelta(days=5),
        safe_message_excerpt=SECRETS[1],
    )
    held_event = CanonicalEvent(
        event_id="event-held",
        timestamp=NOW - timedelta(days=60),
        safe_message_excerpt=SECRETS[2],
    )
    old_signal = DetectionSignal(
        signal_id="signal-old-candidate",
        rule_id="rule-old",
        rule_name=SECRETS[4],
        signal_type="detection",
        severity="high",
        confidence=0.8,
        created_at=NOW - timedelta(days=120),
        metrics={"secret": SECRETS[3]},
    )
    young_signal = DetectionSignal(
        signal_id="signal-young-dependency",
        rule_id="rule-young",
        rule_name="Young signal",
        signal_type="detection",
        severity="low",
        confidence=0.4,
        created_at=NOW - timedelta(days=5),
        suppression_reason=SECRETS[4],
    )
    old_incident = Incident(
        incident_id="incident-old-candidate",
        title=SECRETS[0],
        status="resolved",
        severity="high",
        confidence=0.8,
        created_at=NOW - timedelta(days=520),
        updated_at=NOW - timedelta(days=500),
        review_reason=SECRETS[5],
        metrics={"secret": SECRETS[6]},
    )
    young_incident = Incident(
        incident_id="incident-young-dependency",
        title="Recently resolved incident",
        status="resolved",
        severity="low",
        confidence=0.5,
        created_at=NOW - timedelta(days=10),
        updated_at=NOW - timedelta(days=5),
    )
    active_incident = Incident(
        incident_id="incident-needs-review",
        title="Needs review",
        status="needs_review",
        severity="critical",
        confidence=0.9,
        created_at=NOW - timedelta(days=520),
        updated_at=NOW - timedelta(days=500),
    )
    completed_job = IngestionJob(
        id="job-old-candidate",
        source_name=SECRETS[5],
        original_filename=SECRETS[0],
        status="completed",
        created_at=NOW - timedelta(days=130),
        updated_at=NOW - timedelta(days=120),
        completed_at=NOW - timedelta(days=120),
        error_counts={"secret": SECRETS[7]},
    )
    queued_job = IngestionJob(
        id="job-queued-protected",
        status="queued",
        created_at=NOW - timedelta(days=130),
        completed_at=NOW - timedelta(days=120),
        next_retry_at=NOW + timedelta(hours=1),
    )
    processing_job = IngestionJob(
        id="job-processing-protected",
        status="processing",
        created_at=NOW - timedelta(days=130),
        completed_at=NOW - timedelta(days=120),
        lease_expires_at=NOW + timedelta(minutes=5),
    )
    cancel_job = IngestionJob(
        id="job-cancel-requested-protected",
        status="cancel_requested",
        created_at=NOW - timedelta(days=130),
        completed_at=NOW - timedelta(days=120),
    )

    old_incident.events.extend(
        [
            IncidentEvent(event_id=old_event.event_id, is_context=False),
            IncidentEvent(event_id=young_event.event_id, is_context=True),
        ]
    )
    old_incident.signals.extend(
        [
            IncidentSignal(signal_id=old_signal.signal_id),
            IncidentSignal(signal_id=young_signal.signal_id),
        ]
    )
    active_incident.events.append(IncidentEvent(event_id=held_event.event_id))
    completed_job.events.extend([old_event, young_event])
    completed_job.signals.extend([old_signal, young_signal])
    completed_job.incidents.extend([old_incident, young_incident])

    triage = TriageRun(
        triage_run_id="triage-dependency",
        job=completed_job,
        incident=old_incident,
        started_at=NOW - timedelta(days=500),
        completed_at=NOW - timedelta(days=499),
        status="completed",
        messages=[{"secret": SECRETS[6]}],
        errors=[SECRETS[7]],
    )
    evidence = EvidenceItem(
        evidence_id="evidence-dependency",
        job=completed_job,
        incident_id=old_incident.incident_id,
        triage_run=triage,
        event_id=young_event.event_id,
        quote=SECRETS[0],
        reason="supports",
        source="event",
        original_fields={"secret": SECRETS[1]},
    )
    report = Report(
        report_id="report-dependency",
        job=completed_job,
        incident=old_incident,
        triage_run_id=None,
        generated_at=NOW - timedelta(days=499),
        format="markdown",
        content=SECRETS[6],
    )
    old_audit = AuditEvent(
        audit_event_id="audit-old-candidate",
        incident=old_incident,
        timestamp=NOW - timedelta(days=500),
        event_type="status_transition",
        entity_type="incident",
        entity_id=old_incident.incident_id,
        action="status_change",
        details={"secret": SECRETS[7]},
        old_values_json={"secret": SECRETS[2]},
    )
    hold = RetentionHold(
        hold_id="hold-event",
        entity_type="canonical_event",
        entity_id=held_event.event_id,
        reason="Approved investigation hold",
        created_at=NOW - timedelta(days=70),
    )
    with environment.session_factory() as session:
        session.add_all(
            [
                old_event,
                young_event,
                held_event,
                old_signal,
                young_signal,
                old_incident,
                young_incident,
                active_incident,
                completed_job,
                queued_job,
                processing_job,
                cancel_job,
                triage,
                evidence,
                report,
                old_audit,
                hold,
            ]
        )
        session.commit()
