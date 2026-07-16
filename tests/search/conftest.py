from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agent.api.deps import get_uow
from agent.config import Settings, get_settings
from agent.persistence.database import Base
from agent.persistence.orm_models import (
    CanonicalEvent,
    DetectionSignal,
    EvidenceItem,
    Incident,
    IncidentEvent,
    IncidentSignal,
    IngestionJob,
    Report,
)
from agent.persistence.unit_of_work import UnitOfWork
from server import create_app


SEARCH_SECRET = "search-test-secret-00000000000000000001"
RATE_SECRET = "rate-test-secret-0000000000000000000001"
BASE_TIME = datetime(2026, 1, 15, 12, tzinfo=timezone.utc)


@dataclass
class SearchEnvironment:
    client: TestClient
    session_factory: sessionmaker
    settings: Settings


def make_session_factory(path: Path) -> tuple[sessionmaker, object]:
    engine = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(engine)
    return (
        sessionmaker(autocommit=False, autoflush=False, bind=engine),
        engine,
    )


def make_settings(**overrides) -> Settings:
    values = {
        "app_env": "test",
        "auth_mode": "disabled",
        "llm_enabled": False,
        "rate_limiting_enabled": True,
        "rate_limit_key_secret": RATE_SECRET,
        "search_cursor_secret": SEARCH_SECRET,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def search_env(tmp_path):
    factory, engine = make_session_factory(tmp_path / "search.db")
    settings = make_settings()
    application = create_app(settings)
    application.dependency_overrides[get_settings] = lambda: settings
    application.dependency_overrides[get_uow] = lambda: UnitOfWork(factory)
    with TestClient(application) as client:
        yield SearchEnvironment(client, factory, settings)
    engine.dispose()


def seed_search_data(factory: sessionmaker) -> None:
    with factory() as session:
        jobs = [
            IngestionJob(
                id="job-1",
                idempotency_key="secret-idempotency-1",
                source_name="firewall-a",
                original_filename="safe.json",
                file_sha256="a" * 64,
                pipeline_version="1.0.0",
                analysis_mode="full",
                status="completed",
                created_at=BASE_TIME - timedelta(days=5),
                queued_at=BASE_TIME - timedelta(days=5, minutes=-1),
                started_at=BASE_TIME - timedelta(days=5, minutes=-2),
                completed_at=BASE_TIME - timedelta(days=4),
                attempt_count=1,
                reused_count=0,
                worker_id="private-worker",
                error_counts={"raw": "private"},
            ),
            IngestionJob(
                id="job-2",
                source_name="firewall-b",
                file_sha256="b" * 64,
                pipeline_version="1.1.0",
                analysis_mode="quick",
                status="failed",
                error_code="parser_failed",
                created_at=BASE_TIME - timedelta(days=3),
                queued_at=BASE_TIME - timedelta(days=3, minutes=-1),
                completed_at=BASE_TIME - timedelta(days=2),
                attempt_count=2,
                reused_count=3,
            ),
            IngestionJob(
                id="job-3",
                source_name="firewall-a",
                analysis_mode="full",
                status="cancelled",
                error_code="cancelled_by_user",
                created_at=BASE_TIME - timedelta(days=1),
                queued_at=BASE_TIME - timedelta(days=1, minutes=-1),
                completed_at=BASE_TIME,
                cancelled_at=BASE_TIME,
                attempt_count=0,
                reused_count=1,
            ),
        ]
        events = [
            CanonicalEvent(
                event_id="event-1",
                source_name="firewall-a",
                parser_name="pf",
                timestamp=BASE_TIME - timedelta(hours=3),
                src_ip="192.0.2.10",
                dst_ip="198.51.100.20",
                src_port=50100,
                dst_port=443,
                protocol="tcp",
                action="allow",
                user="analyst",
                safe_message_excerpt="Allowed documentation traffic",
                raw_record_hash="private-hash",
            ),
            CanonicalEvent(
                event_id="event-2",
                source_name="firewall-b",
                parser_name="cef",
                timestamp=BASE_TIME - timedelta(hours=2),
                src_ip="2001:db8::1",
                dst_ip="203.0.113.50",
                src_port=51000,
                dst_port=22,
                protocol="tcp",
                action="deny",
                safe_message_excerpt="Denied documentation traffic",
            ),
            CanonicalEvent(
                event_id="event-3",
                source_name="firewall-a",
                parser_name="pf",
                timestamp=BASE_TIME - timedelta(hours=1),
                src_ip="192.0.2.30",
                dst_ip="198.51.100.20",
                src_port=53000,
                dst_port=53,
                protocol="udp",
                action="allow",
                safe_message_excerpt="DNS documentation traffic",
            ),
        ]
        signals = [
            DetectionSignal(
                signal_id="signal-1",
                rule_id="rule-ssh",
                rule_name="SSH probe",
                signal_family="network",
                signal_type="probe",
                severity="high",
                confidence=0.9,
                first_seen=BASE_TIME - timedelta(hours=4),
                last_seen=BASE_TIME - timedelta(hours=3),
                created_at=BASE_TIME - timedelta(hours=3),
                suppressed=False,
                mitre_techniques=["T1046"],
            ),
            DetectionSignal(
                signal_id="signal-2",
                rule_id="rule-dns",
                rule_name="DNS notice",
                signal_family="network",
                signal_type="notice",
                severity="low",
                confidence=0.4,
                first_seen=BASE_TIME - timedelta(hours=2),
                last_seen=BASE_TIME - timedelta(hours=1),
                created_at=BASE_TIME - timedelta(hours=1),
                suppressed=True,
                mitre_techniques=["T1071.004"],
            ),
        ]
        incidents = [
            Incident(
                incident_id="incident-1",
                title="SSH activity",
                incident_type="network_probe",
                incident_family="network",
                status="new",
                severity="high",
                confidence=0.9,
                first_seen=BASE_TIME - timedelta(days=4),
                last_seen=BASE_TIME - timedelta(days=3),
                created_at=BASE_TIME - timedelta(days=3),
                primary_entity="192.0.2.10",
                mitre_techniques=["T1046"],
            ),
            Incident(
                incident_id="incident-2",
                title="DNS activity",
                incident_type="dns_notice",
                incident_family="network",
                status="needs_review",
                severity="low",
                confidence=0.4,
                first_seen=BASE_TIME - timedelta(days=2),
                last_seen=BASE_TIME - timedelta(days=1),
                created_at=BASE_TIME - timedelta(days=1),
                primary_entity="2001:db8::1",
                mitre_techniques=["T1071.004"],
            ),
            Incident(
                incident_id="incident-3",
                title="Closed item",
                incident_type="network_probe",
                incident_family="network",
                status="closed",
                severity="high",
                confidence=0.7,
                first_seen=BASE_TIME - timedelta(days=1),
                last_seen=BASE_TIME,
                created_at=BASE_TIME,
                primary_entity="192.0.2.30",
                mitre_techniques=[],
            ),
        ]

        jobs[0].events.extend([events[0], events[1]])
        jobs[1].events.append(events[2])
        jobs[0].signals.append(signals[0])
        jobs[1].signals.append(signals[1])
        jobs[0].incidents.append(incidents[0])
        jobs[1].incidents.append(incidents[1])
        incidents[0].events.append(
            IncidentEvent(event_id="event-1", is_context=False)
        )
        incidents[0].events.append(
            IncidentEvent(event_id="event-2", is_context=True)
        )
        incidents[0].signals.append(IncidentSignal(signal_id="signal-1"))
        incidents[1].signals.append(IncidentSignal(signal_id="signal-2"))
        session.add_all(jobs + events + signals + incidents)
        session.add(
            Report(
                report_id="report-1",
                job_id="job-1",
                incident_id="incident-1",
                content="private report content",
                generated_at=BASE_TIME,
            )
        )
        session.add(
            EvidenceItem(
                evidence_id="evidence-1",
                job_id="job-1",
                incident_id="incident-1",
                event_id="event-1",
                quote="private quote",
                reason="supports",
                source="event",
                validation_status="validated",
            )
        )
        session.commit()


@pytest.fixture
def seeded_env(search_env):
    seed_search_data(search_env.session_factory)
    return search_env
