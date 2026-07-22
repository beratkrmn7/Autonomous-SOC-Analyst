from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from agent.application.analysis_service import AnalysisService
from agent.application.models import AnalysisResult
from agent.config import Settings
from agent.detection.models import (
    DetectionMetrics,
    DetectionResult,
    DetectionSignal,
    IncidentBundle,
)
from agent.ingestion.models import IngestionMetrics, IngestionResult, InputFormat
from agent.persistence.database import Base
from agent.persistence.exceptions import CanonicalEventIdentityConflictError
from agent.persistence.mappers import DataMapper
from agent.persistence.orm_models import (
    CanonicalEvent,
    DetectionSignal as OrmDetectionSignal,
    Incident,
    IngestionJob,
    SearchIndexOutbox,
)
from agent.persistence.unit_of_work import UnitOfWork
from agent.schema import CanonicalLogEvent
from agent.triage.guardrails import FirewallExposureFacts, derive_incident_facts
from agent.triage.models import TriageIncidentContext


NOW = datetime(2026, 7, 10, 6, 0, tzinfo=timezone.utc)


@pytest.fixture
def session_factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    yield factory
    engine.dispose()


def _event(event_id: str, *, enriched: bool) -> CanonicalLogEvent:
    values = dict(
        event_id=event_id,
        timestamp=NOW,
        src_ip="198.51.100.17",
        dst_ip="203.0.113.25",
        src_port=49152,
        dst_port=6379,
        protocol="TCP",
        action="pass",
        parser_name="pf_firewall",
        parser_version="2.2.0",
        parse_status="success",
        source_name="firewall.json",
        source_line=7 if event_id == "event-primary" else 8,
        raw_record_hash=("a" if event_id == "event-primary" else "b") * 64,
        safe_message_excerpt="PASS TCP bounded excerpt",
    )
    if enriched:
        values.update(
            action_reason="policy match",
            tcp_flags="SYN,ACK",
            inbound_interface="wan0",
            outbound_interface="lan0",
            inbound_zone="wan1-zone",
            outbound_zone="internal-zone",
            source_fqdns=["source.example.test"],
            destination_fqdns=["target.example.test"],
            bytes=4096,
            packets=8,
            duration_ms=1500,
            nat_type="dnat",
            translated_dst_ip="10.0.0.25",
            translated_dst_port=6379,
            parser_metadata={
                "source_timezone_offset": "+03:00",
                "tcp_flag_tokens": ["SYN", "ACK"],
                "unknown_secret": "must-not-persist",
            },
        )
    return CanonicalLogEvent(**values)


def _signal(event_id: str) -> DetectionSignal:
    return DetectionSignal(
        signal_id="signal-upgrade",
        rule_id="critical_management_service_exposed",
        rule_version="1.0.0",
        rule_name="Critical Management Service Exposed",
        signal_type="critical_management_service_exposed",
        signal_family="firewall_exposure",
        severity="high",
        confidence=0.91,
        first_seen=NOW,
        last_seen=NOW,
        event_ids=[event_id],
        primary_entity="10.0.0.25",
        target_entities=["10.0.0.25"],
        metrics={"service": "redis", "source_ip": "198.51.100.17"},
        evidence=[],
        mitre_techniques=[],
        tags=["firewall", "exposure"],
    )


def _incident(signal: DetectionSignal) -> IncidentBundle:
    return IncidentBundle(
        incident_id="incident-upgrade",
        incident_type="critical_management_service_exposed",
        incident_family="firewall_exposure",
        title="Detected Critical Management Service Exposed from 198.51.100.17",
        severity="critical",
        confidence=0.91,
        first_seen=NOW,
        last_seen=NOW,
        primary_entity="10.0.0.25",
        target_entities=["10.0.0.25"],
        signal_ids=[signal.signal_id],
        event_ids=["event-primary"],
        context_event_ids=["event-context"],
        evidence=[],
        metrics={
            "primary_signal_id": signal.signal_id,
            "severity_family": "firewall_exposure",
            "severity_total_event_count": 1,
            "allowed_event_count": 1,
            "blocked_event_count": 0,
            "distinct_destination_count": 1,
            "asset_value": "critical",
            "targeting": "targeted",
            "max_sensitive_ports_per_destination": 1,
        },
        mitre_techniques=[],
        merge_key="firewall_exposure:10.0.0.25:redis",
    )


def _analysis_result(job_id: str) -> AnalysisResult:
    primary = _event("event-primary", enriched=True)
    context = _event("event-context", enriched=True)
    signal = _signal(primary.event_id)
    incident = _incident(signal)
    return AnalysisResult(
        source_name="firewall.json",
        ingestion_result=IngestionResult(
            source_name="firewall.json",
            input_format=InputFormat.JSONL,
            events=[primary, context],
            metrics=IngestionMetrics(total_records=2, parsed_records=2),
        ),
        detection_result=DetectionResult(
            signals=[signal],
            incidents=[incident],
            suppressed_signals=[],
            uncorrelated_event_ids=[],
            metrics=DetectionMetrics(
                total_events=2,
                signal_count=1,
                incident_count=1,
            ),
            warnings=[],
        ),
        event_map={primary.event_id: primary, context.event_id: context},
        signal_map={signal.signal_id: signal},
        incidents=[],
        job_id=job_id,
        pipeline_version="1.1.0",
        analysis_mode="detect",
    )


def test_upgrade_enriches_existing_rows_and_reconciles_incident_once(
    session_factory,
) -> None:
    settings = Settings(_env_file=None, opensearch_enabled=True)
    fresh_signal = _signal("event-primary")
    legacy_signal = DataMapper.domain_signal_to_orm(fresh_signal)
    legacy_signal.rule_name = "Legacy Exposure"
    legacy_signal.rule_version = None
    legacy_signal.signal_family = "legacy_family"
    legacy_signal.severity = "medium"
    legacy_signal.metrics = {}
    legacy_signal.target_entities = []

    legacy_incident = Incident(
        incident_id="incident-upgrade",
        title="Legacy title",
        incident_type="legacy_exposure",
        incident_family="legacy_family",
        status="investigating",
        severity="medium",
        confidence=0.5,
        version=7,
        merge_key="legacy",
        first_seen=NOW,
        last_seen=NOW,
        primary_entity="203.0.113.25",
        target_entities=[],
        mitre_techniques=[],
        metrics={"legacy_metric": True},
    )
    with session_factory() as session:
        old_job = IngestionJob(id="job-old", status="completed", pipeline_version="1.0.0")
        new_job = IngestionJob(id="job-new", status="processing", pipeline_version="1.1.0")
        session.add_all(
            [
                old_job,
                new_job,
                DataMapper.domain_event_to_orm(_event("event-primary", enriched=False)),
                DataMapper.domain_event_to_orm(_event("event-context", enriched=False)),
                legacy_signal,
                legacy_incident,
            ]
        )
        legacy_incident.jobs.append(old_job)
        session.commit()

    service = AnalysisService(
        uow=UnitOfWork(session_factory=session_factory, settings=settings),
        llm_enabled=False,
    )
    result = _analysis_result("job-new")
    service._persist_analysis(result, run_triage=False)

    with session_factory() as session:
        assert session.query(CanonicalEvent).count() == 2
        event_row = session.get(CanonicalEvent, "event-primary")
        assert event_row is not None
        assert event_row.inbound_zone == "wan1-zone"
        assert event_row.outbound_zone == "internal-zone"
        assert event_row.translated_dst_ip == "10.0.0.25"
        assert event_row.translated_dst_port == 6379
        assert event_row.tcp_flags == "SYN,ACK"
        assert event_row.packets == 8
        assert event_row.bytes == 4096
        assert event_row.duration_ms == 1500
        assert event_row.parser_metadata == {
            "source_timezone_offset": "+03:00",
            "tcp_flag_tokens": ["SYN", "ACK"],
        }

        signal_row = session.get(OrmDetectionSignal, "signal-upgrade")
        assert signal_row is not None
        assert signal_row.rule_version == "1.0.0"
        assert signal_row.rule_name == "Critical Management Service Exposed"
        assert signal_row.signal_family == "firewall_exposure"
        assert signal_row.metrics["service"] == "redis"
        assert signal_row.metrics["source_ip"] == "198.51.100.17"

        incident_row = session.get(Incident, "incident-upgrade")
        assert incident_row is not None
        assert incident_row.status == "investigating"
        assert incident_row.version == 8
        assert incident_row.title.startswith("Detected Critical Management")
        assert incident_row.incident_type == "critical_management_service_exposed"
        assert incident_row.incident_family == "firewall_exposure"
        assert incident_row.severity == "critical"
        assert incident_row.primary_entity == "10.0.0.25"
        assert {row.event_id for row in incident_row.events if not row.is_context} == {
            "event-primary"
        }
        assert {row.event_id for row in incident_row.events if row.is_context} == {
            "event-context"
        }
        assert {row.signal_id for row in incident_row.signals} == {"signal-upgrade"}

        hydrated_event = DataMapper.orm_to_domain_event(event_row)
        hydrated_incident = DataMapper.orm_to_domain_incident(incident_row)
        facts = derive_incident_facts(
            TriageIncidentContext(
                incident=hydrated_incident,
                events=[hydrated_event],
                context_events=[],
            ),
            [],
        )
        assert isinstance(facts, FirewallExposureFacts)
        assert facts.effective_destination_ips == ["10.0.0.25"]
        assert facts.nat_event_count == 1
        assert facts.inbound_zones == ["wan1-zone"]
        assert facts.total_packets == 8
        assert facts.total_bytes == 4096
        assert facts.max_duration_ms == 1500

        incident_projection = session.execute(
            select(SearchIndexOutbox)
            .where(
                SearchIndexOutbox.entity_type == "incident",
                SearchIndexOutbox.entity_id == "incident-upgrade",
            )
            .order_by(SearchIndexOutbox.document_version.desc())
        ).scalars().first()
        assert incident_projection is not None
        assert incident_projection.payload["version"] == 8

        event_projection = session.execute(
            select(SearchIndexOutbox).where(
                SearchIndexOutbox.entity_type == "canonical_event",
                SearchIndexOutbox.entity_id == "event-primary",
            )
        ).scalars().one()
        assert event_projection.payload["job_ids"] == ["job-new"]

        signal_projection = session.execute(
            select(SearchIndexOutbox).where(
                SearchIndexOutbox.entity_type == "detection_signal",
                SearchIndexOutbox.entity_id == "signal-upgrade",
            )
        ).scalars().one()
        assert signal_projection.payload["rule_version"] == "1.0.0"
        assert signal_projection.payload["signal_family"] == "firewall_exposure"
        outbox_count = session.query(SearchIndexOutbox).count()

        new_job = session.get(IngestionJob, "job-new")
        new_job.status = "processing"
        session.commit()

    service._persist_analysis(result, run_triage=False)

    with session_factory() as session:
        incident_row = session.get(Incident, "incident-upgrade")
        assert incident_row.version == 8
        assert session.query(SearchIndexOutbox).count() == outbox_count


def test_existing_event_identity_conflict_is_sanitized(session_factory) -> None:
    settings = Settings(_env_file=None, opensearch_enabled=False)
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        job = IngestionJob(id="job-conflict", status="processing")
        uow.ingestion_jobs.add(job)
        existing = DataMapper.domain_event_to_orm(
            _event("event-primary", enriched=False)
        )
        uow.canonical_events.add(existing)
        uow.session.flush()

        conflicting = _event("event-primary", enriched=True).model_copy(
            update={"src_ip": "192.0.2.99"}
        )
        service = AnalysisService(
            uow=UnitOfWork(session_factory=session_factory, settings=settings),
            llm_enabled=False,
        )
        with pytest.raises(
            CanonicalEventIdentityConflictError,
            match="canonical_event_identity_conflict:src_ip",
        ) as caught:
            service._persist_canonical_events(
                uow, job, {conflicting.event_id: conflicting}
            )
        assert "192.0.2.99" not in str(caught.value)
        assert "198.51.100.17" not in str(caught.value)
