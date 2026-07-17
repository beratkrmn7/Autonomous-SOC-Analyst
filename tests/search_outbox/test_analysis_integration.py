from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, func, select
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
from agent.ingestion.models import (
    CanonicalLogEvent,
    IngestionMetrics,
    IngestionResult,
    InputFormat,
)
from agent.persistence.database import Base
from agent.persistence.orm_models import IngestionJob, SearchIndexOutbox
from agent.persistence.unit_of_work import UnitOfWork


NOW = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    yield factory
    engine.dispose()


def _settings(*, enabled: bool = True) -> Settings:
    return Settings(_env_file=None, opensearch_enabled=enabled)


def _seed_job(factory, settings: Settings, job_id: str, mode: str) -> None:
    with UnitOfWork(session_factory=factory, settings=settings) as uow:
        uow.session.add(
            IngestionJob(
                id=job_id,
                source_name="firewall",
                analysis_mode=mode,
                pipeline_version="pipeline-v1",
                status="processing",
            )
        )


def _analysis_result(job_id: str, *, triaged: bool = False) -> AnalysisResult:
    primary = CanonicalLogEvent(
        event_id="event-primary",
        timestamp=NOW,
        source_name="firewall",
        parser_name="cef",
        safe_message_excerpt="Authorization: Bearer super-secret-token",
        src_ip="192.0.2.10",
        parse_status="success",
    )
    context = CanonicalLogEvent(
        event_id="event-context",
        timestamp=NOW,
        source_name="firewall",
        parser_name="cef",
        safe_message_excerpt="safe context",
        dst_ip="198.51.100.20",
        parse_status="success",
    )
    signal = DetectionSignal(
        signal_id="signal-1",
        rule_id="rule-1",
        rule_version="v1",
        rule_name="Vertical scan",
        signal_type="scan",
        signal_family="network",
        severity="high",
        confidence=0.91,
        first_seen=NOW,
        last_seen=NOW,
        event_ids=[primary.event_id],
        primary_entity="192.0.2.10",
        target_entities=["198.51.100.20"],
        metrics={"raw_firewall_log": "super-secret-token"},
        evidence=[],
        mitre_techniques=["T1046"],
        tags=["network"],
    )
    incident = IncidentBundle(
        incident_id="incident-1",
        incident_type="port_scan",
        incident_family="network",
        title="Port scan",
        severity="high",
        confidence=0.91,
        first_seen=NOW,
        last_seen=NOW,
        primary_entity="192.0.2.10",
        target_entities=["198.51.100.20"],
        signal_ids=[signal.signal_id],
        event_ids=[primary.event_id],
        context_event_ids=[context.event_id],
        evidence=[],
        metrics={"secret": "raw firewall log"},
        mitre_techniques=["T1046"],
        merge_key="network:192.0.2.10",
    )
    triage_states = []
    if triaged:
        triage_states = [
            {
                "incident_id": incident.incident_id,
                "triage_verdict": "confirmed_incident",
                "severity": "high",
                "confidence_score": 0.97,
                "incident_type": "port_scan",
                "iteration_count": 1,
                "safe_triage_input": {
                    "candidate_evidence": [
                        {
                            "evidence_id": "evidence-1",
                            "event_id": primary.event_id,
                            "quote": "raw firewall log super-secret-token",
                            "reason": "validated",
                            "source": "firewall",
                        }
                    ]
                },
                "validated_evidence": [{"evidence_id": "evidence-1"}],
                "rejected_evidence": [],
                "final_report": "full report super-secret-token",
                "entities": {"private": "super-secret-token"},
                "recommended_actions": ["investigate"],
                "mitre_techniques": ["T1046"],
            }
        ]
    return AnalysisResult(
        source_name="firewall",
        ingestion_result=IngestionResult(
            source_name="firewall",
            input_format=InputFormat.JSONL,
            events=[primary, context],
            metrics=IngestionMetrics(total_records=2, parsed_records=2),
        ),
        detection_result=DetectionResult(
            signals=[signal],
            incidents=[incident],
            suppressed_signals=[],
            uncorrelated_event_ids=[],
            warnings=[],
            metrics=DetectionMetrics(
                total_events=2,
                signal_count=1,
                incident_count=1,
                duration_ms=1.0,
            ),
        ),
        event_map={primary.event_id: primary, context.event_id: context},
        signal_map={signal.signal_id: signal},
        incidents=triage_states,
        job_id=job_id,
        analysis_mode="analyze" if triaged else "detect",
        pipeline_version="pipeline-v1",
    )


def _rows(factory) -> list[SearchIndexOutbox]:
    with factory() as session:
        return list(
            session.execute(
                select(SearchIndexOutbox).order_by(
                    SearchIndexOutbox.entity_type,
                    SearchIndexOutbox.document_version,
                )
            ).scalars()
        )


def test_entity_projections_retry_and_cross_mode_versioning(database, monkeypatch) -> None:
    settings = _settings()

    def network_call_forbidden(*_args, **_kwargs):
        raise AssertionError("OpenSearch network calls are out of scope")

    monkeypatch.setattr(
        "agent.opensearch.client.OpenSearchClientFactory.create",
        network_call_forbidden,
    )
    _seed_job(database, settings, "job-detect", "detect")
    service = AnalysisService(
        uow=UnitOfWork(session_factory=database, settings=settings)
    )
    detect_result = _analysis_result("job-detect")
    service._persist_analysis(detect_result, run_triage=False)

    rows = _rows(database)
    assert len(rows) == 4
    by_entity = {(row.entity_type, row.entity_id): row for row in rows}
    primary = by_entity[("canonical_event", "event-primary")].payload
    context = by_entity[("canonical_event", "event-context")].payload
    signal = by_entity[("detection_signal", "signal-1")].payload
    incident = by_entity[("incident", "incident-1")].payload

    assert primary["job_ids"] == ["job-detect"]
    assert primary["incident_ids"] == ["incident-1"]
    assert primary["context_incident_ids"] == []
    assert context["incident_ids"] == []
    assert context["context_incident_ids"] == ["incident-1"]
    assert "super-secret-token" not in str(primary)
    assert "raw_record_hash" not in primary
    assert "original_fields" not in primary

    assert signal["severity"] == "high"
    assert signal["confidence"] == 0.91
    assert signal["mitre_techniques"] == ["T1046"]
    assert signal["job_ids"] == ["job-detect"]
    assert signal["incident_ids"] == ["incident-1"]
    assert "metrics" not in signal
    assert "errors" not in signal

    assert incident["status"] == "new"
    assert incident["job_ids"] == ["job-detect"]
    assert incident["has_report"] is False
    assert incident["has_validated_evidence"] is False

    # A failed-job retry of the same job and same immutable projection is a no-op.
    with database() as session:
        job = session.get(IngestionJob, "job-detect")
        job.status = "processing"
        session.commit()
    service._persist_analysis(detect_result, run_triage=False)
    assert len(_rows(database)) == 4

    # Cross-mode reuse adds relationships, so event/signal projection versions and
    # Incident.version advance instead of colliding under a fixed version.
    _seed_job(database, settings, "job-analyze", "analyze")
    service._persist_analysis(_analysis_result("job-analyze", triaged=True), run_triage=True)
    rows = _rows(database)
    assert len(rows) == 8
    incident_rows = [row for row in rows if row.entity_type == "incident"]
    assert [row.document_version for row in incident_rows] == [1, 3]
    final_incident = incident_rows[-1].payload
    assert final_incident["status"] == "triaged"
    assert final_incident["job_ids"] == ["job-analyze", "job-detect"]
    assert final_incident["has_report"] is True
    assert final_incident["has_validated_evidence"] is True
    assert "full report" not in str(final_incident).lower()
    assert "raw firewall log" not in str(final_incident).lower()
    assert max(
        row.document_version
        for row in rows
        if row.entity_type == "canonical_event" and row.entity_id == "event-primary"
    ) > by_entity[("canonical_event", "event-primary")].document_version
    assert max(
        row.document_version
        for row in rows
        if row.entity_type == "detection_signal"
    ) > by_entity[("detection_signal", "signal-1")].document_version


def test_disabled_mode_creates_no_outbox_and_no_network_call(database, monkeypatch) -> None:
    settings = _settings(enabled=False)

    def network_call_forbidden(*_args, **_kwargs):
        raise AssertionError("disabled OpenSearch must not create a client")

    monkeypatch.setattr(
        "agent.opensearch.client.OpenSearchClientFactory.create",
        network_call_forbidden,
    )
    _seed_job(database, settings, "job-disabled", "detect")
    AnalysisService(
        uow=UnitOfWork(session_factory=database, settings=settings)
    )._persist_analysis(_analysis_result("job-disabled"), run_triage=False)

    with database() as session:
        assert session.execute(
            select(func.count()).select_from(SearchIndexOutbox)
        ).scalar_one() == 0
