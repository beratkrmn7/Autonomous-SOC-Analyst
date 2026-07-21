"""Focused persistence/hydration tests for Phase 6E.1 deterministic triage routing.

Covers the merge-blocker fixes:
- deterministic_report persists the valid verdict "suspicious_activity" with
  provider="deterministic" and zero provider iterations.
- digest/store_only incidents never create a fake TriageRun or Report and are
  never lifecycle-transitioned as though an agent reviewed them.
- an idempotent hydrated result recomputes the same routing metadata as the
  fresh run that originally produced it.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agent.application.analysis_service import AnalysisService
from agent.detection.config import DetectionSettings
from agent.detection.detectors.coordinated_scan import RepeatedBlockedScannerRule
from agent.detection.detectors.remote_service_probe import RemoteServiceProbeRule
from agent.detection.detectors.spi_anomaly import SPIAnomalyRule
from agent.detection.engine import DetectionEngine
from agent.detection.registry import RuleRegistry
from agent.persistence.database import Base
from agent.persistence.orm_models import Incident, IngestionJob, Report, TriageRun
from agent.persistence.unit_of_work import UnitOfWork
from agent.triage.routing import DETERMINISTIC_TRIAGE_VERDICT
from tests.detection.helpers import build_pf_event


NOW = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)


def _lenient_settings() -> DetectionSettings:
    return DetectionSettings.model_validate(
        {
            "REMOTE_SERVICE_MIN_EVENTS": 2,
            "REMOTE_SERVICE_MIN_DISTINCT_TARGETS": 2,
            # Kept above the 2-event RDP probe group so RemoteServiceProbeRule's
            # events (single dst_port) never also qualify as a blocked scanner.
            "REPEATED_BLOCKED_SCANNER_MIN_EVENTS": 3,
            "REPEATED_BLOCKED_SCANNER_MIN_DISTINCT_TARGETS": 2,
            "REPEATED_BLOCKED_SCANNER_MIN_DISTINCT_PORTS": 2,
            "SPI_ANOMALY_MIN_EVENTS": 1,
            "SPI_ANOMALY_MIN_DISTINCT_TARGETS": 1,
        }
    )


def _scoped_engine() -> DetectionEngine:
    registry = RuleRegistry()
    registry.register(RemoteServiceProbeRule())
    registry.register(RepeatedBlockedScannerRule())
    registry.register(SPIAnomalyRule())
    return DetectionEngine(registry=registry, settings=_lenient_settings())


def _scenario_events() -> list:
    # deterministic_report: fully blocked RDP probe (service_probing family).
    rdp_events = [
        build_pf_event(
            f"rdp-{i}",
            spi=False,
            timestamp=NOW,
            action="block",
            protocol="TCP",
            tcp_flags="SYN",
            src_ip="198.51.100.10",
            dst_ip=f"192.0.2.{50 + i}",
            dst_port=3389,
        )
        for i in range(2)
    ]
    # digest: low-severity, fully blocked repeated_blocked_scanner.
    scanner_events = [
        build_pf_event(
            f"scan-{i}",
            spi=False,
            timestamp=NOW,
            action="block",
            protocol="TCP",
            tcp_flags="SYN",
            src_ip="198.51.100.11",
            dst_ip=f"192.0.2.{60 + i}",
            dst_port=9000 + i,
        )
        for i in range(3)
    ]
    # store_only: verified SPI ACK,RST response with a related allowed
    # HTTPS/NAT flow using a different client-side ephemeral port.
    spi_event = build_pf_event(
        "spi-1",
        spi=True,
        timestamp=NOW,
        action="block",
        protocol="TCP",
        tcp_flags="ACK,RST",
        src_ip="203.0.113.5",
        src_port=443,
        dst_ip="192.0.2.10",
        dst_port=51000,
    )
    allowed_context_event = build_pf_event(
        "allowed-ctx-1",
        spi=False,
        timestamp=NOW,
        action="allow",
        protocol="TCP",
        tcp_flags="SYN",
        src_ip="192.0.2.10",
        src_port=52222,
        dst_ip="203.0.113.5",
        dst_port=443,
    )
    return [*rdp_events, *scanner_events, spi_event, allowed_context_event]


def _state_by_route(result, route: str) -> dict:
    matches = [state for state in result.incidents if state.get("triage_route") == route]
    assert len(matches) == 1, f"expected exactly one {route} incident, found {len(matches)}"
    return matches[0]


@pytest.fixture
def session_factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    yield factory
    engine.dispose()


def _fresh_result():
    svc = AnalysisService()
    svc.detection_engine = _scoped_engine()
    result = svc.analyze_events(_scenario_events(), run_triage=True)
    assert result.detection_result is not None
    assert len(result.detection_result.incidents) == 3
    return result


def test_routing_and_deterministic_report_wording_are_correct() -> None:
    result = _fresh_result()

    deterministic = _state_by_route(result, "deterministic_report")
    assert deterministic["triage_verdict"] == DETERMINISTIC_TRIAGE_VERDICT
    assert deterministic["triage_origin"] == "deterministic"
    assert deterministic["llm_invoked"] is False
    assert deterministic["iteration_count"] == 0
    assert "All 2 observed event(s) were blocked" in deterministic["final_report"]

    digest_state = _state_by_route(result, "digest")
    assert digest_state["llm_invoked"] is False
    assert digest_state.get("final_report") is None

    store_only_state = _state_by_route(result, "store_only")
    assert store_only_state["llm_invoked"] is False
    assert store_only_state.get("triage_verdict") is None
    assert store_only_state.get("final_report") is None

    assert result.routing_metrics["individual_triage_count"] == 0
    assert result.routing_metrics["deterministic_report_count"] == 1
    assert result.routing_metrics["digest_incident_count"] == 1
    assert result.routing_metrics["store_only_count"] == 1
    assert result.routing_metrics["provider_invocation_count"] == 0
    assert len(result.triage_digests) == 1
    assert result.triage_digests[0]["source_count"] == 1


def test_deterministic_persistence_and_idempotent_hydration_are_consistent(
    session_factory,
) -> None:
    fresh_result = _fresh_result()
    deterministic_state = _state_by_route(fresh_result, "deterministic_report")
    digest_state = _state_by_route(fresh_result, "digest")
    store_only_state = _state_by_route(fresh_result, "store_only")

    with session_factory() as session:
        session.add(
            IngestionJob(
                id="job-1",
                idempotency_key="idem-1",
                source_name="test",
                status="processing",
            )
        )
        session.commit()

    fresh_result.job_id = "job-1"
    persist_svc = AnalysisService(uow=UnitOfWork(session_factory=session_factory))
    persist_svc._persist_analysis(fresh_result, run_triage=True)

    with session_factory() as session:
        job = session.get(IngestionJob, "job-1")
        assert job.status == "completed"

        det_run = (
            session.query(TriageRun)
            .filter_by(incident_id=deterministic_state["incident_id"])
            .one()
        )
        assert det_run.verdict == "suspicious_activity"
        assert det_run.provider == "deterministic"
        assert det_run.iteration_count == 0

        det_report = (
            session.query(Report)
            .filter_by(incident_id=deterministic_state["incident_id"])
            .one()
        )
        assert "blocked" in det_report.content.lower()

        det_incident = session.get(Incident, deterministic_state["incident_id"])
        assert det_incident.status == "triaged"

        # digest/store_only: no fake TriageRun, no Report, no lifecycle
        # transition implying an agent reviewed them.
        for state in (digest_state, store_only_state):
            assert (
                session.query(TriageRun)
                .filter_by(incident_id=state["incident_id"])
                .count()
                == 0
            )
            assert (
                session.query(Report)
                .filter_by(incident_id=state["incident_id"])
                .count()
                == 0
            )
            incident_row = session.get(Incident, state["incident_id"])
            assert incident_row.status == "new"

    hydrate_svc = AnalysisService(uow=UnitOfWork(session_factory=session_factory))
    hydrated_result = hydrate_svc.analyze_file(
        "nonexistent-file-not-touched.jsonl",
        run_triage=True,
        idempotency_key="idem-1",
    )

    assert hydrated_result.reused is True
    assert hydrated_result.routing_metrics == fresh_result.routing_metrics
    assert len(hydrated_result.triage_digests) == len(fresh_result.triage_digests)

    hydrated_deterministic = _state_by_route(hydrated_result, "deterministic_report")
    assert hydrated_deterministic["incident_id"] == deterministic_state["incident_id"]
    assert hydrated_deterministic["triage_verdict"] == DETERMINISTIC_TRIAGE_VERDICT
    assert hydrated_deterministic["llm_invoked"] is False
    assert hydrated_deterministic["final_report"] == deterministic_state["final_report"]

    hydrated_digest = _state_by_route(hydrated_result, "digest")
    assert hydrated_digest["incident_id"] == digest_state["incident_id"]

    hydrated_store_only = _state_by_route(hydrated_result, "store_only")
    assert hydrated_store_only["incident_id"] == store_only_state["incident_id"]
