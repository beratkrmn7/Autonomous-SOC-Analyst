"""Phase 6E.4 integration: transactional outbox projections, whole-job replay
idempotency, unexpected-failure rollback, and the frozen registry/parser
invariants."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

import agent.application.analysis_service as svc_mod
from agent.application.analysis_service import AnalysisService
from agent.ingestion.models import (
    IngestionMetrics,
    IngestionResult,
    InputFormat,
)
from agent.persistence.orm_models import (
    Incident,
    IncidentCorrelationState,
    Report,
    SearchIndexOutbox,
)
from agent.persistence.unit_of_work import UnitOfWork

from tests.stateful_integration.conftest import (
    campaign_job_a,
    campaign_job_b,
    make_settings,
    run_job,
)


def _incident_outbox_versions(session_factory, entity_id: str) -> list[int]:
    with session_factory() as session:
        rows = session.execute(
            select(SearchIndexOutbox)
            .where(
                SearchIndexOutbox.entity_type == "incident",
                SearchIndexOutbox.entity_id == entity_id,
            )
            .order_by(SearchIndexOutbox.document_version)
        ).scalars().all()
    return [r.document_version for r in rows]


def test_canonical_projection_enqueued_once_at_its_final_version(session_factory) -> None:
    settings = make_settings(enabled=True)

    events_a, sig_a, inc_a = campaign_job_a()
    run_job(
        session_factory, settings, job_id="job-a",
        events=events_a, signals=[sig_a], incidents=[inc_a], run_triage=False,
    )
    versions_after_a = _incident_outbox_versions(session_factory, "INC-A")

    events_b, sig_b, inc_b = campaign_job_b()
    run_job(
        session_factory, settings, job_id="job-b",
        events=events_b, signals=[sig_b], incidents=[inc_b], run_triage=False,
    )

    versions = _incident_outbox_versions(session_factory, "INC-A")
    # Each job enqueues the canonical incident exactly once (no intermediate
    # versions), and the latest projection matches the persisted final version.
    assert len(versions) == len(set(versions))  # no duplicate versions
    assert len(versions) == len(versions_after_a) + 1  # job B added exactly one
    with session_factory() as session:
        incident = session.get(Incident, "INC-A")
        assert max(versions) == incident.version
    # The absorbed incoming incident is never projected.
    assert _incident_outbox_versions(session_factory, "INC-B") == []


def test_whole_job_replay_creates_no_new_writes(session_factory, fake_app, monkeypatch) -> None:
    settings = make_settings(enabled=True)
    events, signal, incident = campaign_job_a()

    ingestion_result = IngestionResult(
        source_name="firewall.json",
        input_format=InputFormat.JSONL,
        events=list(events),
        metrics=IngestionMetrics(total_records=1, parsed_records=1),
    )

    # Force the canonical incident through individual_triage so the first run
    # genuinely invokes the provider and writes a report; the replay must do
    # neither again.
    from agent.triage.routing import RoutingDecision

    monkeypatch.setattr(
        svc_mod,
        "decide_route",
        lambda *a, **k: RoutingDecision(
            route="individual_triage",  # type: ignore[arg-type]
            reason="forced",
            triage_origin="llm",
            llm_invoked=True,
        ),
    )

    def build_service() -> AnalysisService:
        service = AnalysisService(
            uow=UnitOfWork(session_factory=session_factory, settings=settings)
        )
        service.ingest.ingest_file = lambda path: ingestion_result  # type: ignore[assignment]
        from agent.detection.models import (
            DetectionMetrics,
            DetectionResult,
        )

        det = DetectionResult(
            signals=[signal], incidents=[incident], suppressed_signals=[],
            uncorrelated_event_ids=[], warnings=[],
            metrics=DetectionMetrics(total_events=1, signal_count=1, incident_count=1, duration_ms=1.0),
        )
        service.detection_engine.analyze = lambda ev, ctx: det  # type: ignore[assignment]
        return service

    first = build_service().analyze_file(
        "irrelevant.json", run_triage=True, idempotency_key="key-1",
        analysis_mode="analyze", source_name="firewall.json",
    )
    assert first.reused is False
    assert fake_app.calls == 1

    def counts():
        with session_factory() as session:
            return (
                session.execute(select(func.count()).select_from(IncidentCorrelationState)).scalar_one(),
                session.execute(select(func.count()).select_from(Report)).scalar_one(),
                session.execute(select(func.count()).select_from(SearchIndexOutbox)).scalar_one(),
            )

    before = counts()
    incident_version_before = None
    with session_factory() as session:
        incident_version_before = session.get(Incident, "INC-A").version

    replay = build_service().analyze_file(
        "irrelevant.json", run_triage=True, idempotency_key="key-1",
        analysis_mode="analyze", source_name="firewall.json",
    )

    # Reused whole job: no new provider call, no new state/report/outbox rows,
    # no version bump, and the previously persisted incident ID is returned.
    assert replay.reused is True
    assert fake_app.calls == 1
    assert counts() == before
    with session_factory() as session:
        assert session.get(Incident, "INC-A").version == incident_version_before
    assert [s.get("incident_id") for s in replay.incidents] == ["INC-A"]


def test_unexpected_resolver_failure_rolls_back_all_writes(session_factory, monkeypatch) -> None:
    settings = make_settings(enabled=True)
    events, signal, incident = campaign_job_a()

    from tests.stateful_integration.conftest import seed_processing_job

    seed_processing_job(session_factory, settings, "job-fail", "detect")

    def boom(*args, **kwargs):
        raise RuntimeError("resolver exploded")

    monkeypatch.setattr(
        "agent.application.stateful_correlation_service."
        "StatefulIncidentCorrelationService.resolve_and_merge",
        boom,
    )

    from agent.detection.models import DetectionMetrics, DetectionResult

    det = DetectionResult(
        signals=[signal], incidents=[incident], suppressed_signals=[],
        uncorrelated_event_ids=[], warnings=[],
        metrics=DetectionMetrics(total_events=1, signal_count=1, incident_count=1, duration_ms=1.0),
    )
    service = AnalysisService(uow=UnitOfWork(session_factory=session_factory, settings=settings))
    service.detection_engine.analyze = lambda ev, ctx: det  # type: ignore[assignment]

    with pytest.raises(RuntimeError):
        service._process_events(
            events=events, run_triage=False, ingestion_result=None,
            source_name="firewall.json", job_id="job-fail",
        )

    # The whole transaction rolled back: no incident, no state, no outbox rows.
    with session_factory() as session:
        assert session.get(Incident, "INC-A") is None
        assert session.execute(select(func.count()).select_from(IncidentCorrelationState)).scalar_one() == 0
        assert session.execute(select(func.count()).select_from(SearchIndexOutbox)).scalar_one() == 0
        from agent.persistence.orm_models import IngestionJob

        assert session.get(IngestionJob, "job-fail").status == "failed"


def test_default_registry_has_exactly_36_rules() -> None:
    from agent.detection.detectors import register_default_rules
    from agent.detection.registry import default_registry

    register_default_rules()
    rules = default_registry.get_all_rules()
    assert len(rules) == 36
    assert len({rule.rule_id for rule in rules}) == 36


def test_pf_parser_version_is_2_2_0() -> None:
    from agent.parsers.pf_firewall import PfFirewallParser

    assert PfFirewallParser.version == "2.2.0"
