"""T-A: end-to-end provider-call semantics for a whole analyze job."""

from __future__ import annotations

import agent.application.analysis_service as svc_mod
from agent.persistence.orm_models import Report
from agent.triage.enrichment import REPORT_FORMAT, deserialize_result
from agent.triage.routing import RoutingDecision

from tests.stateful_integration.conftest import (
    campaign_job_a,
    make_settings,
    run_job,
)


def _force_enrichment_eligible(monkeypatch) -> None:
    """Route the fixture incident to the batch-enrichment-eligible route."""
    decision = RoutingDecision(
        route="individual_triage",
        reason="forced-for-test",
        triage_origin="deterministic",
        llm_invoked=False,
    )
    monkeypatch.setattr(svc_mod, "decide_route", lambda *a, **k: decision)


def _artifacts(session_factory):
    with session_factory() as session:
        return session.query(Report).filter_by(format=REPORT_FORMAT).all()


def test_analyze_job_makes_exactly_one_logical_invocation(
    session_factory, fake_app, monkeypatch
) -> None:
    settings = make_settings(enabled=True)
    _force_enrichment_eligible(monkeypatch)
    events, signal, incident = campaign_job_a()

    result = run_job(
        session_factory, settings, job_id="job-batch-1",
        events=events, signals=[signal], incidents=[incident], run_triage=True,
    )

    assert fake_app.calls == 1
    assert result.routing_metrics["provider_invocation_count"] == 1
    # Retries are tracked separately and never inflate the logical count.
    assert result.routing_metrics.get("provider_retry_count", 0) == 0


def test_routes_without_action_rows_make_zero_invocations(
    session_factory, fake_app
) -> None:
    """The unforced fixture is fully blocked recon: no action row, no call."""
    settings = make_settings(enabled=True)
    events, signal, incident = campaign_job_a()

    result = run_job(
        session_factory, settings, job_id="job-no-rows",
        events=events, signals=[signal], incidents=[incident], run_triage=True,
    )

    assert result.incidents[0]["triage_route"] == "deterministic_report"
    assert fake_app.calls == 0
    assert result.routing_metrics["provider_invocation_count"] == 0
    assert _artifacts(session_factory) == []


def test_detect_mode_makes_zero_calls_and_writes_no_artifact(
    session_factory, fake_app, monkeypatch
) -> None:
    settings = make_settings(enabled=True)
    _force_enrichment_eligible(monkeypatch)
    events, signal, incident = campaign_job_a()

    detect = run_job(
        session_factory, settings, job_id="job-detect-batch",
        events=events, signals=[signal], incidents=[incident], run_triage=False,
    )

    assert fake_app.calls == 0
    assert detect.brief_enrichment is None
    assert _artifacts(session_factory) == []


def test_artifact_is_job_scoped_and_never_an_incident_report(
    session_factory, fake_app, monkeypatch
) -> None:
    settings = make_settings(enabled=True)
    _force_enrichment_eligible(monkeypatch)
    events, signal, incident = campaign_job_a()

    run_job(
        session_factory, settings, job_id="job-artifact",
        events=events, signals=[signal], incidents=[incident], run_triage=True,
    )

    artifacts = _artifacts(session_factory)
    assert len(artifacts) == 1
    artifact = artifacts[0]
    # Not attached to any incident or triage run, so incident-specific report
    # APIs can never surface it as an ordinary report.
    assert artifact.incident_id is None
    assert artifact.triage_run_id is None
    assert artifact.job_id == "job-artifact"
    assert artifact.content_sha256
    assert deserialize_result(artifact.content) is not None

    # The incident still has its own separate report.
    with session_factory() as session:
        incident_reports = (
            session.query(Report).filter(Report.incident_id.isnot(None)).all()
        )
    assert len(incident_reports) == 1
    assert incident_reports[0].format != REPORT_FORMAT


def test_at_most_one_artifact_per_job_and_schema_version(
    session_factory, fake_app, monkeypatch
) -> None:
    """The deterministic report_id makes a second write an update, not a row."""
    settings = make_settings(enabled=True)
    _force_enrichment_eligible(monkeypatch)
    events, signal, incident = campaign_job_a()

    result = run_job(
        session_factory, settings, job_id="job-once",
        events=events, signals=[signal], incidents=[incident], run_triage=True,
    )
    assert len(_artifacts(session_factory)) == 1

    # Writing the same job's artifact again refreshes the existing row.
    from agent.application.analysis_service import AnalysisService
    from agent.persistence.orm_models import IngestionJob
    from agent.persistence.unit_of_work import UnitOfWork

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        job = uow.session.get(IngestionJob, "job-once")
        AnalysisService._persist_brief_enrichment_artifact(
            uow, job, result.brief_enrichment
        )

    artifacts = _artifacts(session_factory)
    assert len(artifacts) == 1
    assert artifacts[0].report_id.endswith("job-once")


def test_enrichment_failure_does_not_change_the_security_outcome(
    session_factory, monkeypatch
) -> None:
    """A dead provider changes prose only, never verdict, severity or counts."""
    settings = make_settings(enabled=True)
    _force_enrichment_eligible(monkeypatch)
    events, signal, incident = campaign_job_a()

    class DeadProvider:
        def invoke_brief_enrichment(self, request):
            raise RuntimeError("provider exploded")

    monkeypatch.setattr(
        "agent.triage.provider_factory.build_provider", lambda *a, **k: DeadProvider()
    )
    broken = run_job(
        session_factory, settings, job_id="job-broken",
        events=events, signals=[signal], incidents=[incident], run_triage=True,
    )

    state = broken.incidents[0]
    assert state["triage_verdict"] == "suspicious_activity"
    assert state["severity"] != "none"
    assert state["llm_invoked"] is False

    # One logical invocation was attempted, then deterministic text rendered.
    assert broken.brief_enrichment.provider_invocation_count == 1
    assert broken.brief_enrichment.enrichment_failure_reason == "RuntimeError"
    assert all(item.deterministic_fallback for item in broken.brief_enrichment.items)
    # The failure is recorded only in bounded artifact metadata.
    assert "provider exploded" not in str(broken.routing_metrics)
