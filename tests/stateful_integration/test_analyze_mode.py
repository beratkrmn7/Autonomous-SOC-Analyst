"""Phase 6E.4 integration: analyze mode and the ingest-only contract."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import func, select

from agent.ingestion.pipeline import IngestionPipeline
from agent.persistence.orm_models import (
    Incident,
    IncidentCorrelationState,
    Report,
)

from tests.stateful_integration.conftest import (
    campaign_job_a,
    campaign_job_b,
    make_settings,
    run_job,
)

FIXTURE = str(Path(__file__).resolve().parents[1] / "fixtures" / "firewall" / "valid_firewall.jsonl")


def _run_analyze_campaign(session_factory, settings):
    events_a, sig_a, inc_a = campaign_job_a()
    run_job(
        session_factory, settings, job_id="job-a",
        events=events_a, signals=[sig_a], incidents=[inc_a], run_triage=True,
    )
    events_b, sig_b, inc_b = campaign_job_b()
    result_b = run_job(
        session_factory, settings, job_id="job-b",
        events=events_b, signals=[sig_b], incidents=[inc_b], run_triage=True,
    )
    return result_b


def test_analyze_mode_returns_canonical_incident_id_in_second_job(session_factory) -> None:
    settings = make_settings(enabled=True)
    result_b = _run_analyze_campaign(session_factory, settings)
    assert [s.get("incident_id") for s in result_b.incidents] == ["INC-A"]
    assert result_b.detection_result.incidents[0].incident_id == "INC-A"


def test_analyze_mode_creates_at_most_one_report_per_canonical_per_job(session_factory) -> None:
    settings = make_settings(enabled=True)
    _run_analyze_campaign(session_factory, settings)
    with session_factory() as session:
        # Exactly one report was written for the canonical incident during the
        # current (second) job - not one per absorbed incoming incident.
        job_b_reports = session.execute(
            select(func.count())
            .select_from(Report)
            .where(Report.job_id == "job-b", Report.incident_id == "INC-A")
        ).scalar_one()
        assert job_b_reports == 1
        # No report was ever written for the absorbed incoming incident.
        absorbed_reports = session.execute(
            select(func.count()).select_from(Report).where(Report.incident_id == "INC-B")
        ).scalar_one()
        assert absorbed_reports == 0


def test_merge_preserves_existing_canonical_lifecycle_status(session_factory) -> None:
    settings = make_settings(enabled=True)
    _run_analyze_campaign(session_factory, settings)
    with session_factory() as session:
        incident = session.get(Incident, "INC-A")
        # Job A triaged the incident; the job-B merge must not reset it to 'new'.
        assert incident.status != "new"
        assert incident.status in ("triaged", "investigating", "needs_review")


def test_ingest_only_runs_no_detection_correlation_or_provider(
    session_factory, fake_app, monkeypatch
) -> None:
    # Prove the ingest path never reaches deterministic detection.
    def detection_forbidden(*_args, **_kwargs):
        raise AssertionError("ingest-only mode must not run detection")

    monkeypatch.setattr(
        "agent.detection.engine.DetectionEngine.analyze", detection_forbidden
    )

    result = IngestionPipeline().ingest_file(FIXTURE)

    # Parse succeeded and produced events...
    assert result.events
    assert result.metrics.parsed_records > 0
    # ...but no incident/state row was created and the provider was never called.
    assert fake_app.calls == 0
    with session_factory() as session:
        assert session.execute(select(func.count()).select_from(Incident)).scalar_one() == 0
        assert (
            session.execute(
                select(func.count()).select_from(IncidentCorrelationState)
            ).scalar_one()
            == 0
        )
