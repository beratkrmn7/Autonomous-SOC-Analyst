"""Phase 6E.4 integration: detect mode. Deterministic detection + canonical
cross-job correlation with zero provider calls and no triage/report rows."""

from __future__ import annotations

from sqlalchemy import func, select

from agent.persistence.orm_models import (
    Incident,
    Report,
    SearchIndexOutbox,
    TriageRun,
)

from tests.stateful_integration.conftest import (
    campaign_job_a,
    campaign_job_b,
    make_settings,
    run_job,
)


def _run_campaign(session_factory, settings):
    events_a, sig_a, inc_a = campaign_job_a()
    result_a = run_job(
        session_factory, settings, job_id="job-a",
        events=events_a, signals=[sig_a], incidents=[inc_a], run_triage=False,
    )
    events_b, sig_b, inc_b = campaign_job_b()
    result_b = run_job(
        session_factory, settings, job_id="job-b",
        events=events_b, signals=[sig_b], incidents=[inc_b], run_triage=False,
    )
    return result_a, result_b


def test_detect_mode_makes_zero_provider_calls(session_factory, fake_app) -> None:
    settings = make_settings(enabled=True)
    _run_campaign(session_factory, settings)
    assert fake_app.calls == 0


def test_detect_mode_creates_no_triage_run_or_report(session_factory) -> None:
    settings = make_settings(enabled=True)
    _run_campaign(session_factory, settings)
    with session_factory() as session:
        assert session.execute(select(func.count()).select_from(TriageRun)).scalar_one() == 0
        assert session.execute(select(func.count()).select_from(Report)).scalar_one() == 0


def test_two_jobs_correlate_into_one_canonical_persistent_incident(session_factory) -> None:
    settings = make_settings(enabled=True)
    result_a, result_b = _run_campaign(session_factory, settings)

    # Job A creates the canonical incident; job B merges into it.
    assert result_a.stateful_metrics["stateful_created_count"] == 1
    assert result_b.stateful_metrics["stateful_merged_count"] == 1
    assert [s.get("incident_id") for s in result_b.incidents] == ["INC-A"]

    with session_factory() as session:
        incidents = session.query(Incident).all()
        assert [i.incident_id for i in incidents] == ["INC-A"]  # only the canonical


def test_both_jobs_associated_with_the_canonical_incident(session_factory) -> None:
    settings = make_settings(enabled=True)
    _run_campaign(session_factory, settings)
    with session_factory() as session:
        incident = session.get(Incident, "INC-A")
        job_ids = {job.id for job in incident.jobs}
        assert job_ids == {"job-a", "job-b"}


def test_historical_signals_stay_attached_to_the_canonical_incident(session_factory) -> None:
    settings = make_settings(enabled=True)
    _run_campaign(session_factory, settings)
    with session_factory() as session:
        incident = session.get(Incident, "INC-A")
        signal_ids = {str(s.signal_id) for s in incident.signals}
        assert signal_ids == {"SIG-A", "SIG-B"}  # all campaign signals


def test_historical_signals_are_not_copied_into_current_job_associations(
    session_factory,
) -> None:
    settings = make_settings(enabled=True)
    _run_campaign(session_factory, settings)
    from agent.persistence.orm_models import IngestionJob

    with session_factory() as session:
        job_a = session.get(IngestionJob, "job-a")
        job_b = session.get(IngestionJob, "job-b")
        # Each job owns only the signals it detected, never the other job's.
        assert {str(s.signal_id) for s in job_a.signals} == {"SIG-A"}
        assert {str(s.signal_id) for s in job_b.signals} == {"SIG-B"}


def test_absorbed_incident_is_not_persisted_returned_or_projected(session_factory) -> None:
    settings = make_settings(enabled=True)
    _run_campaign(session_factory, settings)

    with session_factory() as session:
        # Not persisted as its own Incident row.
        assert session.get(Incident, "INC-B") is None
        # Not projected to the outbox.
        incident_docs = session.execute(
            select(SearchIndexOutbox).where(SearchIndexOutbox.entity_type == "incident")
        ).scalars().all()
        assert all(row.entity_id != "INC-B" for row in incident_docs)
        assert any(row.entity_id == "INC-A" for row in incident_docs)
