"""Phase 6E.4 integration: the AnalysisService feature-flag contract and the
canonical AnalysisResult it returns when stateful correlation is enabled."""

from __future__ import annotations

from sqlalchemy import func, select

from agent.application.analysis_service import AnalysisService
from agent.config import Settings
from agent.persistence.orm_models import Incident, IncidentCorrelationState
from agent.persistence.unit_of_work import UnitOfWork

from tests.stateful_integration.conftest import (
    campaign_job_a,
    make_detection_result,
    make_settings,
    run_job,
    seed_processing_job,
)


def test_feature_flag_is_false_by_default() -> None:
    assert Settings(_env_file=None).stateful_correlation_enabled is False


def test_disabled_mode_preserves_legacy_ids_and_writes_no_state_row(session_factory) -> None:
    settings = make_settings(enabled=False)
    events, signal, incident = campaign_job_a()
    result = run_job(
        session_factory,
        settings,
        job_id="job-a",
        events=events,
        signals=[signal],
        incidents=[incident],
        run_triage=False,
    )

    # Legacy batch-local path: the original incident ID survives untouched and
    # no stateful metrics are produced.
    assert [s.get("incident_id") for s in result.incidents] == ["INC-A"]
    assert result.stateful_metrics == {}

    with session_factory() as session:
        assert (
            session.execute(
                select(func.count()).select_from(IncidentCorrelationState)
            ).scalar_one()
            == 0
        )
        assert session.get(Incident, "INC-A") is not None


def test_enabled_mode_creates_canonical_incident_and_scalar_metrics(session_factory) -> None:
    settings = make_settings(enabled=True)
    events, signal, incident = campaign_job_a()
    result = run_job(
        session_factory,
        settings,
        job_id="job-a",
        events=events,
        signals=[signal],
        incidents=[incident],
        run_triage=False,
    )

    metrics = result.stateful_metrics
    assert metrics["incoming_batch_incident_count"] == 1
    assert metrics["final_canonical_incident_count"] == 1
    assert metrics["stateful_created_count"] == 1
    assert metrics["absorbed_batch_incident_count"] == 0

    # Bounded scalars only - never ID lists.
    assert all(isinstance(v, int) for v in metrics.values())

    with session_factory() as session:
        assert (
            session.execute(
                select(func.count()).select_from(IncidentCorrelationState)
            ).scalar_one()
            == 1
        )


def test_returned_detection_result_is_a_copy_and_reflects_final_incidents(
    session_factory,
) -> None:
    """The engine's original DetectionResult must never be mutated in place;
    the returned one carries the final canonical incidents and a matching
    incident_count, while signals stay the current job's detected signals."""
    settings = make_settings(enabled=True)
    events, signal, incident = campaign_job_a()
    original = make_detection_result(
        events=events, signals=[signal], incidents=[incident]
    )

    seed_processing_job(session_factory, settings, "job-a", "detect")
    service = AnalysisService(
        uow=UnitOfWork(session_factory=session_factory, settings=settings)
    )
    service.detection_engine.analyze = lambda ev, ctx: original  # type: ignore[assignment]
    result = service._process_events(
        events=events,
        run_triage=False,
        ingestion_result=None,
        source_name="firewall.json",
        job_id="job-a",
    )

    returned = result.detection_result
    assert returned is not original  # copied, not mutated in place
    assert [i.incident_id for i in original.incidents] == ["INC-A"]  # untouched
    assert returned.metrics.incident_count == len(returned.incidents)
    assert [s.signal_id for s in returned.signals] == ["SIG-A"]  # current-job only
