"""Phase 6E.4 integration: every stateful resolver status is handled by the
AnalysisService flow - canonical statuses route the persisted incident, while
unsupported/stale fail closed to the batch-local path so no detection is lost."""

from __future__ import annotations

import datetime

from sqlalchemy import func, select

from agent.persistence.orm_models import Incident, IncidentCorrelationState

from tests.stateful_integration.conftest import (
    FIXED,
    make_event,
    make_incident,
    make_settings,
    make_signal,
    run_job,
    unsupported_incident,
)


def test_unsupported_profile_falls_back_to_batch_local_incident(session_factory) -> None:
    settings = make_settings(enabled=True)
    events, signal, incident = unsupported_incident()
    result = run_job(
        session_factory, settings, job_id="job-u",
        events=events, signals=[signal], incidents=[incident], run_triage=False,
    )

    assert result.stateful_metrics["stateful_unsupported_count"] == 1
    # The detection is preserved as its own batch-local incident, and no
    # correlation-state row is written for an unsupported profile.
    assert [s.get("incident_id") for s in result.incidents] == ["INC-U"]
    with session_factory() as session:
        assert session.get(Incident, "INC-U") is not None
        assert (
            session.execute(
                select(func.count()).select_from(IncidentCorrelationState)
            ).scalar_one()
            == 0
        )


def test_stale_backward_activity_is_persisted_separately(session_factory) -> None:
    settings = make_settings(
        enabled=True,
        stateful_correlation_window_seconds=3600,
        stateful_correlation_state_ttl_seconds=86400,
    )

    # Active campaign anchored at FIXED.
    events_a = [make_event("a1", ts=FIXED)]
    sig_a = make_signal("SIG-A", ["a1"], ts=FIXED)
    inc_a = make_incident("INC-A", sig_a, events_a, ts=FIXED)
    run_job(
        session_factory, settings, job_id="job-a",
        events=events_a, signals=[sig_a], incidents=[inc_a], run_triage=False,
    )

    # A late-arriving incident dated well before the active window.
    back = FIXED - datetime.timedelta(hours=5)
    events_b = [make_event("b1", ts=back)]
    sig_b = make_signal("SIG-B", ["b1"], ts=back)
    inc_b = make_incident("INC-B", sig_b, events_b, ts=back)
    result_b = run_job(
        session_factory, settings, job_id="job-b",
        events=events_b, signals=[sig_b], incidents=[inc_b], run_triage=False,
    )

    assert result_b.stateful_metrics["stateful_stale_count"] == 1
    # The late incident is kept as its own incident; the active campaign row is
    # untouched (still present, not replaced).
    assert [s.get("incident_id") for s in result_b.incidents] == ["INC-B"]
    with session_factory() as session:
        assert {i.incident_id for i in session.query(Incident).all()} == {"INC-A", "INC-B"}


def test_new_generation_creates_a_separate_canonical_incident(session_factory) -> None:
    settings = make_settings(
        enabled=True,
        stateful_correlation_window_seconds=60,
        stateful_correlation_state_ttl_seconds=60,
    )

    events_a = [make_event("a1", ts=FIXED)]
    sig_a = make_signal("SIG-A", ["a1"], ts=FIXED)
    inc_a = make_incident("INC-A", sig_a, events_a, ts=FIXED)
    run_job(
        session_factory, settings, job_id="job-a",
        events=events_a, signals=[sig_a], incidents=[inc_a], run_triage=False,
    )

    # Well past the TTL/window, a fresh campaign against a new target starts a
    # new generation rather than mutating the historical incident.
    much_later = FIXED + datetime.timedelta(hours=5)
    events_c = [make_event("c1", ts=much_later, dst_ip="10.9.9.9")]
    sig_c = make_signal("SIG-C", ["c1"], ts=much_later).model_copy(
        update={"target_entities": ["10.9.9.9"]}
    )
    inc_c = make_incident("INC-C", sig_c, events_c, ts=much_later).model_copy(
        update={"target_entities": ["10.9.9.9"]}
    )
    result_c = run_job(
        session_factory, settings, job_id="job-c",
        events=events_c, signals=[sig_c], incidents=[inc_c], run_triage=False,
    )

    assert result_c.stateful_metrics["stateful_new_generation_count"] == 1
    assert [s.get("incident_id") for s in result_c.incidents] == ["INC-C"]
    with session_factory() as session:
        # The historical incident is preserved unchanged alongside the new one.
        assert {i.incident_id for i in session.query(Incident).all()} == {"INC-A", "INC-C"}
