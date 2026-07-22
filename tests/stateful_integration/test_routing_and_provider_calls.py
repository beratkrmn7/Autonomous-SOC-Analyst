"""Phase 6E.4 integration: routing runs on the final canonical incident and
the per-job provider-call contract holds for every route."""

from __future__ import annotations

import agent.application.analysis_service as svc_mod
from agent.triage.routing import RoutingDecision, decide_route

from tests.stateful_integration.conftest import (
    FIXED,
    campaign_job_a,
    campaign_job_b,
    make_event,
    make_incident,
    make_settings,
    make_signal,
    run_job,
)


def _force_route(monkeypatch, route: str, *, llm: bool) -> None:
    decision = RoutingDecision(
        route=route,  # type: ignore[arg-type]
        reason="forced-for-test",
        triage_origin="llm" if llm else "deterministic",
        llm_invoked=llm,
    )
    monkeypatch.setattr(svc_mod, "decide_route", lambda *a, **k: decision)


def test_individual_triage_calls_provider_exactly_once(
    session_factory, fake_app, monkeypatch
) -> None:
    settings = make_settings(enabled=True)
    _force_route(monkeypatch, "individual_triage", llm=True)
    events, signal, incident = campaign_job_a()
    result = run_job(
        session_factory, settings, job_id="job-a",
        events=events, signals=[signal], incidents=[incident], run_triage=True,
    )
    assert fake_app.calls == 1
    assert result.routing_metrics["provider_invocation_count"] == 1


def test_disabled_llm_does_not_attempt_individual_triage_provider(
    session_factory, fake_app, monkeypatch
) -> None:
    settings = make_settings(enabled=True, llm_enabled=False)
    _force_route(monkeypatch, "individual_triage", llm=True)
    events, signal, incident = campaign_job_a()

    result = run_job(
        session_factory,
        settings,
        job_id="job-disabled-provider",
        events=events,
        signals=[signal],
        incidents=[incident],
        run_triage=True,
    )

    assert fake_app.calls == 0
    assert result.routing_metrics["individual_triage_count"] == 1
    assert result.routing_metrics["provider_invocation_count"] == 0
    assert result.incidents[0]["triage_verdict"] == "needs_review"
    assert result.incidents[0]["llm_invoked"] is False
    assert result.incidents[0]["incident_type"] == incident.incident_type


def test_deterministic_report_route_makes_zero_provider_calls(
    session_factory, fake_app, monkeypatch
) -> None:
    settings = make_settings(enabled=True)
    _force_route(monkeypatch, "deterministic_report", llm=False)
    events, signal, incident = campaign_job_a()
    run_job(
        session_factory, settings, job_id="job-a",
        events=events, signals=[signal], incidents=[incident], run_triage=True,
    )
    assert fake_app.calls == 0


def test_digest_route_makes_zero_provider_calls(session_factory, fake_app, monkeypatch) -> None:
    settings = make_settings(enabled=True)
    _force_route(monkeypatch, "digest", llm=False)
    events, signal, incident = campaign_job_a()
    run_job(
        session_factory, settings, job_id="job-a",
        events=events, signals=[signal], incidents=[incident], run_triage=True,
    )
    assert fake_app.calls == 0


def test_store_only_route_makes_zero_provider_calls(session_factory, fake_app, monkeypatch) -> None:
    settings = make_settings(enabled=True)
    _force_route(monkeypatch, "store_only", llm=False)
    events, signal, incident = campaign_job_a()
    run_job(
        session_factory, settings, job_id="job-a",
        events=events, signals=[signal], incidents=[incident], run_triage=True,
    )
    assert fake_app.calls == 0


def test_routing_sees_final_promoted_identity_and_all_attached_signals(
    session_factory, fake_app, monkeypatch
) -> None:
    """During the second job, routing must run on the canonical incident with
    the union of historical and current signals - never on the obsolete
    incoming INC-B batch bundle."""
    settings = make_settings(enabled=True)
    captured: list[dict] = []

    def spy(inc, events, context_events, rule_ids, det_settings):
        captured.append(
            {
                "incident_id": inc.incident_id,
                "signal_ids": set(inc.signal_ids),
                "rule_ids": set(rule_ids),
            }
        )
        return decide_route(inc, events, context_events, rule_ids, det_settings)

    events_a, sig_a, inc_a = campaign_job_a()
    run_job(
        session_factory, settings, job_id="job-a",
        events=events_a, signals=[sig_a], incidents=[inc_a], run_triage=False,
    )

    monkeypatch.setattr(svc_mod, "decide_route", spy)
    events_b, sig_b, inc_b = campaign_job_b()
    run_job(
        session_factory, settings, job_id="job-b",
        events=events_b, signals=[sig_b], incidents=[inc_b], run_triage=True,
    )

    assert len(captured) == 1
    routed = captured[0]
    assert routed["incident_id"] == "INC-A"  # canonical, not the incoming INC-B
    assert routed["signal_ids"] == {"SIG-A", "SIG-B"}  # historical + current
    assert routed["rule_ids"] == {"remote_service_probe"}


def test_multiple_incoming_incidents_to_one_canonical_are_processed_once(
    session_factory, fake_app, monkeypatch
) -> None:
    """Two incoming batch incidents in one job that resolve to the same
    canonical incident must be hydrated, routed and triaged exactly once."""
    settings = make_settings(enabled=True)
    _force_route(monkeypatch, "individual_triage", llm=True)

    ev1 = [make_event("x1", ts=FIXED)]
    sig1 = make_signal("SIG-X", ["x1"], ts=FIXED)
    inc1 = make_incident("INC-X", sig1, ev1, ts=FIXED)

    ev2 = [make_event("y1", ts=FIXED)]
    sig2 = make_signal("SIG-Y", ["y1"], ts=FIXED)
    inc2 = make_incident("INC-Y", sig2, ev2, ts=FIXED)

    result = run_job(
        session_factory, settings, job_id="job-multi",
        events=ev1 + ev2, signals=[sig1, sig2], incidents=[inc1, inc2],
        run_triage=True,
    )

    assert result.stateful_metrics["incoming_batch_incident_count"] == 2
    assert result.stateful_metrics["final_canonical_incident_count"] == 1
    assert result.stateful_metrics["absorbed_batch_incident_count"] == 1
    assert fake_app.calls == 1  # one final incident -> at most one provider call
    assert len(result.incidents) == 1
