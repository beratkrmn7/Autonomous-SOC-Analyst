"""Phase 6E.4 blocker: every resolver result on one final canonical incident
is aggregated. A created result followed by a merged result that promotes the
primary identity must not hide the promotion (or any material change)."""

from __future__ import annotations

import datetime

from sqlalchemy import select

from agent.detection.models import (
    DetectionEvidence,
    DetectionSignal,
    IncidentBundle,
)
from agent.persistence.orm_models import (
    AuditEvent,
    Incident,
    Report,
    SearchIndexOutbox,
    TriageRun,
)
from agent.schema import CanonicalLogEvent

from tests.stateful_integration.conftest import make_settings, run_job

FIXED = datetime.datetime(2026, 7, 10, 6, 0, 0, tzinfo=datetime.timezone.utc)


def _event(event_id: str, *, ts: datetime.datetime = FIXED) -> CanonicalLogEvent:
    return CanonicalLogEvent(
        event_id=event_id, timestamp=ts, src_ip="203.0.113.10", dst_ip="10.0.0.5",
        dst_port=3389, protocol="TCP", action="block", parser_name="pf_firewall",
        parse_status="parsed", source_name="firewall.json",
        safe_message_excerpt=f"BLOCK TCP {event_id}",
    )


def _signal(sid, eids, stype, sfam, rid, rname, *, ts=FIXED) -> DetectionSignal:
    return DetectionSignal(
        signal_id=sid, rule_id=rid, rule_version="1", rule_name=rname,
        signal_type=stype, signal_family=sfam, severity="medium", confidence=0.6,
        first_seen=ts, last_seen=ts, event_ids=eids, primary_entity="203.0.113.10",
        target_entities=["10.0.0.5"], metrics={},
        evidence=[DetectionEvidence(event_id=eids[0], quote="q", reason="r",
                                    source="pf", original_fields={}, correlation_context={})],
        mitre_techniques=["T1021.001"], tags=[],
    )


def _incident(iid, signal, events, itype, ifam, *, ts=FIXED) -> IncidentBundle:
    return IncidentBundle(
        incident_id=iid, incident_type=itype, incident_family=ifam,
        title=f"{itype} from 203.0.113.10", severity="medium", confidence=0.6,
        first_seen=ts, last_seen=max(e.timestamp for e in events),
        primary_entity="203.0.113.10", target_entities=["10.0.0.5"],
        signal_ids=[signal.signal_id], event_ids=[e.event_id for e in events],
        context_event_ids=[], evidence=signal.evidence,
        metrics={"primary_signal_id": signal.signal_id},
        mitre_techniques=signal.mitre_techniques, merge_key="m1",
    )


def _promotion_campaign():
    e1 = _event("e1")
    e2 = _event("e2", ts=FIXED + datetime.timedelta(minutes=2))
    s1 = _signal("SIG-HS", ["e1"], "horizontal_scan", "network_scanning",
                 "network_scan_horizontal", "Horizontal Scan")
    s2 = _signal("SIG-RDP", ["e2"], "rdp_probe", "service_probing",
                 "remote_service_probe", "RDP Probe")
    i1 = _incident("INC-HS", s1, [e1], "horizontal_scan", "network_scanning")
    i2 = _incident("INC-RDP", s2, [e2], "rdp_probe", "service_probing")
    return [e1, e2], [s1, s2], [i1, i2]


def test_created_then_merged_promotion_is_not_hidden(session_factory) -> None:
    settings = make_settings(enabled=True)
    events, signals, incidents = _promotion_campaign()

    result = run_job(
        session_factory, settings, job_id="job-1",
        events=events, signals=signals, incidents=incidents, run_triage=False,
    )

    # Two incoming incidents converge on one canonical; one is absorbed.
    m = result.stateful_metrics
    assert m["incoming_batch_incident_count"] == 2
    assert m["final_canonical_incident_count"] == 1
    assert m["stateful_created_count"] == 1
    assert m["stateful_merged_count"] == 1
    assert m["absorbed_batch_incident_count"] == 1

    # Routing ran once for the single final canonical incident.
    assert len(result.incidents) == 1
    assert [s.get("incident_id") for s in result.incidents] == ["INC-HS"]

    with session_factory() as session:
        incidents_rows = session.query(Incident).all()
        assert [i.incident_id for i in incidents_rows] == ["INC-HS"]
        # The later rdp_probe promoted the canonical identity.
        assert incidents_rows[0].incident_type == "rdp_probe"

        actions = {a.action for a in session.query(AuditEvent).all()}
        assert "stateful_correlation_created" in actions
        assert "stateful_correlation_merged" in actions
        # The promotion came from the SECOND result and must still be audited.
        assert "stateful_identity_promoted" in actions

        # The merged audit row carries the combined/unioned material changes.
        merged_rows = [
            a for a in session.query(AuditEvent).all()
            if a.action == "stateful_correlation_merged"
        ]
        assert merged_rows
        assert "primary_identity_promoted" in merged_rows[0].details["material_changes"]

        # The absorbed incoming incident leaves no row, report, or projection.
        assert session.get(Incident, "INC-RDP") is None
        assert session.execute(
            select(SearchIndexOutbox).where(
                SearchIndexOutbox.entity_type == "incident",
                SearchIndexOutbox.entity_id == "INC-RDP",
            )
        ).first() is None
        # Detect mode: no reports/triage runs at all.
        assert session.query(Report).count() == 0
        assert session.query(TriageRun).count() == 0


def test_promotion_campaign_triages_once_in_analyze_mode(
    session_factory, fake_app, monkeypatch
) -> None:
    """The provider is invoked at most once for the single final canonical
    incident even though two incoming incidents resolved to it."""
    import agent.application.analysis_service as svc_mod
    from agent.triage.routing import RoutingDecision

    monkeypatch.setattr(
        svc_mod, "decide_route",
        lambda *a, **k: RoutingDecision(
            route="individual_triage", reason="forced",
            triage_origin="llm", llm_invoked=True,
        ),
    )

    settings = make_settings(enabled=True)
    events, signals, incidents = _promotion_campaign()
    result = run_job(
        session_factory, settings, job_id="job-1",
        events=events, signals=signals, incidents=incidents, run_triage=True,
    )

    assert fake_app.calls == 1
    assert result.routing_metrics["provider_invocation_count"] == 1
    with session_factory() as session:
        assert session.query(Report).filter_by(incident_id="INC-RDP").count() == 0
        assert session.query(Report).filter_by(incident_id="INC-HS").count() == 1
