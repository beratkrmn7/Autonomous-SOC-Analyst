import datetime

from agent.detection.models import IncidentBundle
from agent.nodes import (
    action_recommendation_node,
    evidence_validation_node,
    reporter_node,
)
from agent.schema import CanonicalLogEvent
from agent.triage.input_builder import build_triage_input
from agent.triage.models import TriageIncidentContext


def _blocked_scan_state() -> dict:
    first_seen = datetime.datetime(2026, 7, 10, 6, 53, 39, tzinfo=datetime.timezone.utc)
    events = [
        CanonicalLogEvent(
            event_id=f"event-{index}",
            timestamp=first_seen + datetime.timedelta(seconds=index),
            observed_at=first_seen,
            src_ip="5.187.35.142",
            dst_ip=f"193.255.131.{index}",
            dst_port=4567,
            protocol="tcp",
            action="block",
            tcp_flags="SYN",
            parser_name="pf_firewall",
            parse_status="parsed",
            source_name="firewall.json",
            safe_message_excerpt=(
                f"BLOCK TCP 5.187.35.142 -> 193.255.131.{index}:4567 flags=S"
            ),
        )
        for index in (1, 2)
    ]
    incident = IncidentBundle(
        incident_id="INC-SCAN",
        incident_type="horizontal_scan",
        incident_family="network_scanning",
        title="Detected horizontal scan",
        severity="medium",
        confidence=0.6,
        first_seen=events[0].timestamp,
        last_seen=events[-1].timestamp,
        primary_entity="5.187.35.142",
        target_entities=[event.dst_ip for event in events if event.dst_ip],
        signal_ids=["SIG-1"],
        event_ids=[event.event_id for event in events],
        context_event_ids=[],
        evidence=[],
        metrics={"total_events": 2, "distinct_targets": 2},
        mitre_techniques=["T1046"],
        merge_key="network_scanning_1",
    )
    context = TriageIncidentContext(incident=incident, events=events)
    evidence = {
        "event_id": events[0].event_id,
        "quote": events[0].safe_message_excerpt,
        "reason": "Horizontal scan evidence",
        "source": "pf_firewall",
        "original_fields": {},
        "correlation_context": {},
    }
    triage_input = build_triage_input(context, [], [evidence])
    evidence_id = triage_input.candidate_evidence[0].evidence_id

    return {
        "incident_id": incident.incident_id,
        "incident": context.model_dump(mode="json"),
        "triage_submission": {
            "triage_verdict": "confirmed_incident",
            "incident_type": "horizontal_scan",
            "severity": "medium",
            "confidence_score": 0.6,
            "summary": "Model incorrectly estimated 999 targets.",
            "selected_evidence_ids": [evidence_id],
            "claims": [],
        },
        "triage_verdict": "confirmed_incident",
        "incident_type": "horizontal_scan",
        "severity": "medium",
        "confidence_score": 0.6,
        "safe_triage_input": triage_input.model_dump(mode="json"),
        "review_reason": "none",
    }


def test_all_blocked_scan_caps_verdict_and_uses_safe_actions():
    state = _blocked_scan_state()

    validation = evidence_validation_node(state)
    state.update(validation)
    actions = action_recommendation_node(state)
    state.update(actions)

    assert state["triage_verdict"] == "suspicious_activity"
    assert state["triage_submission"]["triage_verdict"] == "suspicious_activity"
    assert state["policy_adjustments"] == [
        "all_blocked_network_verdict_capped"
    ]
    assert len(state["validated_evidence"]) == 1
    assert not any("isolate" in action.lower() for action in actions["recommended_actions"])
    assert actions["mitre_techniques"] == ["T1046 - Network Service Discovery"]


def test_network_report_uses_deterministic_counts_and_actions():
    state = _blocked_scan_state()
    state.update(evidence_validation_node(state))
    state.update(action_recommendation_node(state))

    report = reporter_node(state)["final_report"]

    assert "SUSPICIOUS_ACTIVITY" in report
    assert "Event count: 2" in report
    assert "Distinct target count: 2" in report
    assert "Destination ports: 4567" in report
    assert "All attempts blocked: yes" in report
    assert "999" not in report
    assert "Isolate affected hosts" not in report
    assert "Review firewall and network telemetry" in report
