from datetime import datetime, timezone

from agent.application.analysis_service import AnalysisService
from agent.detection.models import DetectionSignal, IncidentBundle
from agent.schema import CanonicalLogEvent
from agent.triage.models import TriageIncidentContext


NOW = datetime(2026, 7, 10, 9, 54, tzinfo=timezone.utc)


def _event(event_id: str) -> CanonicalLogEvent:
    return CanonicalLogEvent(
        event_id=event_id,
        timestamp=NOW,
        parser_name="pf_firewall",
        parse_status="parsed",
        source_name="firewall.json",
    )


def test_analysis_service_builds_complete_triage_context() -> None:
    primary = _event("event-primary")
    context = _event("event-context")
    signal = DetectionSignal(
        signal_id="signal-1",
        rule_id="network_scan_horizontal",
        rule_version="1.0.0",
        rule_name="Horizontal Port Scan",
        signal_type="horizontal_scan",
        signal_family="network_scanning",
        severity="high",
        confidence=0.91,
        first_seen=NOW,
        last_seen=NOW,
        event_ids=[primary.event_id],
        primary_entity="192.0.2.10",
        target_entities=["198.51.100.20"],
        metrics={},
        evidence=[],
        mitre_techniques=["T1046"],
        tags=["network", "scan"],
    )
    incident = IncidentBundle(
        incident_id="incident-1",
        incident_type="horizontal_scan",
        incident_family="network_scanning",
        title="Horizontal port scan",
        severity="high",
        confidence=0.91,
        first_seen=NOW,
        last_seen=NOW,
        primary_entity="192.0.2.10",
        target_entities=["198.51.100.20"],
        signal_ids=[signal.signal_id],
        event_ids=[primary.event_id],
        context_event_ids=[context.event_id],
        evidence=[],
        metrics={},
        mitre_techniques=["T1046"],
        merge_key="network:192.0.2.10",
    )

    state = AnalysisService()._build_initial_state(
        incident,
        {primary.event_id: primary, context.event_id: context},
        {signal.signal_id: signal},
    )

    triage_context = TriageIncidentContext.model_validate(state["incident"])
    assert triage_context.incident.incident_id == incident.incident_id
    assert [event.event_id for event in triage_context.events] == [primary.event_id]
    assert [event.event_id for event in triage_context.context_events] == [
        context.event_id
    ]
    assert state["canonical_events"][0]["event_id"] == primary.event_id
    assert state["detected_signals"] == [
        {
            "detector_name": "Horizontal Port Scan",
            "rule_name": "Horizontal Port Scan",
            "status": "alert",
            "message": "Horizontal Port Scan detected. Severity: high",
            "description": "Horizontal Port Scan detected",
            "severity": "high",
            "confidence_score": 0.91,
            "mitre_techniques": ["T1046"],
            "matched_event_ids": [primary.event_id],
        }
    ]
