"""Focused tests for agent.triage.routing.decide_route and report wording.

Covers the merge-blocker fixes: non-fully-blocked incidents must never get a
deterministic "all blocked" report, and a verified SPI ACK,RST flow with a
related allowed HTTPS/NAT flow must route to store_only.
"""

from agent.detection.config import DetectionSettings
from agent.detection.models import IncidentBundle
from agent.triage.routing import (
    DETERMINISTIC_TRIAGE_VERDICT,
    decide_route,
    generate_deterministic_report,
)
from tests.detection.helpers import FIXED_TIME, build_pf_event


def _incident(**overrides: object) -> IncidentBundle:
    values: dict = dict(
        incident_id="incident-1",
        incident_type="test_incident",
        incident_family="service_probing",
        title="Test incident",
        severity="high",
        confidence=0.6,
        first_seen=FIXED_TIME,
        last_seen=FIXED_TIME,
        primary_entity="203.0.113.5",
        target_entities=[],
        signal_ids=["signal-1"],
        event_ids=[],
        context_event_ids=[],
        evidence=[],
        metrics={},
        mitre_techniques=[],
        merge_key="service_probing:203.0.113.5",
    )
    values.update(overrides)
    return IncidentBundle(**values)


def test_spi_ack_rst_flow_with_related_allowed_https_flow_routes_to_store_only() -> None:
    spi_event = build_pf_event(
        "spi-response",
        spi=True,
        timestamp=FIXED_TIME,
        action="block",
        protocol="TCP",
        tcp_flags="ACK,RST",
        src_ip="203.0.113.5",
        src_port=443,
        dst_ip="192.0.2.10",
        dst_port=51000,
    )
    allowed_context_event = build_pf_event(
        "allowed-request",
        spi=False,
        timestamp=FIXED_TIME,
        action="allow",
        protocol="TCP",
        tcp_flags="SYN",
        src_ip="192.0.2.10",
        src_port=52222,
        dst_ip="203.0.113.5",
        dst_port=443,
    )
    incident = _incident(
        incident_family="network_anomaly",
        event_ids=[spi_event.event_id],
    )

    decision = decide_route(
        incident,
        [spi_event],
        [allowed_context_event],
        frozenset({"spi_anomaly_burst"}),
        DetectionSettings(),
    )

    assert decision.route == "store_only"
    assert decision.triage_origin == "none"
    assert decision.llm_invoked is False


def test_spi_ack_rst_flow_with_related_allowed_udp_flow_does_not_route_to_store_only() -> None:
    spi_event = build_pf_event(
        "spi-response",
        spi=True,
        timestamp=FIXED_TIME,
        action="block",
        protocol="TCP",
        tcp_flags="ACK,RST",
        src_ip="203.0.113.5",
        src_port=443,
        dst_ip="192.0.2.10",
        dst_port=51000,
    )
    allowed_udp_context_event = build_pf_event(
        "allowed-udp",
        spi=False,
        timestamp=FIXED_TIME,
        action="allow",
        protocol="UDP",
        src_ip="192.0.2.10",
        src_port=52222,
        dst_ip="203.0.113.5",
        dst_port=443,
    )
    incident = _incident(
        incident_family="network_anomaly",
        event_ids=[spi_event.event_id],
    )

    decision = decide_route(
        incident,
        [spi_event],
        [allowed_udp_context_event],
        frozenset({"spi_anomaly_burst"}),
        DetectionSettings(),
    )

    assert decision.route != "store_only"


def test_non_fully_blocked_incident_routes_conservatively_to_individual_triage() -> None:
    blocked = build_pf_event(
        "blocked-1",
        spi=False,
        timestamp=FIXED_TIME,
        action="block",
        protocol="TCP",
        tcp_flags="SYN",
        dst_ip="198.51.100.1",
        dst_port=445,
    )
    unrecognized_action = build_pf_event(
        "unknown-action-1",
        spi=False,
        timestamp=FIXED_TIME,
        action="monitor",
        protocol="TCP",
        tcp_flags="SYN",
        dst_ip="198.51.100.2",
        dst_port=445,
    )
    incident = _incident(event_ids=[blocked.event_id, unrecognized_action.event_id])

    decision = decide_route(
        incident,
        [blocked, unrecognized_action],
        [],
        frozenset({"smb_probe"}),
        DetectionSettings(),
    )

    assert decision.route == "individual_triage"
    assert decision.llm_invoked is True


def test_empty_evidence_incident_routes_to_individual_triage() -> None:
    incident = _incident(event_ids=[])

    decision = decide_route(incident, [], [], frozenset(), DetectionSettings())

    assert decision.route == "individual_triage"
    assert decision.llm_invoked is True


def test_deterministic_report_uses_suspicious_activity_verdict() -> None:
    events = [
        build_pf_event(
            f"blocked-{i}",
            spi=False,
            timestamp=FIXED_TIME,
            action="block",
            protocol="TCP",
            tcp_flags="SYN",
            dst_ip=f"198.51.100.{i + 1}",
            dst_port=445,
        )
        for i in range(3)
    ]
    incident = _incident(event_ids=[event.event_id for event in events])

    decision = decide_route(
        incident, events, [], frozenset({"smb_probe"}), DetectionSettings()
    )
    report = generate_deterministic_report(incident, events)

    assert decision.route == "deterministic_report"
    assert decision.triage_origin == "deterministic"
    assert decision.llm_invoked is False
    assert DETERMINISTIC_TRIAGE_VERDICT == "suspicious_activity"
    assert "All 3 observed event(s) were blocked" in report


def test_deterministic_report_wording_never_claims_all_blocked_when_not() -> None:
    blocked = build_pf_event(
        "blocked-1", spi=False, timestamp=FIXED_TIME, action="block", dst_port=445
    )
    allowed = build_pf_event(
        "allowed-1", spi=False, timestamp=FIXED_TIME, action="allow", dst_port=445
    )
    incident = _incident(event_ids=[blocked.event_id, allowed.event_id])

    report = generate_deterministic_report(incident, [blocked, allowed])

    assert "All 2 observed event(s) were blocked" not in report
    assert "1 of 2 observed event(s) were blocked" in report
