from agent.detection.config import DetectionSettings
from agent.detection.models import DetectionSignal
from agent.detection.scoring import (
    calculate_incident_severity,
    derive_incident_severity_facts,
)
from tests.detection.helpers import FIXED_TIME, build_event


def _signal(*, family: str, severity: str, event_ids: list[str]) -> DetectionSignal:
    return DetectionSignal(
        signal_id=f"sig-{family}-{severity}",
        rule_id="test_rule",
        rule_version="1.0.0",
        rule_name="Test Rule",
        signal_type="test_signal",
        signal_family=family,
        severity=severity,
        confidence=0.8,
        first_seen=FIXED_TIME,
        last_seen=FIXED_TIME,
        primary_entity="203.0.113.10",
        target_entities=[],
        event_ids=event_ids,
        evidence=[],
        metrics={},
        mitre_techniques=[],
        tags=[],
    )


def _severity(events, *, family: str, signal_severity: str = "high") -> str:
    facts = derive_incident_severity_facts(events, family=family)
    signal = _signal(
        family=family,
        severity=signal_severity,
        event_ids=[event.event_id for event in events],
    )
    return calculate_incident_severity(
        [signal], signal.primary_entity, DetectionSettings(), facts=facts
    )


def test_fully_blocked_probe_is_low_even_when_rule_signal_is_high() -> None:
    events = [
        build_event(f"e-{index}", dst_ip=f"198.51.100.{index}", dst_port=3389)
        for index in range(1, 20)
    ]
    assert _severity(events, family="service_probing") == "low"


def test_broad_fully_blocked_recon_is_capped_at_medium() -> None:
    events = [
        build_event(f"e-{index}", dst_ip=f"198.51.100.{index}", dst_port=10086)
        for index in range(1, 39)
    ]
    assert _severity(events, family="network_scanning") == "medium"


def test_allowed_sensitive_service_outranks_blocked_recon() -> None:
    event = build_event(
        "allowed-rdp",
        action="pass",
        dst_ip="10.0.0.10",
        dst_port=3389,
    )
    assert _severity([event], family="firewall_exposure", signal_severity="medium") == "high"


def test_allowed_critical_management_service_is_critical() -> None:
    event = build_event(
        "allowed-redis",
        action="pass",
        dst_ip="10.0.0.10",
        dst_port=6379,
    )
    assert _severity([event], family="firewall_exposure", signal_severity="high") == "critical"


def test_allowed_ipmi_management_service_is_critical() -> None:
    event = build_event(
        "allowed-ipmi",
        action="pass",
        dst_ip="10.0.0.10",
        dst_port=623,
    )
    assert _severity([event], family="firewall_exposure", signal_severity="high") == "critical"


def test_unrelated_family_keeps_signal_based_severity() -> None:
    event = build_event("dos", action="block", dst_port=443)
    assert _severity([event], family="network_dos", signal_severity="high") == "high"
