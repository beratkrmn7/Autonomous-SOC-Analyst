from datetime import timedelta

from agent.detection.models import DetectionSignal, IncidentBundle
from agent.detection.rollup import build_rollup
from tests.detection.helpers import FIXED_TIME, build_event


def _incident(
    incident_id: str,
    event_ids: list[str],
    *,
    family: str = "network_scanning",
    incident_type: str = "subnet_sweep",
    severity: str = "medium",
    allowed: int = 0,
    blocked: int | None = None,
    first_offset: int = 0,
) -> IncidentBundle:
    blocked = len(event_ids) if blocked is None else blocked
    return IncidentBundle(
        incident_id=incident_id,
        incident_type=incident_type,
        incident_family=family,
        title=f"Detected {incident_type}",
        severity=severity,
        confidence=0.8,
        first_seen=FIXED_TIME + timedelta(seconds=first_offset),
        last_seen=FIXED_TIME + timedelta(seconds=first_offset + 10),
        primary_entity="212.73.148.1",
        target_entities=[],
        signal_ids=[f"sig-{incident_id}"],
        event_ids=event_ids,
        context_event_ids=[],
        evidence=[],
        metrics={
            "allowed_event_count": allowed,
            "blocked_event_count": blocked,
            "severity_total_event_count": len(event_ids),
        },
        mitre_techniques=[],
        merge_key=incident_id,
        absorbed_signal_ids=[],
    )


def test_compatible_fully_blocked_sources_collapse_to_one_recon_group() -> None:
    events = [
        build_event(
            f"e-{index}",
            src_ip=f"212.73.148.{index + 1}",
            dst_ip=f"198.51.100.{index + 1}",
            dst_port=10086,
            action="block",
            timestamp=FIXED_TIME + timedelta(seconds=index),
        )
        for index in range(30)
    ]
    incidents = [
        _incident(f"inc-{index}", [event.event_id], first_offset=index)
        for index, event in enumerate(events)
    ]
    rollup = build_rollup(incidents, {event.event_id: event for event in events})

    assert len(rollup.recon_groups) == 1
    group = rollup.recon_groups[0]
    assert group.source_cidr == "212.73.148.0/24"
    assert group.source_count == 30
    assert group.total_event_count == 30
    assert group.distinct_target_count == 30


def test_same_subnet_alone_does_not_merge_incompatible_scope_or_time() -> None:
    first = build_event(
        "ssh", src_ip="203.0.113.1", dst_port=22, action="block"
    )
    second = build_event(
        "rdp",
        src_ip="203.0.113.2",
        dst_port=3389,
        action="block",
        timestamp=FIXED_TIME + timedelta(seconds=1),
    )
    late = build_event(
        "late-ssh",
        src_ip="203.0.113.3",
        dst_port=22,
        action="block",
        timestamp=FIXED_TIME + timedelta(hours=1),
    )
    incidents = [
        _incident("ssh", ["ssh"]),
        _incident("rdp", ["rdp"], incident_type="rdp_probe"),
        _incident("late", ["late-ssh"], first_offset=3600),
    ]
    rollup = build_rollup(
        incidents,
        {event.event_id: event for event in (first, second, late)},
    )
    assert len(rollup.recon_groups) == 3


def test_mixed_or_passed_campaign_is_actionable_and_never_blocked_fyi() -> None:
    events = [
        build_event("blocked", action="block", dst_port=10086),
        build_event("passed", action="pass", dst_port=10086),
    ]
    incident = _incident(
        "mixed",
        [event.event_id for event in events],
        severity="medium",
        allowed=1,
        blocked=1,
    )
    rollup = build_rollup([incident], {event.event_id: event for event in events})

    assert rollup.recon_groups == ()
    assert [item.incident_id for item in rollup.investigate] == ["mixed"]


def test_asset_inventory_and_funnel_use_allowed_effective_destination() -> None:
    event = build_event(
        "dnat",
        src_ip="8.8.8.8",
        dst_ip="203.0.113.20",
        dst_port=443,
        translated_dst_ip="10.0.0.20",
        translated_dst_port=6379,
        inbound_zone="wan1-zone",
        action="pass",
    )
    incident = _incident(
        "exposure",
        [event.event_id],
        family="firewall_exposure",
        incident_type="dnat_sensitive_service_exposure",
        severity="critical",
        allowed=1,
        blocked=0,
    )
    rollup = build_rollup([incident], {event.event_id: event})

    assert rollup.funnel == {
        "total_events": 1,
        "blocked_events": 0,
        "policy_exposures": 1,
        "action_items": 1,
    }
    asset = rollup.exposed_assets[0]
    assert asset.effective_destination_ip == "10.0.0.20"
    assert asset.service == "redis"
    assert asset.nat_observed is True
    assert asset.internal_address == "10.0.0.20"
    assert asset.public_destinations == ("203.0.113.20",)


def test_suppressed_entries_are_bounded_and_preserve_reason() -> None:
    signal = DetectionSignal(
        signal_id="suppressed",
        rule_id="spi_anomaly_burst",
        rule_version="1.0.0",
        rule_name="SPI Anomaly Burst",
        signal_type="spi_anomaly",
        signal_family="network_anomaly",
        severity="medium",
        confidence=0.8,
        first_seen=FIXED_TIME,
        last_seen=FIXED_TIME,
        primary_entity="20.190.147.7",
        target_entities=[f"198.51.100.{index}" for index in range(10)],
        event_ids=["e1"],
        metrics={},
        evidence=[],
        mitre_techniques=[],
        tags=[],
        suppressed=True,
        suppression_reason="late_rst_from_established_service",
    )
    rollup = build_rollup([], {}, suppressed_signals=[signal])
    assert rollup.suppressed[0].reason == "late_rst_from_established_service"
    assert len(rollup.suppressed[0].targets) == 5
