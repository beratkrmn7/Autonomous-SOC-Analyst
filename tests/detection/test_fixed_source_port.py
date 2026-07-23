"""T-C: fixed-source-port scanning is surfaced without growing the registry."""

from __future__ import annotations

from agent.detection.config import DetectionSettings
from agent.detection.detectors.exposure_helpers import (
    SENSITIVE_SERVICE_PORTS,
    is_explicit_wan_zone,
)
from agent.detection.detectors.scan_helpers import find_fixed_source_port_groups
from agent.detection.fixed_source_port_cluster import (
    CLUSTER_TACTIC,
    CLUSTER_TECHNIQUE,
    build_fixed_source_port_clusters,
)
from agent.detection.registry import default_registry

from tests.fixtures.sanitized_real_log import (
    FILE0_EVENTS,
    FILE1_EVENTS,
    FIXED_SOURCE_PORT,
    FSP_SOURCE_BLOCKED,
    FSP_SOURCE_CANONICAL_A,
    FSP_SOURCE_CLUSTER_A,
    FSP_SOURCE_CLUSTER_B,
    FSP_SOURCE_NO_FLAGS,
)


SETTINGS = DetectionSettings()


def _groups(events):
    return find_fixed_source_port_groups(
        events,
        source_ports=SETTINGS.FIXED_SOURCE_PORT_SCAN_PORTS,
        min_events=SETTINGS.FIXED_SOURCE_PORT_SCAN_MIN_EVENTS,
        min_distinct_destination_ports=(
            SETTINGS.FIXED_SOURCE_PORT_SCAN_MIN_DISTINCT_PORTS
        ),
        window_seconds=SETTINGS.FIXED_SOURCE_PORT_SCAN_WINDOW_SECONDS,
        is_external_inbound=lambda event: is_explicit_wan_zone(event.inbound_zone),
    )


def _all_groups(events):
    """Every exact-source group, including sub-threshold ones."""
    return find_fixed_source_port_groups(
        events,
        source_ports=SETTINGS.FIXED_SOURCE_PORT_SCAN_PORTS,
        min_events=1,
        min_distinct_destination_ports=1,
        window_seconds=SETTINGS.FIXED_SOURCE_PORT_SCAN_WINDOW_SECONDS,
        is_external_inbound=lambda event: is_explicit_wan_zone(event.inbound_zone),
    )


def test_registry_count_is_unchanged() -> None:
    from agent.detection.engine import DetectionEngine

    assert len(DetectionEngine().registry.get_all_rules()) == 36


def test_canonical_exact_source_findings_require_five_syn_events() -> None:
    groups = {group.source_ip: group for group in _groups(FILE0_EVENTS)}
    # Only the source with 7 observed SYN events qualifies.
    assert set(groups) == {FSP_SOURCE_CANONICAL_A}
    assert groups[FSP_SOURCE_CANONICAL_A].event_count == 7
    assert groups[FSP_SOURCE_CANONICAL_A].source_port == FIXED_SOURCE_PORT
    assert len(groups[FSP_SOURCE_CANONICAL_A].destination_ports) == 7


def test_events_without_tcp_flags_are_not_claimed_as_syn_probes() -> None:
    """5 events across 5 ports, but no recorded SYN, so no scan is claimed."""
    assert FSP_SOURCE_NO_FLAGS not in {
        group.source_ip for group in _all_groups(FILE0_EVENTS)
    }


def test_sub_threshold_sources_are_not_canonical_findings() -> None:
    canonical = {group.source_ip for group in _groups(FILE1_EVENTS)}
    # 3-event and 4-event sources must not stand alone as canonical findings.
    assert FSP_SOURCE_CLUSTER_A not in canonical
    assert FSP_SOURCE_CLUSTER_B not in canonical
    assert FSP_SOURCE_BLOCKED not in canonical


def test_file1_cluster_preserves_exact_sources_and_counts() -> None:
    clusters = build_fixed_source_port_clusters(
        _all_groups(FILE1_EVENTS),
        min_sources=SETTINGS.FIXED_SOURCE_PORT_CLUSTER_MIN_SOURCES,
        min_events_per_source=(
            SETTINGS.FIXED_SOURCE_PORT_CLUSTER_MIN_EVENTS_PER_SOURCE
        ),
        min_total_events=SETTINGS.FIXED_SOURCE_PORT_CLUSTER_MIN_TOTAL_EVENTS,
        window_seconds=SETTINGS.FIXED_SOURCE_PORT_CLUSTER_WINDOW_SECONDS,
        sensitive_ports=SENSITIVE_SERVICE_PORTS,
    )
    assert len(clusters) == 1
    cluster = clusters[0]

    # 7 allowed events, contributed by two exact sources.
    assert cluster.allowed_event_count == 7
    assert cluster.event_count == 7
    assert cluster.fixed_source_port == 443
    assert cluster.contributing_source_ips == (
        FSP_SOURCE_CLUSTER_A,
        FSP_SOURCE_CLUSTER_B,
    )
    assert cluster.source_count == 2
    assert cluster.distinct_destination_ip_count == 2
    # Union of {443, 3306, 3389} and {22, 80, 179, 3306}.
    assert cluster.distinct_destination_port_count == 6

    # Deterministic ATT&CK, technique and tactic in separate fields.
    assert cluster.mitre_technique == CLUSTER_TECHNIQUE == "T1046"
    assert cluster.mitre_tactic == CLUSTER_TACTIC == "TA0007"

    # The blocked scanner ran in a disjoint window and is not absorbed.
    assert FSP_SOURCE_BLOCKED not in cluster.contributing_source_ips
    assert cluster.blocked_event_count == 0

    # The /24 is never presented as the attacker identity on its own.
    assert cluster.source_cidr.endswith("/24")
    assert cluster.source_cidr not in cluster.contributing_source_ips


def test_blocked_scanner_is_reported_separately_from_allowed_cluster() -> None:
    blocked_groups = [
        group
        for group in _all_groups(FILE1_EVENTS)
        if group.source_ip == FSP_SOURCE_BLOCKED
    ]
    assert len(blocked_groups) == 1
    blocked = blocked_groups[0]
    assert blocked.blocked_event_count == 4
    assert blocked.allowed_event_count == 0


def test_cluster_requires_two_distinct_exact_sources() -> None:
    single_source = [
        group
        for group in _all_groups(FILE1_EVENTS)
        if group.source_ip == FSP_SOURCE_CLUSTER_A
    ]
    clusters = build_fixed_source_port_clusters(
        single_source,
        min_sources=2,
        min_events_per_source=3,
        min_total_events=7,
        window_seconds=60,
        sensitive_ports=SENSITIVE_SERVICE_PORTS,
    )
    assert clusters == ()


def test_events_are_deduplicated_by_event_id() -> None:
    duplicated = list(FILE0_EVENTS) + list(FILE0_EVENTS)
    groups = {group.source_ip: group for group in _groups(duplicated)}
    assert groups[FSP_SOURCE_CANONICAL_A].event_count == 7


def test_registry_rule_ids_are_unchanged() -> None:
    from agent.detection.engine import DetectionEngine

    rule_ids = {rule.rule_id for rule in DetectionEngine().registry.get_all_rules()}
    assert "fixed_source_port_scan" not in rule_ids
    assert "network_scan_vertical" in rule_ids
    assert default_registry is not None
