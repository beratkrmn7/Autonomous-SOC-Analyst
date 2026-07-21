"""Phase 6E.4A focused tests: StatefulCorrelationProfile derivation and
deterministic correlation-key generation (required tests 1-10)."""

from __future__ import annotations

import datetime

from agent.correlation.stateful import compute_correlation_key, derive_stateful_profile
from agent.detection.models import IncidentBundle
from agent.schema import CanonicalLogEvent


FIXED = datetime.datetime(2026, 7, 10, 6, 0, 0, tzinfo=datetime.timezone.utc)


def _event(event_id: str, **overrides) -> CanonicalLogEvent:
    values = dict(
        event_id=event_id,
        timestamp=FIXED,
        src_ip="203.0.113.10",
        dst_ip="10.0.0.5",
        dst_port=3389,
        protocol="TCP",
        action="block",
        parser_name="pf_firewall",
        parse_status="parsed",
        source_name="firewall.json",
        safe_message_excerpt="BLOCK TCP 203.0.113.10 -> 10.0.0.5:3389",
    )
    values.update(overrides)
    return CanonicalLogEvent(**values)


def _incident(events: list[CanonicalLogEvent], **overrides) -> IncidentBundle:
    values = dict(
        incident_id="INC-TEST",
        incident_type="rdp_probe",
        incident_family="service_probing",
        title="Detected RDP Probe from 203.0.113.10",
        severity="medium",
        confidence=0.6,
        first_seen=events[0].timestamp,
        last_seen=events[-1].timestamp,
        primary_entity="203.0.113.10",
        target_entities=["10.0.0.5"],
        signal_ids=["SIG-1"],
        event_ids=[e.event_id for e in events],
        context_event_ids=[],
        evidence=[],
        metrics={},
        mitre_techniques=[],
        merge_key="m1",
    )
    values.update(overrides)
    return IncidentBundle(**values)


def _profile(events, **incident_overrides):
    incident = _incident(events, **incident_overrides)
    return derive_stateful_profile(
        incident, events, correlation_version="1", max_profile_items=20
    )


# --- 1: identical profiles produce identical keys regardless of input order


def test_identical_profiles_produce_identical_keys_regardless_of_ordering() -> None:
    events_forward = [_event("e1"), _event("e2", dst_port=3389)]
    events_reversed = list(reversed(events_forward))

    incident_forward = _incident(events_forward, event_ids=["e1", "e2"])
    incident_reversed = _incident(events_reversed, event_ids=["e2", "e1"])

    p1 = derive_stateful_profile(
        incident_forward, events_forward, correlation_version="1", max_profile_items=20
    )
    p2 = derive_stateful_profile(
        incident_reversed, events_reversed, correlation_version="1", max_profile_items=20
    )

    assert p1 is not None and p2 is not None
    assert compute_correlation_key(p1) == compute_correlation_key(p2)


# --- 2: RDP activity from the same source in two jobs with different event
# IDs produces the same source-service profile


def test_rdp_same_source_two_jobs_different_event_ids_same_profile() -> None:
    events_job_a = [_event("a1"), _event("a2")]
    events_job_b = [_event("b1", timestamp=FIXED + datetime.timedelta(minutes=5))]

    profile_a = _profile(events_job_a, incident_id="INC-A", event_ids=["a1", "a2"])
    profile_b = _profile(events_job_b, incident_id="INC-B", event_ids=["b1"])

    assert profile_a is not None and profile_b is not None
    assert compute_correlation_key(profile_a) == compute_correlation_key(profile_b)


# --- 3: RDP and SSH activity from the same source produce different profiles


def test_rdp_and_ssh_same_source_produce_different_profiles() -> None:
    rdp_events = [_event("r1", dst_port=3389)]
    ssh_events = [_event("s1", dst_port=22)]

    rdp_profile = _profile(rdp_events, incident_type="rdp_probe", event_ids=["r1"])
    ssh_profile = _profile(ssh_events, incident_type="ssh_probe", event_ids=["s1"])

    assert rdp_profile is not None and ssh_profile is not None
    assert compute_correlation_key(rdp_profile) != compute_correlation_key(ssh_profile)


# --- 4: same source IP without compatible service/port/protocol does not
# correlate (no profile at all - fails closed)


def test_same_source_without_service_or_port_does_not_correlate() -> None:
    events = [_event("n1", dst_port=None, protocol="ICMP", action="allow")]
    profile = _profile(
        events, incident_type="horizontal_scan", incident_family="network_scanning", event_ids=["n1"]
    )
    assert profile is None


# --- 5: horizontal scan continuation may correlate across different target
# sets when source, protocol and destination service/port match


def test_horizontal_scan_continuation_correlates_across_different_targets() -> None:
    events_a = [_event("ha1", dst_ip="10.0.0.1", dst_port=3389)]
    events_b = [_event("hb1", dst_ip="10.0.0.99", dst_port=3389)]

    profile_a = _profile(
        events_a,
        incident_id="INC-HA",
        incident_type="horizontal_scan",
        incident_family="network_scanning",
        target_entities=["10.0.0.1"],
        event_ids=["ha1"],
    )
    profile_b = _profile(
        events_b,
        incident_id="INC-HB",
        incident_type="horizontal_scan",
        incident_family="network_scanning",
        target_entities=["10.0.0.99"],
        event_ids=["hb1"],
    )

    assert profile_a is not None and profile_b is not None
    assert compute_correlation_key(profile_a) == compute_correlation_key(profile_b)


# --- 6: vertical or target-specific activity against different destinations
# does not correlate


def test_vertical_scan_against_different_destinations_does_not_correlate() -> None:
    events_a = [_event("va1", dst_ip="10.0.0.1", dst_port=3389)]
    events_b = [_event("vb1", dst_ip="10.0.0.2", dst_port=3389)]

    profile_a = _profile(
        events_a,
        incident_id="INC-VA",
        incident_type="vertical_scan",
        incident_family="network_scanning",
        target_entities=["10.0.0.1"],
        event_ids=["va1"],
    )
    profile_b = _profile(
        events_b,
        incident_id="INC-VB",
        incident_type="vertical_scan",
        incident_family="network_scanning",
        target_entities=["10.0.0.2"],
        event_ids=["vb1"],
    )

    assert profile_a is not None and profile_b is not None
    assert compute_correlation_key(profile_a) != compute_correlation_key(profile_b)


# --- 7: two exposure incidents from different public sources to the same
# effective Redis destination produce the same protected-service profile


def test_exposure_different_sources_same_redis_destination_same_profile() -> None:
    events_a = [
        _event(
            "xa1",
            src_ip="8.8.8.8",
            dst_ip="203.0.113.50",
            dst_port=6379,
            translated_dst_ip="10.0.0.60",
            translated_dst_port=6379,
            action="allow",
        )
    ]
    events_b = [
        _event(
            "xb1",
            src_ip="9.9.9.9",
            dst_ip="203.0.113.51",
            dst_port=6379,
            translated_dst_ip="10.0.0.60",
            translated_dst_port=6379,
            action="allow",
        )
    ]

    profile_a = _profile(
        events_a,
        incident_id="INC-XA",
        incident_type="dnat_sensitive_service_exposure",
        incident_family="firewall_exposure",
        primary_entity="10.0.0.60",
        event_ids=["xa1"],
    )
    profile_b = _profile(
        events_b,
        incident_id="INC-XB",
        incident_type="dnat_sensitive_service_exposure",
        incident_family="firewall_exposure",
        primary_entity="10.0.0.60",
        event_ids=["xb1"],
    )

    assert profile_a is not None and profile_b is not None
    assert profile_a.actor_entity is None
    assert profile_b.actor_entity is None
    assert compute_correlation_key(profile_a) == compute_correlation_key(profile_b)


# --- 8: the same destination with Redis and SSH produces different profiles


def test_exposure_same_destination_redis_vs_ssh_different_profiles() -> None:
    redis_events = [
        _event(
            "rd1",
            dst_ip="203.0.113.50",
            dst_port=6379,
            translated_dst_ip="10.0.0.60",
            translated_dst_port=6379,
            action="allow",
        )
    ]
    ssh_events = [
        _event(
            "sh1",
            dst_ip="203.0.113.50",
            dst_port=22,
            translated_dst_ip="10.0.0.60",
            translated_dst_port=22,
            action="allow",
        )
    ]

    redis_profile = _profile(
        redis_events,
        incident_id="INC-RD",
        incident_type="dnat_sensitive_service_exposure",
        incident_family="firewall_exposure",
        primary_entity="10.0.0.60",
        event_ids=["rd1"],
    )
    ssh_profile = _profile(
        ssh_events,
        incident_id="INC-SH",
        incident_type="dnat_sensitive_service_exposure",
        incident_family="firewall_exposure",
        primary_entity="10.0.0.60",
        event_ids=["sh1"],
    )

    assert redis_profile is not None and ssh_profile is not None
    assert compute_correlation_key(redis_profile) != compute_correlation_key(ssh_profile)


# --- 9: DNAT effective destination uses translated destination fields


def test_dnat_effective_destination_uses_translated_fields() -> None:
    events = [
        _event(
            "d1",
            dst_ip="203.0.113.50",
            dst_port=6379,
            translated_dst_ip="10.0.0.60",
            translated_dst_port=6379,
            action="allow",
        )
    ]
    profile = _profile(
        events,
        incident_type="dnat_sensitive_service_exposure",
        incident_family="firewall_exposure",
        primary_entity="10.0.0.60",
        event_ids=["d1"],
    )
    assert profile is not None
    assert profile.protected_entity == "10.0.0.60"
    assert profile.protected_entity != "203.0.113.50"


# --- 10: missing or ambiguous required identity returns unsupported/no
# profile


def test_missing_actor_entity_returns_no_profile() -> None:
    events = [_event("m1")]
    profile = _profile(
        events,
        incident_type="rdp_probe",
        incident_family="service_probing",
        primary_entity="",
        event_ids=["m1"],
    )
    assert profile is None


def test_generic_incident_with_no_safe_strategy_returns_no_profile() -> None:
    events = [_event("g1")]
    profile = _profile(
        events,
        incident_type="some_unclassified_incident_type",
        incident_family="network_dos",
        event_ids=["g1"],
    )
    assert profile is None


def test_contradictory_protocols_return_no_profile() -> None:
    events = [
        _event("c1", protocol="TCP"),
        _event("c2", protocol="UDP"),
    ]
    profile = _profile(
        events,
        incident_type="rdp_probe",
        incident_family="service_probing",
        event_ids=["c1", "c2"],
    )
    assert profile is None


def test_never_falls_back_to_primary_entity_alone() -> None:
    # A generic incident_type/family combination has no supported strategy
    # at all, even though primary_entity is a perfectly good-looking IP -
    # the derivation must not silently treat primary_entity as sufficient
    # identity on its own.
    events = [_event("f1")]
    profile = _profile(
        events,
        incident_type="repeated_blocked_scanner_but_unlisted_variant",
        incident_family="network_anomaly",
        event_ids=["f1"],
    )
    assert profile is None


# --- Blocker 4: canonical service identity semantics ------------------------


def test_same_source_ssh_on_22_and_2222_produce_same_profile() -> None:
    ssh_22 = _profile(
        [_event("s22", dst_port=22)],
        incident_type="ssh_probe",
        incident_family="service_probing",
        event_ids=["s22"],
    )
    ssh_2222 = _profile(
        [_event("s2222", dst_port=2222)],
        incident_type="ssh_probe",
        incident_family="service_probing",
        event_ids=["s2222"],
    )
    assert ssh_22 is not None and ssh_2222 is not None
    assert compute_correlation_key(ssh_22) == compute_correlation_key(ssh_2222)


def test_redis_probe_and_mysql_probe_produce_different_profiles() -> None:
    redis = _profile(
        [_event("r1", dst_port=6379)],
        incident_type="redis_probe",
        incident_family="service_probing",
        event_ids=["r1"],
    )
    mysql = _profile(
        [_event("m1", dst_port=3306)],
        incident_type="mysql_probe",
        incident_family="service_probing",
        event_ids=["m1"],
    )
    assert redis is not None and mysql is not None
    # The generic "database" bucket must never collapse Redis and MySQL.
    assert compute_correlation_key(redis) != compute_correlation_key(mysql)


def test_two_different_unclassified_ports_produce_different_profiles() -> None:
    port_a = _profile(
        [_event("u1", dst_port=12345)],
        incident_type="horizontal_scan",
        incident_family="network_scanning",
        event_ids=["u1"],
    )
    port_b = _profile(
        [_event("u2", dst_port=54321)],
        incident_type="horizontal_scan",
        incident_family="network_scanning",
        event_ids=["u2"],
    )
    assert port_a is not None and port_b is not None
    assert compute_correlation_key(port_a) != compute_correlation_key(port_b)


def test_subnet_sweep_same_subnet_different_ip_targets_same_profile() -> None:
    sweep_a = _profile(
        [
            _event("sa1", dst_ip="10.0.0.5", dst_port=3389),
            _event("sa2", dst_ip="10.0.0.9", dst_port=3389),
        ],
        incident_type="subnet_sweep",
        incident_family="network_scanning",
        target_entities=["10.0.0.5", "10.0.0.9"],
        event_ids=["sa1", "sa2"],
    )
    sweep_b = _profile(
        [_event("sb1", dst_ip="10.0.0.200", dst_port=3389)],
        incident_type="subnet_sweep",
        incident_family="network_scanning",
        target_entities=["10.0.0.200"],
        event_ids=["sb1"],
    )
    assert sweep_a is not None and sweep_b is not None
    # Different individual IPs, same /24 subnet -> same campaign.
    assert compute_correlation_key(sweep_a) == compute_correlation_key(sweep_b)


def test_subnet_sweep_different_subnets_produce_different_profiles() -> None:
    sweep_a = _profile(
        [_event("sa1", dst_ip="10.0.0.5", dst_port=3389)],
        incident_type="subnet_sweep",
        incident_family="network_scanning",
        target_entities=["10.0.0.5"],
        event_ids=["sa1"],
    )
    sweep_c = _profile(
        [_event("sc1", dst_ip="10.0.1.5", dst_port=3389)],
        incident_type="subnet_sweep",
        incident_family="network_scanning",
        target_entities=["10.0.1.5"],
        event_ids=["sc1"],
    )
    assert sweep_a is not None and sweep_c is not None
    assert compute_correlation_key(sweep_a) != compute_correlation_key(sweep_c)


# --- Blocker 1: distributed_scan role collision -----------------------------


def test_distributed_scan_never_produces_a_stateful_profile() -> None:
    # DistributedScanRule sets primary_entity=dst_ip (the protected
    # destination) and target_entities to the distributed source IPs - the
    # opposite orientation from every other source-service campaign type.
    events = [
        _event("d1", src_ip="198.51.100.1", dst_ip="10.0.0.5", dst_port=3389),
        _event("d2", src_ip="198.51.100.2", dst_ip="10.0.0.5", dst_port=3389),
    ]
    profile = _profile(
        events,
        incident_type="distributed_scan",
        incident_family="network_scanning",
        primary_entity="10.0.0.5",
        target_entities=["198.51.100.1", "198.51.100.2"],
        event_ids=["d1", "d2"],
    )
    assert profile is None


def test_horizontal_scan_and_distributed_scan_sharing_an_ip_do_not_collide() -> None:
    # A horizontal scan sourced FROM 10.0.0.5 against RDP...
    horizontal_events = [_event("h1", src_ip="10.0.0.5", dst_ip="192.168.1.1", dst_port=3389)]
    horizontal_profile = _profile(
        horizontal_events,
        incident_type="horizontal_scan",
        incident_family="network_scanning",
        primary_entity="10.0.0.5",
        target_entities=["192.168.1.1"],
        event_ids=["h1"],
    )
    assert horizontal_profile is not None
    horizontal_key = compute_correlation_key(horizontal_profile)

    # ...must never share a correlation key with a distributed scan
    # TARGETING 10.0.0.5:3389 (same IP, opposite role).
    distributed_events = [
        _event("dd1", src_ip="198.51.100.1", dst_ip="10.0.0.5", dst_port=3389),
        _event("dd2", src_ip="198.51.100.2", dst_ip="10.0.0.5", dst_port=3389),
    ]
    distributed_profile = _profile(
        distributed_events,
        incident_type="distributed_scan",
        incident_family="network_scanning",
        primary_entity="10.0.0.5",
        target_entities=["198.51.100.1", "198.51.100.2"],
        event_ids=["dd1", "dd2"],
    )
    # Fails closed entirely, so there is no key at all to collide with.
    assert distributed_profile is None
    assert horizontal_key is not None
