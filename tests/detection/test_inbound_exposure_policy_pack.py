from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

import pytest
from pydantic import ValidationError

from agent.detection.config import DetectionSettings
from agent.detection.contracts import DetectionRuleMetadata
from agent.detection.detectors import register_default_rules
from agent.detection.detectors.base import BaseDetectionRule, DetectionContext
from agent.detection.detectors.exposure_helpers import (
    CRITICAL_MANAGEMENT_PORTS,
    SENSITIVE_SERVICE_PORTS,
    classify_network_direction,
    effective_destination_ip,
    effective_destination_port,
    has_destination_translation,
    is_critical_management_port,
    is_explicit_dmz_zone,
    is_explicit_lan_zone,
    is_explicit_wan_zone,
    is_private_effective_destination,
    is_public_source,
    sensitive_service_for_port,
)
from agent.detection.detectors.inbound_exposure import (
    BlockedThenAllowedSameServiceRule,
    CriticalManagementServiceExposedRule,
    DnatSensitiveServiceExposureRule,
    InboundSensitiveServiceAllowedRule,
    MultiSourceAllowedSensitiveServiceRule,
    WanToDmzAdministrativeServiceAllowedRule,
    WanToLanSensitiveServiceAllowedRule,
)
from agent.detection.detectors.remote_service_probe import RemoteServiceProbeRule
from agent.detection.detectors.spi_anomaly import SPIAnomalyRule
from agent.detection.engine import DetectionEngine
from agent.detection.registry import RuleRegistry, default_registry
from agent.schema import CanonicalLogEvent
from tests.detection.helpers import (
    FIXED_TIME,
    assert_evidence_belongs_to_signal,
    assert_signal_contract,
    assert_signal_is_deterministic,
    build_event,
)


EXISTING_RULE_IDS = {
    "scan_followed_by_allowed_connection",
    "spi_followed_by_allowed_connection",
    "remote_service_probe",
    "smb_probe",
    "vnc_probe",
    "winrm_probe",
    "database_service_probe",
    "kubernetes_service_probe",
    "docker_daemon_probe",
    "web_admin_panel_probe",
    "legacy_cleartext_service_probe",
    "internal_lateral_scan",
    "distributed_scan",
    "multi_service_sweep",
    "tcp_syn_fin_anomaly",
    "tcp_syn_rst_anomaly",
    "tcp_null_scan",
    "tcp_xmas_scan",
    "tcp_fin_scan",
    "tcp_ack_scan",
    "repeated_tcp_reset_anomaly",
    "subnet_sweep",
    "network_flood_dos",
    "network_scan_horizontal",
    "network_scan_vertical",
    "spi_anomaly_burst",
    "repeated_blocked_scanner",
    "low_and_slow_horizontal_scan",
    "low_and_slow_vertical_scan",
}

NEW_RULE_IDS = {
    "inbound_sensitive_service_allowed",
    "critical_management_service_exposed",
    "dnat_sensitive_service_exposure",
    "wan_to_lan_sensitive_service_allowed",
    "wan_to_dmz_administrative_service_allowed",
    "blocked_then_allowed_same_service",
    "multi_source_allowed_sensitive_service",
}

PUBLIC_SOURCES = ("8.8.8.8", "1.1.1.1", "9.9.9.9", "4.2.2.2")


def _settings(**overrides: object) -> DetectionSettings:
    values: dict[str, object] = {
        "INBOUND_EXPOSURE_WINDOW_SECONDS": 120,
        "INBOUND_SENSITIVE_MIN_ALLOWED_EVENTS": 3,
        "INBOUND_SENSITIVE_MIN_DISTINCT_DESTINATIONS": 1,
        "CRITICAL_MANAGEMENT_EXPOSURE_MIN_EVENTS": 1,
        "WAN_TO_LAN_MIN_ALLOWED_EVENTS": 2,
        "WAN_TO_DMZ_ADMIN_MIN_ALLOWED_EVENTS": 3,
        "BLOCKED_THEN_ALLOWED_WINDOW_SECONDS": 120,
        "BLOCKED_THEN_ALLOWED_MIN_BLOCKED_EVENTS": 3,
        "MULTI_SOURCE_SENSITIVE_WINDOW_SECONDS": 120,
        "MULTI_SOURCE_SENSITIVE_MIN_EVENTS": 5,
        "MULTI_SOURCE_SENSITIVE_MIN_DISTINCT_SOURCES": 3,
        "REMOTE_SERVICE_MIN_EVENTS": 2,
        "REMOTE_SERVICE_MIN_DISTINCT_TARGETS": 2,
        "REMOTE_SERVICE_MIN_BLOCK_RATIO": 0.60,
        "REMOTE_SERVICE_MIN_SYN_RATIO": 0.50,
        "SPI_ANOMALY_MIN_EVENTS": 3,
        "SPI_ANOMALY_MIN_DISTINCT_TARGETS": 1,
    }
    values.update(overrides)
    return DetectionSettings.model_validate(values)


def _event(
    event_id: str,
    index: int,
    *,
    src_ip: str = "8.8.8.8",
    dst_ip: str = "10.0.0.20",
    dst_port: int = 22,
    action: str = "allow",
    inbound_zone: str | None = None,
    outbound_zone: str | None = None,
    translated_dst_ip: str | None = None,
    translated_dst_port: int | None = None,
    nat_type: str | None = None,
    spi: bool = False,
) -> CanonicalLogEvent:
    return build_event(
        event_id,
        timestamp=FIXED_TIME + timedelta(seconds=index),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=40000 + index,
        dst_port=dst_port,
        protocol="TCP",
        tcp_flags="SYN" if action == "block" else "SYN,ACK",
        action=action,
        inbound_zone=inbound_zone,
        outbound_zone=outbound_zone,
        translated_dst_ip=translated_dst_ip,
        translated_dst_port=translated_dst_port,
        nat_type=nat_type,
        parser_name="pf_firewall" if spi else "test_builder",
        parser_metadata={"spi_anomaly": spi},
        action_reason="unexpected tcp flags" if spi else "policy match",
    )


def _general_positive() -> list[CanonicalLogEvent]:
    return [_event(f"general-{index}", index) for index in range(3)]


def _general_negative() -> list[CanonicalLogEvent]:
    return [_event("isolated-ssh", 0)]


def _critical_positive() -> list[CanonicalLogEvent]:
    return [
        _event(
            "critical-docker",
            0,
            dst_port=2375,
            inbound_zone="wan1-zone",
            outbound_zone="internal-zone",
        )
    ]


def _critical_negative() -> list[CanonicalLogEvent]:
    return [
        _event(
            "non-critical-rdp",
            0,
            dst_port=3389,
            inbound_zone="wan",
            outbound_zone="lan",
        )
    ]


def _dnat_positive() -> list[CanonicalLogEvent]:
    return [
        _event(
            "dnat-redis",
            0,
            dst_ip="142.250.72.14",
            dst_port=443,
            translated_dst_ip="10.0.0.60",
            translated_dst_port=6379,
            nat_type="dnat",
        )
    ]


def _dnat_negative() -> list[CanonicalLogEvent]:
    return [
        _event(
            "nat-type-only",
            0,
            dst_ip="142.250.72.14",
            dst_port=6379,
            nat_type="dnat",
        )
    ]


def _wan_lan_positive() -> list[CanonicalLogEvent]:
    return [
        _event(
            f"wan-lan-{index}",
            index,
            dst_port=3389,
            inbound_zone="WAN",
            outbound_zone="internal-zone",
        )
        for index in range(2)
    ]


def _wan_lan_negative() -> list[CanonicalLogEvent]:
    return [
        _event(
            f"unknown-zone-{index}",
            index,
            dst_port=3389,
            inbound_zone="partner",
            outbound_zone="production",
        )
        for index in range(2)
    ]


def _wan_dmz_positive() -> list[CanonicalLogEvent]:
    return [
        _event(
            f"wan-dmz-{index}",
            index,
            dst_port=8443,
            inbound_zone="outside",
            outbound_zone="dmz_network",
        )
        for index in range(3)
    ]


def _wan_dmz_negative() -> list[CanonicalLogEvent]:
    return [
        _event(
            f"ordinary-https-{index}",
            index,
            dst_port=443,
            inbound_zone="outside",
            outbound_zone="dmz",
        )
        for index in range(3)
    ]


def _sequence_positive() -> list[CanonicalLogEvent]:
    blocked = [
        _event(
            f"blocked-{index}",
            index,
            dst_port=22,
            action="block",
        )
        for index in range(3)
    ]
    allowed = _event("allowed", 4, dst_port=2222)
    return [*blocked, allowed]


def _sequence_negative() -> list[CanonicalLogEvent]:
    events = _sequence_positive()
    return [
        events[-1].model_copy(
            update={"timestamp": FIXED_TIME - timedelta(seconds=1)}
        ),
        *events[:-1],
    ]


def _multi_source_positive() -> list[CanonicalLogEvent]:
    sources = ("8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.8.8", "1.1.1.1")
    return [
        _event(
            f"multi-{index}",
            index,
            src_ip=source,
            dst_port=445,
        )
        for index, source in enumerate(sources)
    ]


def _multi_source_negative() -> list[CanonicalLogEvent]:
    return [
        _event(f"single-source-{index}", index, src_ip="8.8.8.8", dst_port=445)
        for index in range(5)
    ]


@dataclass(frozen=True)
class RuleCase:
    case_id: str
    rule: BaseDetectionRule
    positive_events: Callable[[], list[CanonicalLogEvent]]
    negative_events: Callable[[], list[CanonicalLogEvent]]


RULE_CASES = (
    RuleCase(
        "general-inbound",
        InboundSensitiveServiceAllowedRule(),
        _general_positive,
        _general_negative,
    ),
    RuleCase(
        "critical-management",
        CriticalManagementServiceExposedRule(),
        _critical_positive,
        _critical_negative,
    ),
    RuleCase(
        "dnat",
        DnatSensitiveServiceExposureRule(),
        _dnat_positive,
        _dnat_negative,
    ),
    RuleCase(
        "wan-lan",
        WanToLanSensitiveServiceAllowedRule(),
        _wan_lan_positive,
        _wan_lan_negative,
    ),
    RuleCase(
        "wan-dmz",
        WanToDmzAdministrativeServiceAllowedRule(),
        _wan_dmz_positive,
        _wan_dmz_negative,
    ),
    RuleCase(
        "blocked-allowed",
        BlockedThenAllowedSameServiceRule(),
        _sequence_positive,
        _sequence_negative,
    ),
    RuleCase(
        "multi-source",
        MultiSourceAllowedSensitiveServiceRule(),
        _multi_source_positive,
        _multi_source_negative,
    ),
)


@pytest.mark.parametrize("case", RULE_CASES, ids=lambda case: case.case_id)
def test_inbound_exposure_rules_produce_valid_deterministic_signals(
    case: RuleCase,
) -> None:
    events = case.positive_events()
    context = DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME)

    first = case.rule.evaluate(events, context)
    second = case.rule.evaluate(list(reversed(events)), context)

    assert len(first) == 1
    assert len(second) == 1
    signal = first[0]
    assert signal.rule_id == case.rule.rule_id
    assert signal.rule_name == case.rule.name
    assert signal.signal_type == case.rule.metadata.signal_type
    assert_signal_contract(signal, case.rule, events)
    assert_evidence_belongs_to_signal(signal)
    assert_signal_is_deterministic(signal, second[0])


@pytest.mark.parametrize("case", RULE_CASES, ids=lambda case: case.case_id)
def test_inbound_exposure_rules_reject_focused_negative_cases(
    case: RuleCase,
) -> None:
    signals = case.rule.evaluate(
        case.negative_events(),
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    )

    assert signals == []


@pytest.mark.parametrize(
    "value",
    ["wan", "WAN", "wan1-zone", "internet", "external-zone", "outside", "untrust"],
)
def test_wan_zone_tokens_are_case_insensitive_and_bounded(value: str) -> None:
    assert is_explicit_wan_zone(value)


@pytest.mark.parametrize("value", [None, "", "wanton", "untrusted", "partner-wanx"])
def test_unknown_zones_are_not_guessed(value: object) -> None:
    assert not is_explicit_wan_zone(value)
    assert not is_explicit_lan_zone(value)
    assert not is_explicit_dmz_zone(value)


def test_lan_and_dmz_zone_tokens_use_normalized_separators() -> None:
    assert is_explicit_lan_zone("internal-zone")
    assert is_explicit_lan_zone("TRUST network")
    assert is_explicit_dmz_zone("dmz_network")
    assert not is_explicit_lan_zone("external")
    assert not is_explicit_dmz_zone("dmzone")


def test_public_to_private_direction_and_private_internal_exclusion() -> None:
    inbound = _event("public-private", 0, src_ip="8.8.8.8", dst_ip="10.0.0.20")
    internal = _event(
        "private-private",
        0,
        src_ip="10.0.0.10",
        dst_ip="10.0.0.20",
        inbound_zone="wan",
    )

    assert is_public_source(inbound)
    assert is_private_effective_destination(inbound)
    assert classify_network_direction(inbound) == "public_to_private"
    assert classify_network_direction(internal) == "private_internal"
    assert InboundSensitiveServiceAllowedRule().evaluate(
        [internal.model_copy(update={"event_id": f"internal-{index}"}) for index in range(3)],
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    ) == []


def test_effective_destination_prefers_translation_without_mutating_event() -> None:
    event = _dnat_positive()[0]
    before = event.model_dump(mode="json")

    assert effective_destination_ip(event) == "10.0.0.60"
    assert effective_destination_port(event) == 6379
    assert has_destination_translation(event)
    assert event.model_dump(mode="json") == before


def test_dnat_rule_reports_translated_destination_and_port() -> None:
    events = _dnat_positive()
    signal = DnatSensitiveServiceExposureRule().evaluate(
        events,
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    )[0]

    assert classify_network_direction(events[0]) == "dnat_inbound"
    assert signal.primary_entity == "10.0.0.60"
    assert signal.metrics["original_destination"] == "142.250.72.14"
    assert signal.metrics["original_destination_port"] == 443
    assert signal.metrics["translated_destination"] == "10.0.0.60"
    assert signal.metrics["translated_destination_port"] == 6379
    assert signal.metrics["service"] == "redis"


@pytest.mark.parametrize("port", sorted(CRITICAL_MANAGEMENT_PORTS))
def test_critical_management_rule_uses_exact_narrow_port_set(port: int) -> None:
    events = [
        _event(
            f"critical-{port}",
            0,
            dst_port=port,
            inbound_zone="outside",
        )
    ]

    assert is_critical_management_port(port)
    assert len(
        CriticalManagementServiceExposedRule().evaluate(
            events,
            DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
        )
    ) == 1


@pytest.mark.parametrize("port", [22, 3389, 443, 6443])
def test_non_critical_management_ports_do_not_single_event_trigger(port: int) -> None:
    event = _event("non-critical", 0, dst_port=port, inbound_zone="wan")

    assert not is_critical_management_port(port)
    assert CriticalManagementServiceExposedRule().evaluate(
        [event],
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    ) == []


def test_critical_management_requires_zone_or_translation_not_public_source_alone() -> None:
    public_only = _event("critical-public-only", 0, dst_port=2375)
    translated = _event(
        "critical-translated",
        0,
        dst_ip="142.250.72.14",
        dst_port=443,
        translated_dst_ip="10.0.0.70",
        translated_dst_port=2375,
    )
    rule = CriticalManagementServiceExposedRule()
    context = DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME)

    assert rule.evaluate([public_only], context) == []
    assert len(rule.evaluate([translated], context)) == 1


def test_sensitive_service_set_is_exact_and_excludes_web_ports() -> None:
    expected = {
        20,
        21,
        22,
        23,
        139,
        445,
        1433,
        3306,
        3389,
        5432,
        5900,
        135,
        389,
    }

    assert SENSITIVE_SERVICE_PORTS == expected
    assert sensitive_service_for_port(80) is None
    assert sensitive_service_for_port(443) is None


def test_critical_management_set_is_exact() -> None:
    assert CRITICAL_MANAGEMENT_PORTS == {
        161,
        623,
        2375,
        5985,
        6379,
        9200,
        10250,
        11211,
        27017,
    }


@pytest.mark.parametrize(
    ("port", "service"),
    [
        (20, "ftp_data"),
        (21, "ftp"),
        (623, "ipmi"),
        (6379, "redis"),
        (9200, "elasticsearch"),
        (27017, "mongodb"),
    ],
)
def test_exposure_service_labels_are_specific(port: int, service: str) -> None:
    assert sensitive_service_for_port(port) == service


@pytest.mark.parametrize("port", [22, 3389])
def test_default_general_exposure_threshold_reports_one_allowed_event(port: int) -> None:
    signals = InboundSensitiveServiceAllowedRule().evaluate(
        [_event(f"single-{port}", 0, dst_port=port)],
        DetectionContext(
            settings=DetectionSettings(), analysis_started_at=FIXED_TIME
        ),
    )
    assert len(signals) == 1


@pytest.mark.parametrize("port", [22, 3389])
def test_general_ssh_and_rdp_honor_an_explicit_repeated_event_threshold(
    port: int,
) -> None:
    rule = InboundSensitiveServiceAllowedRule()
    context = DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME)
    isolated = [_event(f"isolated-{port}", 0, dst_port=port)]
    repeated = [
        _event(f"repeated-{port}-{index}", index, dst_port=port)
        for index in range(3)
    ]

    assert rule.evaluate(isolated, context) == []
    assert len(rule.evaluate(repeated, context)) == 1


def test_wan_to_lan_falls_back_to_shared_direction_when_outbound_zone_is_missing() -> None:
    events = _wan_lan_positive()
    missing_outbound = [event.model_copy(update={"outbound_zone": None}) for event in events]
    inferred_only = [
        event.model_copy(update={"inbound_zone": None, "outbound_zone": None})
        for event in events
    ]
    rule = WanToLanSensitiveServiceAllowedRule()
    context = DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME)

    assert len(rule.evaluate(missing_outbound, context)) == 1
    assert rule.evaluate(inferred_only, context) == []


@pytest.mark.parametrize("port", [80, 443])
def test_ordinary_wan_to_dmz_web_traffic_never_triggers(port: int) -> None:
    events = [
        _event(
            f"web-{port}-{index}",
            index,
            dst_port=port,
            inbound_zone="wan",
            outbound_zone="dmz",
        )
        for index in range(3)
    ]

    assert WanToDmzAdministrativeServiceAllowedRule().evaluate(
        events,
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    ) == []


def test_ordinary_allowed_web_traffic_creates_no_exposure_signal() -> None:
    events = [
        _event(
            f"ordinary-web-{index}",
            index,
            src_ip=PUBLIC_SOURCES[index % len(PUBLIC_SOURCES)],
            dst_port=443 if index % 2 else 80,
            inbound_zone="wan",
            outbound_zone="dmz",
        )
        for index in range(5)
    ]
    registry = RuleRegistry()
    for rule in (
        InboundSensitiveServiceAllowedRule(),
        CriticalManagementServiceExposedRule(),
        DnatSensitiveServiceExposureRule(),
        WanToLanSensitiveServiceAllowedRule(),
        WanToDmzAdministrativeServiceAllowedRule(),
        BlockedThenAllowedSameServiceRule(),
        MultiSourceAllowedSensitiveServiceRule(),
    ):
        registry.register(rule)

    result = DetectionEngine(registry=registry, settings=_settings()).analyze(events)

    assert result.signals == []


def test_generic_blocked_then_allowed_excludes_explicit_spi_blocks() -> None:
    events = [
        event.model_copy(
            update={
                "parser_metadata": {"spi_anomaly": True},
                "action_reason": "unexpected tcp flags",
            }
        )
        for event in _sequence_positive()[:-1]
    ]
    events.append(_sequence_positive()[-1])

    assert BlockedThenAllowedSameServiceRule().evaluate(
        events,
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    ) == []


def test_blocked_then_allowed_contains_final_allowed_event_and_evidence() -> None:
    events = _sequence_positive()
    signal = BlockedThenAllowedSameServiceRule().evaluate(
        events,
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    )[0]

    assert signal.metrics["allowed_event_id"] == "allowed"
    assert "allowed" in signal.event_ids
    assert "allowed" in {item.event_id for item in signal.evidence}


def test_blocked_then_allowed_supports_an_exact_unclassified_tcp_port() -> None:
    events = [
        _event(
            f"custom-block-{index}",
            index,
            dst_port=12345,
            action="block",
        )
        for index in range(3)
    ]
    events.append(_event("custom-allowed", 4, dst_port=12345))

    signal = BlockedThenAllowedSameServiceRule().evaluate(
        events,
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    )[0]

    assert signal.metrics["destination_port"] == 12345
    assert signal.metrics["service"] == "tcp_12345"


def test_multi_source_requires_public_sources() -> None:
    private_sources = [
        _event(
            f"private-source-{index}",
            index,
            src_ip=f"10.0.1.{index + 1}",
            dst_port=445,
        )
        for index in range(5)
    ]

    assert MultiSourceAllowedSensitiveServiceRule().evaluate(
        private_sources,
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    ) == []


def test_malformed_ips_and_missing_zones_are_skipped_safely() -> None:
    malformed = [
        _event(f"malformed-{index}", index, src_ip="not-an-ip")
        for index in range(3)
    ]

    assert InboundSensitiveServiceAllowedRule().evaluate(
        malformed,
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    ) == []


def test_overlapping_inbound_windows_deduplicate_deterministically() -> None:
    events = [_event(f"overlap-{index}", index) for index in range(4)]
    registry = RuleRegistry()
    registry.register(InboundSensitiveServiceAllowedRule())
    engine = DetectionEngine(registry=registry, settings=_settings())

    first = engine.analyze(events)
    second = engine.analyze(list(reversed(events)))

    assert len(first.signals) == 1
    assert len(first.signals[0].event_ids) == len(set(first.signals[0].event_ids))
    assert len(first.signals[0].evidence) == len(
        {item.event_id for item in first.signals[0].evidence}
    )
    assert_signal_is_deterministic(first.signals[0], second.signals[0])


def test_default_registry_contains_exactly_thirty_six_unique_rules() -> None:
    register_default_rules()
    register_default_rules()
    rules = default_registry.get_all_rules()
    rule_ids = {rule.rule_id for rule in rules}

    assert len(rules) == 36
    assert len(rule_ids) == 36
    assert EXISTING_RULE_IDS.issubset(rule_ids)
    assert NEW_RULE_IDS.issubset(rule_ids)
    assert all(
        DetectionRuleMetadata.model_validate(rule.metadata.model_dump()) == rule.metadata
        for rule in rules
    )


def test_inbound_exposure_setting_defaults() -> None:
    settings = DetectionSettings()

    assert settings.INBOUND_EXPOSURE_WINDOW_SECONDS == 300
    assert settings.INBOUND_SENSITIVE_MIN_ALLOWED_EVENTS == 1
    assert settings.INBOUND_SENSITIVE_MIN_DISTINCT_DESTINATIONS == 1
    assert settings.CRITICAL_MANAGEMENT_EXPOSURE_MIN_EVENTS == 1
    assert settings.WAN_TO_LAN_MIN_ALLOWED_EVENTS == 2
    assert settings.WAN_TO_DMZ_ADMIN_MIN_ALLOWED_EVENTS == 3
    assert settings.BLOCKED_THEN_ALLOWED_WINDOW_SECONDS == 600
    assert settings.BLOCKED_THEN_ALLOWED_MIN_BLOCKED_EVENTS == 3
    assert settings.MULTI_SOURCE_SENSITIVE_WINDOW_SECONDS == 300
    assert settings.MULTI_SOURCE_SENSITIVE_MIN_EVENTS == 5
    assert settings.MULTI_SOURCE_SENSITIVE_MIN_DISTINCT_SOURCES == 3


@pytest.mark.parametrize(
    "overrides",
    [
        {"INBOUND_EXPOSURE_WINDOW_SECONDS": 0},
        {"INBOUND_SENSITIVE_MIN_ALLOWED_EVENTS": 0},
        {"CRITICAL_MANAGEMENT_EXPOSURE_MIN_EVENTS": 0},
        {"WAN_TO_LAN_MIN_ALLOWED_EVENTS": 0},
        {"BLOCKED_THEN_ALLOWED_WINDOW_SECONDS": 0},
        {"MULTI_SOURCE_SENSITIVE_MIN_DISTINCT_SOURCES": 0},
    ],
)
def test_inbound_exposure_settings_reject_non_positive_values(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _settings(**overrides)


@pytest.mark.parametrize(
    ("port", "identity"),
    [
        (3389, ("rdp_probe", "RDP Probe", "rdp_probe")),
        (22, ("ssh_probe", "SSH Probe", "ssh_probe")),
    ],
)
def test_rdp_and_ssh_identities_remain_unchanged(
    port: int,
    identity: tuple[str, str, str],
) -> None:
    events = [
        _event(
            f"remote-{port}-{index}",
            index,
            dst_ip=f"10.0.0.{20 + index}",
            dst_port=port,
            action="block",
        )
        for index in range(2)
    ]
    signal = RemoteServiceProbeRule().evaluate(
        events,
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    )[0]

    assert (signal.rule_id, signal.rule_name, signal.signal_type) == identity


def test_existing_spi_identity_remains_unchanged() -> None:
    events = [
        _event(
            f"spi-{index}",
            index,
            dst_ip=f"10.0.0.{40 + index}",
            dst_port=8787,
            action="block",
            spi=True,
        )
        for index in range(3)
    ]
    signal = SPIAnomalyRule().evaluate(
        events,
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    )[0]

    assert signal.rule_id == "spi_anomaly_burst"
    assert signal.signal_type == "spi_anomaly"


def test_inbound_exposure_detection_makes_zero_provider_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("provider or agent invocation is forbidden during detection")

    monkeypatch.setattr("agent.triage.runner.TriageRunner.run", fail_if_called)
    register_default_rules()

    result = DetectionEngine().analyze(_general_positive())

    assert any(
        signal.signal_type == "inbound_sensitive_service_allowed"
        for signal in result.signals
    )
