from dataclasses import dataclass
from datetime import timedelta

import pytest
from pydantic import ValidationError

from agent.detection.config import DetectionSettings
from agent.detection.contracts import DetectionRuleMetadata
from agent.detection.detectors import register_default_rules
from agent.detection.detectors.base import BaseDetectionRule, DetectionContext
from agent.detection.detectors.horizontal_scan import HorizontalScanRule
from agent.detection.detectors.remote_service_probe import RemoteServiceProbeRule
from agent.detection.detectors.scan_helpers import is_tcp_syn
from agent.detection.detectors.spi_anomaly import SPIAnomalyRule
from agent.detection.detectors.tcp_spi_anomaly import (
    RepeatedTcpResetAnomalyRule,
    SpiFollowedByAllowedConnectionRule,
    TcpAckScanRule,
    TcpFinScanRule,
    TcpNullScanRule,
    TcpSynFinAnomalyRule,
    TcpSynRstAnomalyRule,
    TcpXmasScanRule,
)
from agent.detection.engine import DetectionEngine
from agent.detection.registry import RuleRegistry, default_registry
from agent.parsers.base import ParseContext
from agent.parsers.pf_firewall import PfFirewallParser
from agent.schema import CanonicalLogEvent
from agent.tcp_flags import canonicalize_tcp_flags, parse_tcp_flag_tokens
from tests.detection.helpers import (
    FIXED_TIME,
    assert_evidence_belongs_to_signal,
    assert_signal_contract,
    assert_signal_is_deterministic,
    build_event,
)


MISSING = object()

EXISTING_RULE_IDS = {
    "scan_followed_by_allowed_connection",
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
    "tcp_null_scan",
    "tcp_xmas_scan",
    "tcp_fin_scan",
    "tcp_ack_scan",
    "tcp_syn_fin_anomaly",
    "tcp_syn_rst_anomaly",
    "repeated_tcp_reset_anomaly",
    "spi_followed_by_allowed_connection",
}


def _settings(**overrides: object) -> DetectionSettings:
    values: dict[str, object] = {
        "TCP_FLAG_SCAN_WINDOW_SECONDS": 120,
        "TCP_FLAG_SCAN_MIN_EVENTS": 3,
        "TCP_FLAG_SCAN_MIN_DISTINCT_TARGETS": 3,
        "TCP_FLAG_SCAN_MIN_DISTINCT_PORTS": 3,
        "TCP_FLAG_SCAN_MIN_BLOCK_RATIO": 0.60,
        "TCP_ACK_SCAN_MIN_EVENTS": 3,
        "TCP_ACK_SCAN_MIN_BLOCK_RATIO": 0.80,
        "TCP_INVALID_COMBINATION_MIN_EVENTS": 3,
        "TCP_INVALID_COMBINATION_MIN_BLOCK_RATIO": 0.80,
        "TCP_RESET_ANOMALY_WINDOW_SECONDS": 120,
        "TCP_RESET_ANOMALY_MIN_EVENTS": 3,
        "TCP_RESET_ANOMALY_MIN_DISTINCT_TARGETS": 3,
        "TCP_RESET_ANOMALY_MIN_DISTINCT_PORTS": 3,
        "TCP_RESET_ANOMALY_MIN_BLOCK_RATIO": 0.60,
        "SPI_THEN_ALLOWED_WINDOW_SECONDS": 120,
        "SPI_THEN_ALLOWED_MIN_SPI_EVENTS": 3,
        "SPI_ANOMALY_MIN_EVENTS": 3,
        "SPI_ANOMALY_MIN_DISTINCT_TARGETS": 1,
        "REMOTE_SERVICE_MIN_EVENTS": 3,
        "REMOTE_SERVICE_MIN_DISTINCT_TARGETS": 3,
        "REMOTE_SERVICE_MIN_BLOCK_RATIO": 0.60,
        "REMOTE_SERVICE_MIN_SYN_RATIO": 0.50,
        "HORIZONTAL_SCAN_MIN_EVENTS": 3,
        "HORIZONTAL_SCAN_MIN_DISTINCT_TARGETS": 3,
        "HORIZONTAL_SCAN_MIN_BLOCK_RATIO": 0.60,
        "HORIZONTAL_SCAN_MIN_SYN_RATIO": 0.50,
    }
    values.update(overrides)
    return DetectionSettings.model_validate(values)


def _event(
    event_id: str,
    index: int,
    *,
    tcp_flags: str | None,
    action: str = "block",
    spi: bool = False,
    dst_ip: str | None = None,
    dst_port: int | None = None,
) -> CanonicalLogEvent:
    return build_event(
        event_id,
        timestamp=FIXED_TIME + timedelta(seconds=index),
        src_ip="192.0.2.44",
        dst_ip=dst_ip or f"198.51.100.{index + 1}",
        dst_port=dst_port if dst_port is not None else 8000 + index,
        protocol="TCP",
        action=action,
        tcp_flags=tcp_flags,
        parser_name="pf_firewall" if spi else "test_builder",
        parser_metadata={"spi_anomaly": spi},
        action_reason="unexpected tcp flags" if spi else "policy match",
    )


@pytest.mark.parametrize(
    ("raw_flags", "canonical", "tokens", "explicit_none", "recognized"),
    [
        ("S", "SYN", ("SYN",), False, True),
        ("SA", "SYN,ACK", ("SYN", "ACK"), False, True),
        ("SR", "SYN,RST", ("SYN", "RST"), False, True),
        ("AR", "RST,ACK", ("RST", "ACK"), False, True),
        ("AFR", "FIN,RST,ACK", ("FIN", "RST", "ACK"), False, True),
        ("AFP", "FIN,PSH,ACK", ("FIN", "PSH", "ACK"), False, True),
        ("FPU", "FIN,PSH,URG", ("FIN", "PSH", "URG"), False, True),
        ("", "NONE", (), True, True),
        (MISSING, None, (), False, True),
        (".", None, (), False, False),
    ],
    ids=["s", "sa", "sr", "ar", "afr", "afp", "fpu", "empty", "missing", "unknown"],
)
def test_pf_tcp_flag_normalization(
    raw_flags: object,
    canonical: str | None,
    tokens: tuple[str, ...],
    explicit_none: bool,
    recognized: bool,
) -> None:
    raw: dict[str, object] = {
        "src": "192.0.2.10",
        "dst": "198.51.100.20",
        "proto": "tcp",
        "deviceAction": "block",
    }
    if raw_flags is not MISSING:
        raw["tcpFlags"] = raw_flags

    event = PfFirewallParser().parse(
        raw,
        ParseContext(source_name="test", observed_at=FIXED_TIME),
        "pf-flags",
    )

    assert PfFirewallParser.version == "2.2.0"
    assert event.parser_version == "2.2.0"
    assert event.tcp_flags == canonical
    assert event.parser_metadata is not None
    assert event.parser_metadata["tcp_flags_present"] is (raw_flags is not MISSING)
    assert event.parser_metadata["tcp_flag_tokens"] == list(tokens)
    assert event.parser_metadata["tcp_flags_explicit_none"] is explicit_none
    assert isinstance(event.parser_metadata["tcp_flags_present"], bool)
    assert isinstance(event.parser_metadata["tcp_flags_explicit_none"], bool)
    expected_original = (
        None if raw_flags is MISSING or raw_flags == "" else str(raw_flags)
    )
    assert event.parser_metadata["original_tcp_flags"] == expected_original
    assert (not event.parse_warnings) is recognized
    assert len(event.safe_message_excerpt) <= 512
    if expected_original is not None:
        assert f"flags={expected_original}" in event.safe_message_excerpt


@pytest.mark.parametrize(
    ("value", "canonical"),
    [
        ("RFA", "FIN,RST,ACK"),
        ("syn,ack", "SYN,ACK"),
        ("FIN PSH URG", "FIN,PSH,URG"),
        ("fin|psh|urg", "FIN,PSH,URG"),
    ],
)
def test_vendor_neutral_flag_normalizer_is_case_insensitive_and_ordered(
    value: str,
    canonical: str,
) -> None:
    result = canonicalize_tcp_flags(value, field_present=True)

    assert result.canonical == canonical
    assert parse_tcp_flag_tokens(value) == frozenset(result.tokens)


@pytest.mark.parametrize("value", [None, "", "0", "NONE", "NULL", "-"])
def test_explicit_no_flag_values_remain_distinct_from_missing(value: object) -> None:
    explicit = canonicalize_tcp_flags(value, field_present=True)
    missing = canonicalize_tcp_flags(value, field_present=False)

    assert explicit.canonical == "NONE"
    assert explicit.tokens == ()
    assert explicit.explicit_none is True
    assert missing.canonical is None
    assert missing.explicit_none is False


@pytest.mark.parametrize("value", [".", "SYN,BOGUS", "SYNACK", "XYZ"])
def test_unknown_or_partially_invalid_tcp_flags_are_not_guessed(value: str) -> None:
    result = canonicalize_tcp_flags(value, field_present=True)

    assert result.canonical is None
    assert result.tokens == ()
    assert result.explicit_none is False
    assert result.recognized is False
    assert parse_tcp_flag_tokens(value) == frozenset()


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        ("S", True),
        ("SYN", True),
        ("SYN,RST", True),
        ("SYN,ACK", False),
        ("ACK", False),
        (None, False),
    ],
)
def test_initial_syn_classification_uses_shared_tokens(
    flags: str | None,
    expected: bool,
) -> None:
    assert is_tcp_syn(_event("syn-classification", 0, tcp_flags=flags)) is expected


@dataclass(frozen=True)
class PatternRuleCase:
    case_id: str
    rule: BaseDetectionRule
    flags: tuple[str, ...]


PATTERN_RULE_CASES = (
    PatternRuleCase("null", TcpNullScanRule(), ("NONE", "NONE", "NONE")),
    PatternRuleCase(
        "xmas",
        TcpXmasScanRule(),
        ("FIN,PSH,URG", "FPU", "URG,FIN,PSH"),
    ),
    PatternRuleCase("fin", TcpFinScanRule(), ("FIN", "F", "FIN")),
    PatternRuleCase("ack", TcpAckScanRule(), ("ACK", "A", "ACK")),
    PatternRuleCase(
        "syn-fin",
        TcpSynFinAnomalyRule(),
        ("FIN,SYN", "SF", "SYN,FIN,PSH"),
    ),
    PatternRuleCase(
        "syn-rst",
        TcpSynRstAnomalyRule(),
        ("SYN,RST", "SR", "RST,SYN,PSH"),
    ),
    PatternRuleCase(
        "repeated-reset",
        RepeatedTcpResetAnomalyRule(),
        ("RST", "AR", "FIN,RST,ACK"),
    ),
)


def _pattern_events(case: PatternRuleCase) -> list[CanonicalLogEvent]:
    return [
        _event(
            f"{case.case_id}-{index}",
            index,
            tcp_flags=flags,
            spi=case.case_id == "syn-rst",
        )
        for index, flags in enumerate(case.flags)
    ]


@pytest.mark.parametrize("case", PATTERN_RULE_CASES, ids=lambda case: case.case_id)
def test_tcp_pattern_rules_produce_valid_deterministic_signals(
    case: PatternRuleCase,
) -> None:
    events = _pattern_events(case)
    context = DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME)

    first = case.rule.evaluate(events, context)
    second = case.rule.evaluate(list(reversed(events)), context)

    assert len(first) == 1
    assert len(second) == 1
    signal = first[0]
    assert signal.rule_id == case.rule.rule_id
    assert signal.rule_name == case.rule.name
    assert signal.signal_type == case.rule.metadata.signal_type
    assert signal.metrics["event_count"] == 3
    assert signal.metrics["distinct_targets"] == 3
    assert signal.metrics["distinct_ports"] == 3
    assert_signal_contract(signal, case.rule, events)
    assert_evidence_belongs_to_signal(signal)
    assert_signal_is_deterministic(signal, second[0])


def _spi_sequence_events() -> list[CanonicalLogEvent]:
    blocked = [
        _event(
            f"spi-block-{index}",
            index,
            tcp_flags="SR",
            spi=True,
            dst_ip=f"198.51.100.{50 + index}",
            dst_port=22,
        )
        for index in range(3)
    ]
    allowed = _event(
        "spi-allowed",
        4,
        tcp_flags="SYN,ACK",
        action="allow",
        dst_ip="198.51.100.50",
        dst_port=2222,
    )
    return [*blocked, allowed]


def test_spi_followed_by_allowed_sequence_is_deterministic_and_owns_evidence() -> None:
    events = _spi_sequence_events()
    rule = SpiFollowedByAllowedConnectionRule()
    context = DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME)

    first = rule.evaluate(events, context)
    second = rule.evaluate(list(reversed(events)), context)

    assert len(first) == 1
    assert len(second) == 1
    signal = first[0]
    assert signal.rule_id == "spi_followed_by_allowed_connection"
    assert signal.signal_type == "spi_followed_by_allowed_connection"
    assert signal.metrics["spi_event_count"] == 3
    assert signal.metrics["allowed_event_id"] == "spi-allowed"
    assert "spi-allowed" in signal.event_ids
    assert "spi-allowed" in {evidence.event_id for evidence in signal.evidence}
    assert_signal_contract(signal, rule, events)
    assert_evidence_belongs_to_signal(signal)
    assert_signal_is_deterministic(signal, second[0])


def test_spi_sequence_supports_existing_canonical_action_marker() -> None:
    events = _spi_sequence_events()
    canonical_action_events = [
        event.model_copy(
            update={
                "action": "blocked by spi",
                "action_reason": "unexpected tcp flags",
                "parser_metadata": {},
            }
        )
        for event in events[:-1]
    ]
    rule = SpiFollowedByAllowedConnectionRule()

    signals = rule.evaluate(
        [*canonical_action_events, events[-1]],
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    )

    assert len(signals) == 1


def test_null_scan_requires_explicit_no_flags() -> None:
    events = [_event(f"missing-{index}", index, tcp_flags=None) for index in range(3)]

    assert TcpNullScanRule().evaluate(
        events,
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    ) == []


def test_xmas_and_fin_matching_are_mutually_exclusive() -> None:
    context = DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME)
    fin_events = [_event(f"fin-{index}", index, tcp_flags="FIN") for index in range(3)]
    xmas_events = [
        _event(f"xmas-{index}", index, tcp_flags="FIN,PSH,URG")
        for index in range(3)
    ]
    xmas_with_ece = [
        _event(f"xmas-ece-{index}", index, tcp_flags="FIN,PSH,URG,ECE")
        for index in range(3)
    ]

    assert TcpXmasScanRule().evaluate(fin_events, context) == []
    assert TcpFinScanRule().evaluate(xmas_events, context) == []
    assert TcpXmasScanRule().evaluate(xmas_with_ece, context) == []


def test_fin_scan_rejects_normal_fin_ack_closures() -> None:
    events = [
        _event(f"fin-ack-{index}", index, tcp_flags="FIN,ACK", action="allow")
        for index in range(3)
    ]

    assert TcpFinScanRule().evaluate(
        events,
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    ) == []


def test_ack_scan_rejects_allowed_traffic_and_ack_reset() -> None:
    context = DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME)
    allowed_ack = [
        _event(f"allowed-ack-{index}", index, tcp_flags="ACK", action="allow")
        for index in range(3)
    ]
    ack_reset = [
        _event(f"ack-rst-{index}", index, tcp_flags="ACK,RST")
        for index in range(3)
    ]

    assert TcpAckScanRule().evaluate(allowed_ack, context) == []
    assert TcpAckScanRule().evaluate(ack_reset, context) == []


@pytest.mark.parametrize(
    ("rule", "flags"),
    [
        (TcpSynFinAnomalyRule(), "SYN,FIN"),
        (TcpSynRstAnomalyRule(), "SYN,RST"),
    ],
)
def test_single_invalid_combination_packet_does_not_trigger(
    rule: BaseDetectionRule,
    flags: str,
) -> None:
    event = _event("single-invalid", 0, tcp_flags=flags, spi=True)

    assert rule.evaluate(
        [event],
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    ) == []


def test_repeated_resets_require_diversity_and_exclude_syn_rst() -> None:
    context = DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME)
    same_endpoint = [
        _event(
            f"same-reset-{index}",
            index,
            tcp_flags="RST,ACK",
            dst_ip="198.51.100.80",
            dst_port=443,
        )
        for index in range(3)
    ]
    syn_rst = [
        _event(f"syn-rst-reset-{index}", index, tcp_flags="SYN,RST")
        for index in range(3)
    ]

    assert RepeatedTcpResetAnomalyRule().evaluate(same_endpoint, context) == []
    assert RepeatedTcpResetAnomalyRule().evaluate(syn_rst, context) == []


def test_spi_sequence_requires_allowed_event_after_related_spi_blocks() -> None:
    events = _spi_sequence_events()
    allowed = events[-1]
    blocked = events[:-1]
    context = DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME)
    rule = SpiFollowedByAllowedConnectionRule()
    allowed_before = allowed.model_copy(
        update={"timestamp": FIXED_TIME - timedelta(seconds=1)}
    )
    unrelated_allowed = allowed.model_copy(update={"dst_ip": "198.51.100.99"})

    assert rule.evaluate([allowed_before, *blocked], context) == []
    assert rule.evaluate([*blocked, unrelated_allowed], context) == []


def test_invalid_or_unknown_flags_do_not_crash_detection() -> None:
    events = [
        _event(f"unknown-{index}", index, tcp_flags="SYN,BOGUS")
        for index in range(3)
    ]
    registry = RuleRegistry()
    registry.register(TcpNullScanRule())
    registry.register(TcpXmasScanRule())

    result = DetectionEngine(registry=registry, settings=_settings()).analyze(events)

    assert result.signals == []
    assert result.warnings == []


def test_overlapping_tcp_windows_deduplicate_deterministically() -> None:
    events = [_event(f"fin-{index}", index, tcp_flags="FIN") for index in range(4)]
    registry = RuleRegistry()
    registry.register(TcpFinScanRule())
    engine = DetectionEngine(registry=registry, settings=_settings())

    first = engine.analyze(events)
    second = engine.analyze(list(reversed(events)))

    assert len(first.signals) == 1
    assert len(first.signals[0].event_ids) == len(set(first.signals[0].event_ids))
    assert len(first.signals[0].evidence) == len(
        {evidence.event_id for evidence in first.signals[0].evidence}
    )
    assert_signal_is_deterministic(first.signals[0], second.signals[0])


def test_existing_spi_burst_identity_and_new_sequence_can_coexist() -> None:
    events = _spi_sequence_events()
    context = DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME)

    spi_signals = SPIAnomalyRule().evaluate(events, context)
    sequence_signals = SpiFollowedByAllowedConnectionRule().evaluate(events, context)

    assert len(spi_signals) == 1
    assert spi_signals[0].rule_id == "spi_anomaly_burst"
    assert spi_signals[0].signal_type == "spi_anomaly"
    assert len(sequence_signals) == 1


@pytest.mark.parametrize(
    ("port", "identity"),
    [
        (3389, ("rdp_probe", "RDP Probe", "rdp_probe")),
        (22, ("ssh_probe", "SSH Probe", "ssh_probe")),
    ],
)
def test_rdp_and_ssh_signal_identities_remain_unchanged(
    port: int,
    identity: tuple[str, str, str],
) -> None:
    events = [
        _event(
            f"remote-{port}-{index}",
            index,
            tcp_flags="SYN",
            dst_port=port,
        )
        for index in range(3)
    ]
    rule = RemoteServiceProbeRule()
    signal = rule.evaluate(
        events,
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    )[0]

    assert (signal.rule_id, signal.rule_name, signal.signal_type) == identity


def test_service_probe_precedence_and_tcp_anomaly_coexistence_are_preserved() -> None:
    events = [
        _event(
            f"rdp-syn-rst-{index}",
            index,
            tcp_flags="SYN,RST",
            spi=True,
            dst_port=3389,
        )
        for index in range(3)
    ]
    registry = RuleRegistry()
    registry.register(RemoteServiceProbeRule())
    registry.register(HorizontalScanRule())
    registry.register(TcpSynRstAnomalyRule())

    result = DetectionEngine(registry=registry, settings=_settings()).analyze(events)

    assert {signal.signal_type for signal in result.signals} == {
        "rdp_probe",
        "tcp_syn_rst_anomaly",
    }


def test_default_registry_contains_exactly_twenty_nine_unique_rules() -> None:
    register_default_rules()
    register_default_rules()
    rules = default_registry.get_all_rules()
    rule_ids = {rule.rule_id for rule in rules}

    assert len(rules) == 29
    assert len(rule_ids) == 29
    assert EXISTING_RULE_IDS.issubset(rule_ids)
    assert NEW_RULE_IDS.issubset(rule_ids)
    assert all(
        DetectionRuleMetadata.model_validate(rule.metadata.model_dump()) == rule.metadata
        for rule in rules
    )


def test_tcp_anomaly_setting_defaults_are_conservative() -> None:
    settings = DetectionSettings()

    assert settings.TCP_FLAG_SCAN_WINDOW_SECONDS == 300
    assert settings.TCP_FLAG_SCAN_MIN_EVENTS == 5
    assert settings.TCP_FLAG_SCAN_MIN_DISTINCT_TARGETS == 3
    assert settings.TCP_FLAG_SCAN_MIN_DISTINCT_PORTS == 3
    assert settings.TCP_FLAG_SCAN_MIN_BLOCK_RATIO == 0.60
    assert settings.TCP_ACK_SCAN_MIN_EVENTS == 10
    assert settings.TCP_ACK_SCAN_MIN_BLOCK_RATIO == 0.85
    assert settings.TCP_INVALID_COMBINATION_MIN_EVENTS == 5
    assert settings.TCP_INVALID_COMBINATION_MIN_BLOCK_RATIO == 0.80
    assert settings.TCP_RESET_ANOMALY_WINDOW_SECONDS == 300
    assert settings.TCP_RESET_ANOMALY_MIN_EVENTS == 10
    assert settings.TCP_RESET_ANOMALY_MIN_DISTINCT_TARGETS == 3
    assert settings.TCP_RESET_ANOMALY_MIN_DISTINCT_PORTS == 3
    assert settings.TCP_RESET_ANOMALY_MIN_BLOCK_RATIO == 0.60
    assert settings.SPI_THEN_ALLOWED_WINDOW_SECONDS == 600
    assert settings.SPI_THEN_ALLOWED_MIN_SPI_EVENTS == 3


@pytest.mark.parametrize(
    "overrides",
    [
        {"TCP_FLAG_SCAN_WINDOW_SECONDS": 0},
        {"TCP_FLAG_SCAN_MIN_DISTINCT_PORTS": 0},
        {"TCP_ACK_SCAN_MIN_BLOCK_RATIO": 1.01},
        {"TCP_INVALID_COMBINATION_MIN_BLOCK_RATIO": -0.01},
        {"TCP_RESET_ANOMALY_MIN_EVENTS": 0},
        {"SPI_THEN_ALLOWED_MIN_SPI_EVENTS": 0},
    ],
)
def test_tcp_anomaly_settings_reject_invalid_values(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _settings(**overrides)


def test_tcp_spi_detection_makes_zero_provider_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("provider or agent invocation is forbidden during detection")

    monkeypatch.setattr("agent.triage.runner.TriageRunner.run", fail_if_called)
    events = [_event(f"null-{index}", index, tcp_flags="NONE") for index in range(5)]
    register_default_rules()

    result = DetectionEngine().analyze(events)

    assert any(signal.signal_type == "tcp_null_scan" for signal in result.signals)
