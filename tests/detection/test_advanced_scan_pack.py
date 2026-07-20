from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

import pytest
from pydantic import ValidationError

from agent.detection.config import DetectionSettings
from agent.detection.contracts import DetectionRuleMetadata
from agent.detection.detectors import register_default_rules
from agent.detection.detectors.base import BaseDetectionRule, DetectionContext
from agent.detection.detectors.coordinated_scan import (
    DistributedScanRule,
    RepeatedBlockedScannerRule,
)
from agent.detection.detectors.low_and_slow_scan import (
    LowAndSlowHorizontalScanRule,
    LowAndSlowVerticalScanRule,
)
from agent.detection.detectors.remote_service_probe import RemoteServiceProbeRule
from agent.detection.detectors.scan_sequence import (
    ScanFollowedByAllowedConnectionRule,
)
from agent.detection.detectors.service_sweep import (
    InternalLateralScanRule,
    MultiServiceSweepRule,
)
from agent.detection.detectors.subnet_sweep import SubnetSweepRule
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


def _settings(**overrides: object) -> DetectionSettings:
    values: dict[str, object] = {
        "LOW_SLOW_HORIZONTAL_WINDOW_SECONDS": 120,
        "LOW_SLOW_HORIZONTAL_MIN_EVENTS": 4,
        "LOW_SLOW_HORIZONTAL_MIN_DISTINCT_TARGETS": 4,
        "LOW_SLOW_HORIZONTAL_MIN_SPAN_SECONDS": 30,
        "LOW_SLOW_HORIZONTAL_MIN_BLOCK_RATIO": 0.75,
        "LOW_SLOW_HORIZONTAL_MIN_SYN_RATIO": 0.75,
        "LOW_SLOW_VERTICAL_WINDOW_SECONDS": 120,
        "LOW_SLOW_VERTICAL_MIN_EVENTS": 4,
        "LOW_SLOW_VERTICAL_MIN_DISTINCT_PORTS": 4,
        "LOW_SLOW_VERTICAL_MIN_SPAN_SECONDS": 30,
        "LOW_SLOW_VERTICAL_MIN_BLOCK_RATIO": 0.75,
        "LOW_SLOW_VERTICAL_MIN_SYN_RATIO": 0.75,
        "REPEATED_BLOCKED_SCANNER_WINDOW_SECONDS": 120,
        "REPEATED_BLOCKED_SCANNER_MIN_EVENTS": 4,
        "REPEATED_BLOCKED_SCANNER_MIN_BLOCK_RATIO": 0.75,
        "REPEATED_BLOCKED_SCANNER_MIN_DISTINCT_TARGETS": 2,
        "REPEATED_BLOCKED_SCANNER_MIN_DISTINCT_PORTS": 2,
        "INTERNAL_LATERAL_SCAN_WINDOW_SECONDS": 120,
        "INTERNAL_LATERAL_SCAN_MIN_EVENTS": 4,
        "INTERNAL_LATERAL_SCAN_MIN_DISTINCT_TARGETS": 3,
        "INTERNAL_LATERAL_SCAN_MIN_BLOCK_RATIO": 0.75,
        "INTERNAL_LATERAL_SCAN_MIN_SYN_RATIO": 0.75,
        "SUBNET_SWEEP_WINDOW_SECONDS": 120,
        "SUBNET_SWEEP_MIN_EVENTS": 4,
        "SUBNET_SWEEP_MIN_DISTINCT_TARGETS": 4,
        "SUBNET_SWEEP_MIN_BLOCK_RATIO": 0.75,
        "SUBNET_SWEEP_MIN_SYN_RATIO": 0.75,
        "DISTRIBUTED_SCAN_WINDOW_SECONDS": 120,
        "DISTRIBUTED_SCAN_MIN_EVENTS": 4,
        "DISTRIBUTED_SCAN_MIN_DISTINCT_SOURCES": 4,
        "DISTRIBUTED_SCAN_MIN_BLOCK_RATIO": 0.75,
        "DISTRIBUTED_SCAN_MIN_SYN_RATIO": 0.75,
        "MULTI_SERVICE_SWEEP_WINDOW_SECONDS": 120,
        "MULTI_SERVICE_SWEEP_MIN_EVENTS": 4,
        "MULTI_SERVICE_SWEEP_MIN_DISTINCT_SERVICES": 3,
        "MULTI_SERVICE_SWEEP_MIN_DISTINCT_TARGETS": 3,
        "MULTI_SERVICE_SWEEP_MIN_BLOCK_RATIO": 0.75,
        "MULTI_SERVICE_SWEEP_MIN_SYN_RATIO": 0.75,
        "SCAN_THEN_ALLOWED_WINDOW_SECONDS": 120,
        "SCAN_THEN_ALLOWED_MIN_BLOCKED_EVENTS": 4,
        "SCAN_THEN_ALLOWED_MIN_DISTINCT_TARGETS": 2,
        "SCAN_THEN_ALLOWED_MIN_DISTINCT_PORTS": 2,
    }
    values.update(overrides)
    return DetectionSettings.model_validate(values)


def _network_event(event_id: str, index: int, **overrides: object) -> CanonicalLogEvent:
    values: dict[str, object] = {
        "timestamp": FIXED_TIME + timedelta(seconds=index),
        "action": "block",
        "protocol": "TCP",
        "tcp_flags": "SYN",
    }
    values.update(overrides)
    return build_event(event_id, **values)


def _low_horizontal_positive() -> list[CanonicalLogEvent]:
    return [
        _network_event(
            f"low-horizontal-{index}",
            index * 20,
            src_ip="192.0.2.10",
            dst_ip=f"198.51.100.{index + 1}",
            dst_port=8443,
        )
        for index in range(4)
    ]


def _low_horizontal_negative() -> list[CanonicalLogEvent]:
    return [
        _network_event(
            f"fast-horizontal-{index}",
            index,
            dst_ip=f"198.51.100.{index + 1}",
            dst_port=8443,
        )
        for index in range(4)
    ]


def _low_vertical_positive() -> list[CanonicalLogEvent]:
    return [
        _network_event(
            f"low-vertical-{index}",
            index * 20,
            dst_ip="198.51.100.80",
            dst_port=8000 + index,
        )
        for index in range(4)
    ]


def _low_vertical_negative() -> list[CanonicalLogEvent]:
    return [
        _network_event(
            f"fast-vertical-{index}",
            index,
            dst_ip="198.51.100.80",
            dst_port=8000 + index,
        )
        for index in range(4)
    ]


def _repeated_positive() -> list[CanonicalLogEvent]:
    return [
        _network_event(
            f"repeated-{index}",
            index,
            dst_ip=f"198.51.100.{20 + index % 2}",
            dst_port=9000,
        )
        for index in range(4)
    ]


def _repeated_negative() -> list[CanonicalLogEvent]:
    return [
        _network_event(
            f"single-endpoint-{index}",
            index,
            dst_ip="198.51.100.30",
            dst_port=9000,
        )
        for index in range(4)
    ]


def _internal_positive() -> list[CanonicalLogEvent]:
    ports = [22, 445, 3389, 5985]
    return [
        _network_event(
            f"internal-{index}",
            index,
            src_ip="10.0.0.10",
            dst_ip=f"10.0.1.{index + 10}",
            dst_port=ports[index],
        )
        for index in range(4)
    ]


def _internal_negative() -> list[CanonicalLogEvent]:
    return [
        event.model_copy(update={"src_ip": "8.8.8.8"})
        for event in _internal_positive()
    ]


def _subnet_positive() -> list[CanonicalLogEvent]:
    return [
        _network_event(
            f"subnet-{index}",
            index,
            dst_ip=f"10.10.20.{index + 1}",
            dst_port=8443,
        )
        for index in range(4)
    ]


def _subnet_negative() -> list[CanonicalLogEvent]:
    return [
        _network_event(
            f"different-subnet-{index}",
            index,
            dst_ip=f"10.10.{index}.1",
            dst_port=8443,
        )
        for index in range(4)
    ]


def _distributed_positive() -> list[CanonicalLogEvent]:
    return [
        _network_event(
            f"distributed-{index}",
            index,
            src_ip=f"203.0.113.{index + 1}",
            dst_ip="10.0.0.50",
            dst_port=22,
        )
        for index in range(4)
    ]


def _distributed_negative() -> list[CanonicalLogEvent]:
    return [
        _network_event(
            f"web-{index}",
            index,
            src_ip=f"203.0.113.{index + 1}",
            dst_ip="10.0.0.80",
            dst_port=443,
            action="allow",
            tcp_flags="ACK",
        )
        for index in range(4)
    ]


def _multi_service_positive() -> list[CanonicalLogEvent]:
    ports = [22, 3389, 445, 5985]
    return [
        _network_event(
            f"multi-service-{index}",
            index,
            dst_ip=f"198.51.100.{index + 1}",
            dst_port=ports[index],
        )
        for index in range(4)
    ]


def _multi_service_negative() -> list[CanonicalLogEvent]:
    return [
        _network_event(
            f"single-service-{index}",
            index,
            dst_ip=f"198.51.100.{index + 1}",
            dst_port=22,
        )
        for index in range(4)
    ]


def _sequence_positive() -> list[CanonicalLogEvent]:
    blocked = [
        _network_event(
            f"sequence-blocked-{index}",
            index,
            dst_ip=f"198.51.100.{index % 2 + 1}",
            dst_port=22,
        )
        for index in range(4)
    ]
    return [
        *blocked,
        _network_event(
            "sequence-allowed",
            5,
            dst_ip="198.51.100.1",
            dst_port=22,
            action="allow",
            tcp_flags="ACK",
        ),
    ]


def _sequence_negative() -> list[CanonicalLogEvent]:
    events = _sequence_positive()
    return [events[-1].model_copy(update={"timestamp": FIXED_TIME - timedelta(seconds=1)}), *events[:-1]]


@dataclass(frozen=True)
class RuleCase:
    case_id: str
    rule: BaseDetectionRule
    positive_events: Callable[[], list[CanonicalLogEvent]]
    negative_events: Callable[[], list[CanonicalLogEvent]]


RULE_CASES = (
    RuleCase(
        "low-horizontal",
        LowAndSlowHorizontalScanRule(),
        _low_horizontal_positive,
        _low_horizontal_negative,
    ),
    RuleCase(
        "low-vertical",
        LowAndSlowVerticalScanRule(),
        _low_vertical_positive,
        _low_vertical_negative,
    ),
    RuleCase(
        "repeated-blocked",
        RepeatedBlockedScannerRule(),
        _repeated_positive,
        _repeated_negative,
    ),
    RuleCase(
        "internal-lateral",
        InternalLateralScanRule(),
        _internal_positive,
        _internal_negative,
    ),
    RuleCase("subnet", SubnetSweepRule(), _subnet_positive, _subnet_negative),
    RuleCase(
        "distributed",
        DistributedScanRule(),
        _distributed_positive,
        _distributed_negative,
    ),
    RuleCase(
        "multi-service",
        MultiServiceSweepRule(),
        _multi_service_positive,
        _multi_service_negative,
    ),
    RuleCase(
        "scan-then-allowed",
        ScanFollowedByAllowedConnectionRule(),
        _sequence_positive,
        _sequence_negative,
    ),
)


@pytest.mark.parametrize("case", RULE_CASES, ids=lambda case: case.case_id)
def test_advanced_scan_rule_positive_contract_and_determinism(case: RuleCase) -> None:
    events = case.positive_events()
    context = DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME)

    first = case.rule.evaluate(events, context)
    second = case.rule.evaluate(events, context)

    assert len(first) == 1
    assert len(second) == 1
    assert first[0].signal_type == case.rule.metadata.signal_type
    assert_signal_contract(first[0], case.rule, events)
    assert_evidence_belongs_to_signal(first[0])
    assert_signal_is_deterministic(first[0], second[0])


@pytest.mark.parametrize("case", RULE_CASES, ids=lambda case: case.case_id)
def test_advanced_scan_rule_negative_or_below_threshold(case: RuleCase) -> None:
    context = DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME)
    assert case.rule.evaluate(case.negative_events(), context) == []


def test_default_registry_contains_exactly_twenty_nine_valid_rules() -> None:
    register_default_rules()
    rules = default_registry.get_all_rules()

    assert len(rules) == 29
    assert len({rule.rule_id for rule in rules}) == 29
    assert all(
        DetectionRuleMetadata.model_validate(rule.metadata.model_dump()) == rule.metadata
        for rule in rules
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"LOW_SLOW_HORIZONTAL_WINDOW_SECONDS": 0},
        {
            "LOW_SLOW_HORIZONTAL_WINDOW_SECONDS": 10,
            "LOW_SLOW_HORIZONTAL_MIN_SPAN_SECONDS": 11,
        },
        {"DISTRIBUTED_SCAN_MIN_BLOCK_RATIO": 1.01},
        {"SUBNET_SWEEP_IPV4_PREFIX": 33},
        {"INTERNAL_LATERAL_SCAN_PORTS": (22, 22)},
        {"INTERNAL_LATERAL_SCAN_PORTS": (0,)},
    ],
)
def test_advanced_scan_settings_reject_invalid_values(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _settings(**overrides)


def test_subnet_sweep_skips_malformed_ip_without_losing_valid_group() -> None:
    events = [
        _network_event("malformed-ip", 0, dst_ip="not-an-ip", dst_port=8443),
        *_subnet_positive(),
    ]
    rule = SubnetSweepRule()

    signals = rule.evaluate(
        events,
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    )

    assert len(signals) == 1
    assert "malformed-ip" not in signals[0].event_ids


def test_scan_then_allowed_uses_timestamp_and_event_id_order() -> None:
    same_time_blocks = [
        _network_event(
            f"m-blocked-{index}",
            0,
            dst_ip=f"198.51.100.{index % 2 + 1}",
            dst_port=22,
        )
        for index in range(4)
    ]
    allowed_after = _network_event(
        "z-allowed",
        0,
        dst_ip="198.51.100.1",
        dst_port=22,
        action="allow",
        tcp_flags="ACK",
    )
    allowed_before = allowed_after.model_copy(update={"event_id": "a-allowed"})
    rule = ScanFollowedByAllowedConnectionRule()
    context = DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME)

    after_signals = rule.evaluate([*same_time_blocks, allowed_after], context)
    before_signals = rule.evaluate([*same_time_blocks, allowed_before], context)

    assert len(after_signals) == 1
    assert before_signals == []
    assert allowed_after.event_id in after_signals[0].event_ids
    assert allowed_after.event_id in {
        evidence.event_id for evidence in after_signals[0].evidence
    }


def test_overlapping_advanced_windows_deduplicate() -> None:
    registry = RuleRegistry()
    registry.register(RepeatedBlockedScannerRule())
    events = [
        *_repeated_positive(),
        _network_event(
            "repeated-extra",
            5,
            dst_ip="198.51.100.20",
            dst_port=9000,
        ),
    ]

    result = DetectionEngine(registry=registry, settings=_settings()).analyze(events)

    assert len(result.signals) == 1
    assert len(result.signals[0].event_ids) == len(set(result.signals[0].event_ids))
    assert len(result.signals[0].evidence) == len(
        {evidence.event_id for evidence in result.signals[0].evidence}
    )


def test_remote_service_precedence_does_not_absorb_low_and_slow_signal() -> None:
    registry = RuleRegistry()
    registry.register(RemoteServiceProbeRule())
    registry.register(LowAndSlowHorizontalScanRule())
    settings = _settings(
        REMOTE_SERVICE_MIN_EVENTS=2,
        REMOTE_SERVICE_MIN_DISTINCT_TARGETS=2,
    )
    events = [event.model_copy(update={"dst_port": 3389}) for event in _low_horizontal_positive()]

    result = DetectionEngine(registry=registry, settings=settings).analyze(events)

    assert {signal.signal_type for signal in result.signals} == {
        "rdp_probe",
        "low_and_slow_horizontal_scan",
    }


@pytest.mark.parametrize(
    ("port", "identity"),
    [
        (3389, ("rdp_probe", "RDP Probe", "rdp_probe")),
        (22, ("ssh_probe", "SSH Probe", "ssh_probe")),
    ],
)
def test_remote_service_signal_variants_remain_unchanged(
    port: int,
    identity: tuple[str, str, str],
) -> None:
    events = [
        _network_event(
            f"remote-{port}-{index}",
            index,
            dst_ip=f"198.51.100.{index + 1}",
            dst_port=port,
        )
        for index in range(2)
    ]
    rule = RemoteServiceProbeRule()
    context = DetectionContext(
        settings=_settings(
            REMOTE_SERVICE_MIN_EVENTS=2,
            REMOTE_SERVICE_MIN_DISTINCT_TARGETS=2,
        ),
        analysis_started_at=FIXED_TIME,
    )

    signal = rule.evaluate(events, context)[0]

    assert (signal.rule_id, signal.rule_name, signal.signal_type) == identity


def test_detection_with_advanced_default_pack_makes_zero_provider_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("provider or agent invocation is forbidden during detection")

    monkeypatch.setattr("agent.triage.runner.TriageRunner.run", fail_if_called)
    register_default_rules()

    result = DetectionEngine(settings=_settings()).analyze(_repeated_positive())

    assert any(signal.signal_type == "repeated_blocked_scanner" for signal in result.signals)
