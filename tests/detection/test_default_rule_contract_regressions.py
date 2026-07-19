from datetime import timedelta

import pytest

from agent.detection.config import DetectionSettings
from agent.detection.detectors.base import BaseDetectionRule, DetectionContext
from agent.detection.detectors.horizontal_scan import HorizontalScanRule
from agent.detection.detectors.network_flood import NetworkFloodRule
from agent.detection.detectors.remote_service_probe import RemoteServiceProbeRule
from agent.detection.detectors.spi_anomaly import SPIAnomalyRule
from agent.detection.detectors.vertical_scan import VerticalScanRule
from agent.detection.engine import DetectionEngine
from agent.detection.registry import RuleRegistry
from agent.schema import CanonicalLogEvent
from tests.detection.helpers import (
    FIXED_TIME,
    assert_evidence_belongs_to_signal,
    assert_no_duplicate_signals,
    assert_signal_contract,
    assert_signal_is_deterministic,
    build_event,
    build_pf_event,
)


def _events_for(rule: BaseDetectionRule) -> list[CanonicalLogEvent]:
    common = {"action": "block", "protocol": "TCP", "tcp_flags": "SYN"}
    if isinstance(rule, HorizontalScanRule):
        return [
            build_event(
                f"horizontal-{index}",
                timestamp=FIXED_TIME + timedelta(seconds=index),
                dst_ip=f"198.51.100.{index + 1}",
                dst_port=443,
                **common,
            )
            for index in range(2)
        ]
    if isinstance(rule, VerticalScanRule):
        return [
            build_event(
                f"vertical-{index}",
                timestamp=FIXED_TIME + timedelta(seconds=index),
                dst_port=8000 + index,
                **common,
            )
            for index in range(2)
        ]
    if isinstance(rule, RemoteServiceProbeRule):
        return [
            build_event(
                f"remote-{index}",
                timestamp=FIXED_TIME + timedelta(seconds=index),
                dst_ip=f"198.51.100.{index + 1}",
                dst_port=3389,
                **common,
            )
            for index in range(2)
        ]
    if isinstance(rule, SPIAnomalyRule):
        return [
            build_pf_event(
                f"spi-{index}",
                spi=True,
                timestamp=FIXED_TIME + timedelta(seconds=index),
                dst_ip=f"198.51.100.{index + 1}",
            )
            for index in range(2)
        ]
    return [
        build_event(
            f"flood-{index}",
            timestamp=FIXED_TIME + timedelta(seconds=index),
            dst_port=443,
            **common,
        )
        for index in range(2)
    ]


@pytest.mark.parametrize(
    "rule",
    [
        HorizontalScanRule(),
        VerticalScanRule(),
        RemoteServiceProbeRule(),
        SPIAnomalyRule(),
        NetworkFloodRule(),
    ],
)
def test_default_rule_signals_obey_contract_and_are_deterministic(
    rule: BaseDetectionRule,
) -> None:
    settings = DetectionSettings(
        HORIZONTAL_SCAN_MIN_EVENTS=2,
        HORIZONTAL_SCAN_MIN_DISTINCT_TARGETS=2,
        VERTICAL_SCAN_MIN_EVENTS=2,
        VERTICAL_SCAN_MIN_DISTINCT_PORTS=2,
        REMOTE_SERVICE_MIN_EVENTS=2,
        REMOTE_SERVICE_MIN_DISTINCT_TARGETS=2,
        SPI_ANOMALY_MIN_EVENTS=2,
        NETWORK_FLOOD_MIN_EVENTS=2,
    )
    context = DetectionContext(settings=settings, analysis_started_at=FIXED_TIME)
    events = _events_for(rule)

    first = rule.evaluate(events, context)
    second = rule.evaluate(events, context)

    assert len(first) == 1
    assert len(second) == 1
    assert_signal_contract(first[0], rule, events)
    assert_evidence_belongs_to_signal(first[0])
    assert_signal_is_deterministic(first[0], second[0])
    assert_no_duplicate_signals(first)
    assert first[0].mitre_techniques == list(rule.metadata.mitre_techniques)


def test_detection_engine_makes_zero_provider_calls(monkeypatch) -> None:
    def fail_if_called(*args, **kwargs):
        raise AssertionError("provider or agent invocation is forbidden during detection")

    monkeypatch.setattr("agent.triage.runner.TriageRunner.run", fail_if_called)
    registry = RuleRegistry()
    registry.register(SPIAnomalyRule())
    settings = DetectionSettings(SPI_ANOMALY_MIN_EVENTS=2)

    result = DetectionEngine(registry=registry, settings=settings).analyze(
        _events_for(SPIAnomalyRule())
    )

    assert len(result.signals) == 1
