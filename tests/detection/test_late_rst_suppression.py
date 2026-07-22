from datetime import timedelta

import pytest

from agent.detection.config import DetectionSettings
from agent.detection.detectors.spi_anomaly import SPIAnomalyRule
from agent.detection.engine import DetectionEngine
from agent.detection.registry import RuleRegistry
from agent.detection.suppression import LATE_RST_SUPPRESSION_REASON
from tests.detection.helpers import FIXED_TIME, build_pf_event


def _events(**overrides):
    events = []
    for index in range(5):
        values = {
            "timestamp": FIXED_TIME + timedelta(milliseconds=index),
            "src_ip": "20.190.147.7",
            "dst_ip": "193.255.130.23",
            "src_port": 443,
            "dst_port": 40_000 + index,
            "protocol": "TCP",
            "action": "block",
            "tcp_flags": "RST,ACK",
            "parser_metadata": {
                "spi_anomaly": True,
                "original_device_action": "blocked by spi",
            },
        }
        values.update(overrides)
        events.append(build_pf_event(f"late-rst-{index}", spi=True, **values))
    return events


def _engine() -> DetectionEngine:
    registry = RuleRegistry()
    registry.register(SPIAnomalyRule())
    return DetectionEngine(
        registry=registry,
        settings=DetectionSettings(
            SPI_ANOMALY_MIN_EVENTS=5,
            SPI_ANOMALY_MIN_DISTINCT_TARGETS=1,
        ),
    )


def test_verified_late_rst_spi_pattern_is_suppressed_with_exact_reason() -> None:
    result = _engine().analyze(_events())

    assert result.signals == []
    assert result.incidents == []
    assert len(result.suppressed_signals) == 1
    assert result.suppressed_signals[0].suppression_reason == (
        LATE_RST_SUPPRESSION_REASON
    )
    assert result.metrics.suppressed_signal_count == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"src_port": 44_444},
        {"dst_port": 22},
        {"dst_ip": None},
        {"tcp_flags": "SYN"},
        {"action": "pass"},
        {"parser_metadata": {"spi_anomaly": False}},
    ],
)
def test_near_miss_late_rst_patterns_are_not_suppressed(overrides) -> None:
    events = _events(**overrides)
    # Keep SPI rule evaluation active for the explicit-action/metadata near
    # misses without weakening the suppression predicate.
    if overrides == {"parser_metadata": {"spi_anomaly": False}}:
        events = [
            event.model_copy(update={"action_reason": "blocked by spi"})
            for event in events
        ]
    result = _engine().analyze(events)

    assert result.suppressed_signals == []


def test_repeated_ephemeral_destination_port_is_not_suppressed() -> None:
    events = [event.model_copy(update={"dst_port": 40_000}) for event in _events()]
    result = _engine().analyze(events)
    assert result.suppressed_signals == []


def test_multiple_destination_ips_are_not_suppressed() -> None:
    events = _events()
    events[-1] = events[-1].model_copy(update={"dst_ip": "193.255.130.24"})
    result = _engine().analyze(events)
    assert result.suppressed_signals == []


def test_single_reset_event_is_not_a_late_rst_sequence() -> None:
    registry = RuleRegistry()
    registry.register(SPIAnomalyRule())
    engine = DetectionEngine(
        registry=registry,
        settings=DetectionSettings(
            SPI_ANOMALY_MIN_EVENTS=1,
            SPI_ANOMALY_MIN_DISTINCT_TARGETS=1,
        ),
    )

    result = engine.analyze(_events()[:1])

    assert result.suppressed_signals == []
    assert len(result.signals) == 1
