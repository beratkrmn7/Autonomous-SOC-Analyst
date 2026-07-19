from datetime import datetime, timezone

from agent.detection.config import DetectionSettings
from agent.detection.detectors.base import DetectionContext
from agent.detection.detectors.spi_anomaly import SPIAnomalyRule
from agent.schema import CanonicalLogEvent


NOW = datetime(2026, 7, 10, 9, 51, tzinfo=timezone.utc)


def _events(count: int, *, spi: bool) -> list[CanonicalLogEvent]:
    settings = DetectionSettings()
    distinct_targets = max(settings.SPI_ANOMALY_MIN_DISTINCT_TARGETS, 1)
    return [
        CanonicalLogEvent(
            event_id=f"event-{i}",
            timestamp=NOW,
            src_ip="192.0.2.44",
            dst_ip=f"198.51.100.{(i % distinct_targets) + 1}",
            dst_port=8787,
            protocol="tcp",
            action="block",
            action_reason="unexpected tcp flags" if spi else "match",
            parser_metadata={
                "original_device_action": "blocked by spi" if spi else "block",
                "spi_anomaly": spi,
            },
            safe_message_excerpt=(
                "BLOCK TCP 192.0.2.44 -> 198.51.100.1:8787 spi=true"
                if spi
                else "BLOCK TCP 192.0.2.44 -> 198.51.100.1:8787 reason=match"
            ),
            parser_name="pf_firewall",
            parse_status="parsed",
        )
        for i in range(count)
    ]


def test_spi_burst_at_configured_threshold_produces_signal() -> None:
    rule = SPIAnomalyRule()
    settings = DetectionSettings()
    context = DetectionContext(settings=settings, analysis_started_at=NOW)
    events = _events(settings.SPI_ANOMALY_MIN_EVENTS, spi=True)

    signals = rule.evaluate(events, context)

    assert len(signals) == 1
    signal = signals[0]
    assert signal.rule_id == "spi_anomaly_burst"
    assert signal.signal_type == "spi_anomaly"
    assert signal.primary_entity == "192.0.2.44"
    input_event_ids = {event.event_id for event in events}
    assert set(signal.event_ids) <= input_event_ids
    assert {evidence.event_id for evidence in signal.evidence} <= input_event_ids


def test_spi_burst_below_configured_threshold_produces_no_signal() -> None:
    rule = SPIAnomalyRule()
    settings = DetectionSettings()
    context = DetectionContext(settings=settings, analysis_started_at=NOW)
    assert settings.SPI_ANOMALY_MIN_EVENTS > 0
    events = _events(settings.SPI_ANOMALY_MIN_EVENTS - 1, spi=True)

    assert rule.evaluate(events, context) == []


def test_normal_blocked_events_do_not_produce_spi_signal() -> None:
    rule = SPIAnomalyRule()
    settings = DetectionSettings()
    context = DetectionContext(settings=settings, analysis_started_at=NOW)
    events = _events(settings.SPI_ANOMALY_MIN_EVENTS, spi=False)

    assert rule.evaluate(events, context) == []


def test_spi_rule_retains_safe_excerpt_fallback() -> None:
    rule = SPIAnomalyRule()
    settings = DetectionSettings()
    context = DetectionContext(settings=settings, analysis_started_at=NOW)
    events = _events(settings.SPI_ANOMALY_MIN_EVENTS, spi=False)
    for event in events:
        event.safe_message_excerpt = "BLOCKED BY SPI"

    signals = rule.evaluate(events, context)

    if settings.SPI_ANOMALY_FALLBACK_RAW_MATCH:
        assert len(signals) == 1
    else:
        assert signals == []
