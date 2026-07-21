"""Focused regression tests for RepeatedBlockedScannerRule v1.1.0.

Response-side SPI TCP traffic (for example ACK,RST) must not be mistaken for
scanning, while a genuine blocked SYN scan must still be detected.
"""

from datetime import timedelta

from agent.detection.config import DetectionSettings
from agent.detection.detectors.base import DetectionContext
from agent.detection.detectors.coordinated_scan import RepeatedBlockedScannerRule
from tests.detection.helpers import FIXED_TIME, build_pf_event


def _settings() -> DetectionSettings:
    return DetectionSettings.model_validate(
        {
            "REPEATED_BLOCKED_SCANNER_WINDOW_SECONDS": 120,
            "REPEATED_BLOCKED_SCANNER_MIN_EVENTS": 4,
            "REPEATED_BLOCKED_SCANNER_MIN_BLOCK_RATIO": 0.75,
            "REPEATED_BLOCKED_SCANNER_MIN_DISTINCT_TARGETS": 2,
            "REPEATED_BLOCKED_SCANNER_MIN_DISTINCT_PORTS": 2,
        }
    )


def test_spi_ack_rst_events_do_not_produce_repeated_blocked_scanner() -> None:
    events = [
        build_pf_event(
            f"spi-ack-rst-{index}",
            spi=True,
            timestamp=FIXED_TIME + timedelta(seconds=index),
            action="block",
            protocol="TCP",
            tcp_flags="ACK,RST",
            src_ip="192.0.2.10",
            dst_ip=f"198.51.100.{index + 1}",
            dst_port=9000 + index,
        )
        for index in range(4)
    ]
    rule = RepeatedBlockedScannerRule()
    context = DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME)

    assert rule.evaluate(events, context) == []


def test_blocked_syn_scan_still_produces_repeated_blocked_scanner() -> None:
    events = [
        build_pf_event(
            f"syn-scan-{index}",
            spi=False,
            timestamp=FIXED_TIME + timedelta(seconds=index),
            action="block",
            protocol="TCP",
            tcp_flags="SYN",
            src_ip="192.0.2.10",
            dst_ip=f"198.51.100.{index + 1}",
            dst_port=9000 + index,
        )
        for index in range(4)
    ]
    rule = RepeatedBlockedScannerRule()
    context = DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME)

    signals = rule.evaluate(events, context)

    assert len(signals) == 1
    assert signals[0].signal_type == "repeated_blocked_scanner"
    assert set(signals[0].event_ids) == {event.event_id for event in events}
