from collections.abc import Sequence
from datetime import datetime, timezone

from agent.detection.contracts import validate_signal_contract
from agent.detection.detectors.base import BaseDetectionRule
from agent.detection.models import DetectionSignal
from agent.schema import CanonicalLogEvent


FIXED_TIME = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)


def build_event(event_id: str = "event-1", **overrides: object) -> CanonicalLogEvent:
    values: dict[str, object] = {
        "event_id": event_id,
        "timestamp": FIXED_TIME,
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "src_port": 49152,
        "dst_port": 443,
        "protocol": "TCP",
        "action": "block",
        "event_type": "network",
        "parser_name": "test_builder",
        "parse_status": "parsed",
        "safe_message_excerpt": "deterministic test event",
    }
    values.update(overrides)
    return CanonicalLogEvent.model_validate(values)


def build_pf_event(
    event_id: str = "pf-event-1",
    *,
    spi: bool = False,
    **overrides: object,
) -> CanonicalLogEvent:
    values: dict[str, object] = {
        "parser_name": "pf_firewall",
        "parser_metadata": {"spi_anomaly": spi},
    }
    values.update(overrides)
    return build_event(event_id, **values)


def assert_signal_contract(
    signal: DetectionSignal,
    rule: BaseDetectionRule,
    input_events: Sequence[CanonicalLogEvent],
) -> None:
    validate_signal_contract(signal, rule, {event.event_id for event in input_events})


def assert_evidence_belongs_to_signal(signal: DetectionSignal) -> None:
    assert {item.event_id for item in signal.evidence}.issubset(signal.event_ids)


def assert_no_duplicate_signals(signals: Sequence[DetectionSignal]) -> None:
    ids = [signal.signal_id for signal in signals]
    assert len(ids) == len(set(ids))


def assert_signal_is_deterministic(
    first: DetectionSignal,
    second: DetectionSignal,
) -> None:
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
