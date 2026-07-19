from datetime import datetime, timezone
from typing import List, Sequence

import pytest

from agent.application.analysis_service import AnalysisService
from agent.detection.detectors.base import BaseDetectionRule, DetectionContext
from agent.detection.engine import DetectionEngine
from agent.detection.models import DetectionSignal
from agent.detection.registry import RuleRegistry
from agent.filtering import EventFilter
from agent.schema import CanonicalLogEvent


NOW = datetime(2026, 7, 10, 9, 51, tzinfo=timezone.utc)


class RecordingRule(BaseDetectionRule):
    rule_id = "recording_rule"
    version = "1.0.0"
    name = "Recording Rule"
    family = "test"
    priority = 1

    def __init__(self) -> None:
        self.evaluation_count = 0
        self.event_ids: List[str] = []

    def evaluate(
        self,
        events: Sequence[CanonicalLogEvent],
        context: DetectionContext,
    ) -> List[DetectionSignal]:
        self.evaluation_count += 1
        self.event_ids = [event.event_id for event in events]
        return []


def _event(event_id: str, **overrides: object) -> CanonicalLogEvent:
    fields: dict[str, object] = {
        "event_id": event_id,
        "timestamp": NOW,
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
        "protocol": "tcp",
        "action": "pass",
        "parser_name": "test",
        "parse_status": "parsed",
    }
    fields.update(overrides)
    return CanonicalLogEvent.model_validate(fields)


def _service_with_recording_rule() -> tuple[AnalysisService, RecordingRule]:
    rule = RecordingRule()
    registry = RuleRegistry()
    registry.register(rule)
    service = AnalysisService()
    service.detection_engine = DetectionEngine(registry=registry)
    return service, rule


def test_context_event_reaches_detection_rule_evaluation() -> None:
    event = _event("context", dst_port=12345, bytes=1000)
    roles = EventFilter().filter_events([event])
    assert [item.event_id for item in roles.context] == [event.event_id]

    service, rule = _service_with_recording_rule()
    service.analyze_events([event], run_triage=False)

    assert rule.event_ids == [event.event_id]


def test_noise_event_reaches_detection_rule_evaluation() -> None:
    event = _event("https-noise", dst_port=443, bytes=1200)
    roles = EventFilter().filter_events([event])
    assert [item.event_id for item in roles.noise] == [event.event_id]

    service, rule = _service_with_recording_rule()
    service.analyze_events([event], run_triage=False)

    assert rule.event_ids == [event.event_id]


def test_normal_dns_noise_reaches_detection_rule_evaluation() -> None:
    event = _event("dns-noise", dst_port=53, bytes=200, protocol="udp")
    roles = EventFilter().filter_events([event])
    assert [item.event_id for item in roles.noise] == [event.event_id]

    service, rule = _service_with_recording_rule()
    service.analyze_events([event], run_triage=False)

    assert rule.event_ids == [event.event_id]


@pytest.mark.parametrize(
    "parse_status",
    ["failed", "unsupported_schema", "semantically_invalid"],
)
def test_invalid_event_does_not_reach_rule_evaluation(parse_status: str) -> None:
    event = _event(f"invalid-{parse_status}", parse_status=parse_status)
    service, rule = _service_with_recording_rule()

    result = service.analyze_events([event], run_triage=False)

    assert rule.evaluation_count == 0
    assert result.detection_result is not None
    assert result.detection_result.metrics.eligible_events == 0
    assert result.detection_result.metrics.skipped_events == 1
