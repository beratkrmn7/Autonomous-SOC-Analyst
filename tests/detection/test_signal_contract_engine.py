import logging

from agent.detection.config import DetectionSettings
from agent.detection.detectors.base import BaseDetectionRule
from agent.detection.engine import DetectionEngine
from agent.detection.registry import RuleRegistry
from tests.detection.helpers import build_event
from tests.detection.test_rule_contracts import make_metadata, make_signal


class InvalidSignalRule(BaseDetectionRule):
    metadata = make_metadata(rule_id="invalid_signal_rule")

    def evaluate(self, events, context):
        return [make_signal(rule_id="wrong_rule", signal_id="SIG-INVALID")]


class ValidSignalRule(BaseDetectionRule):
    metadata = make_metadata(rule_id="valid_signal_rule")

    def evaluate(self, events, context):
        return [
            make_signal(
                rule_id=self.rule_id,
                rule_name=self.name,
                signal_id="SIG-VALID",
            )
        ]


class RecordingEligibilityRule(BaseDetectionRule):
    metadata = make_metadata(
        rule_id="recording_eligibility_rule",
        supported_event_types=("network",),
        required_fields=("src_ip", "dst_ip"),
    )

    def __init__(self) -> None:
        self.event_ids: list[str] = []

    def evaluate(self, events, context):
        self.event_ids = [event.event_id for event in events]
        return []


def test_invalid_signal_does_not_stop_other_rules(caplog) -> None:
    registry = RuleRegistry()
    registry.register(InvalidSignalRule())
    registry.register(ValidSignalRule())
    engine = DetectionEngine(registry=registry, settings=DetectionSettings())

    with caplog.at_level(logging.WARNING):
        result = engine.analyze([build_event()])

    assert [signal.signal_id for signal in result.signals] == ["SIG-VALID"]
    assert result.warnings == [
        "Rule invalid_signal_rule produced invalid signal SIG-INVALID: rule_id_mismatch"
    ]
    assert result.warnings[0] in caplog.text
    assert "deterministic test event" not in caplog.text


def test_engine_applies_rule_level_event_eligibility() -> None:
    rule = RecordingEligibilityRule()
    registry = RuleRegistry()
    registry.register(rule)
    engine = DetectionEngine(registry=registry, settings=DetectionSettings())

    engine.analyze(
        [
            build_event("valid"),
            build_event("missing-destination", dst_ip=None),
            build_event("authentication", event_type="authentication"),
        ]
    )

    assert rule.event_ids == ["valid"]
