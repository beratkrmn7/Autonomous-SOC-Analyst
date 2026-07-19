import pytest

from agent.detection.contracts import DetectionRuleMetadata, RuleContractError
from agent.detection.detectors.base import BaseDetectionRule
from agent.detection.registry import RuleRegistry


def metadata(rule_id: str = "dummy", priority: int = 1) -> DetectionRuleMetadata:
    return DetectionRuleMetadata(
        rule_id=rule_id,
        version="1.0.0",
        name=rule_id.replace("_", " ").title(),
        family="test_family",
        priority=priority,
        signal_type="test_signal",
        default_severity="low",
    )


class DummyRule(BaseDetectionRule):
    metadata = metadata()

    def evaluate(self, events, context):
        return []


def test_registry_lookup_and_unregister_are_compatible() -> None:
    registry = RuleRegistry()
    registry.register(DummyRule())

    assert registry.get_rule("dummy").rule_id == "dummy"
    assert registry.get_rule_metadata("dummy") == DummyRule.metadata
    assert registry.list_rule_metadata() == (DummyRule.metadata,)

    registry.unregister("dummy")
    assert registry.get_all_rules() == []


def test_exact_duplicate_registration_is_idempotent() -> None:
    registry = RuleRegistry()
    registry.register(DummyRule())
    registry.register(DummyRule())
    assert len(registry.get_all_rules()) == 1


def test_equal_priority_is_ordered_by_rule_id() -> None:
    class ZRule(DummyRule):
        metadata = metadata("z_rule", priority=10)

    class ARule(DummyRule):
        metadata = metadata("a_rule", priority=10)

    registry = RuleRegistry()
    registry.register(ZRule())
    registry.register(ARule())
    assert [rule.rule_id for rule in registry.get_all_rules()] == ["a_rule", "z_rule"]


def test_conflicting_duplicate_rule_id_is_rejected() -> None:
    class ConflictingRule(DummyRule):
        metadata = metadata("dummy")

    registry = RuleRegistry()
    registry.register(DummyRule())
    with pytest.raises(RuleContractError, match="dummy"):
        registry.register(ConflictingRule())


def test_registration_revalidates_constructed_metadata() -> None:
    class InvalidRule(DummyRule):
        metadata = DetectionRuleMetadata.model_construct(
            **metadata().model_dump(exclude={"required_fields"}),
            required_fields=("field_that_does_not_exist",),
        )

    with pytest.raises(RuleContractError, match="field_that_does_not_exist"):
        RuleRegistry().register(InvalidRule())


def test_legacy_attribute_mismatch_is_rejected() -> None:
    class MismatchedRule(DummyRule):
        rule_id = "different_rule"

    with pytest.raises(RuleContractError, match="conflicts with metadata"):
        RuleRegistry().register(MismatchedRule())
