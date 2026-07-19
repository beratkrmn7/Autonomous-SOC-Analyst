from typing import List, Dict
import logging

from agent.detection.detectors.base import BaseDetectionRule
from agent.detection.contracts import DetectionRuleMetadata, RuleContractError

logger = logging.getLogger(__name__)

class RuleRegistry:
    def __init__(self):
        self._rules: Dict[str, BaseDetectionRule] = {}

    def register(self, rule: BaseDetectionRule) -> None:
        if not isinstance(getattr(rule, "metadata", None), DetectionRuleMetadata):
            raise RuleContractError("rule must declare valid DetectionRuleMetadata")
        try:
            metadata = DetectionRuleMetadata.model_validate(rule.metadata.model_dump())
        except ValueError as ex:
            raise RuleContractError(f"invalid metadata for rule: {ex}") from ex
        legacy_values = {
            "rule_id": rule.rule_id,
            "version": rule.version,
            "name": rule.name,
            "family": rule.family,
            "priority": rule.priority,
        }
        for field_name, value in legacy_values.items():
            if value != getattr(metadata, field_name):
                raise RuleContractError(
                    f"rule attribute '{field_name}' conflicts with metadata for "
                    f"rule_id '{metadata.rule_id}'"
                )
        existing = self._rules.get(rule.rule_id)
        if existing is not None:
            if type(existing) is type(rule) and existing.metadata == rule.metadata:
                return
            raise RuleContractError(f"conflicting registration for rule_id '{rule.rule_id}'")
        self._rules[rule.rule_id] = rule
        logger.info(f"Registered rule: {rule.rule_id} v{rule.version} ({rule.name})")

    def unregister(self, rule_id: str) -> None:
        if rule_id in self._rules:
            del self._rules[rule_id]
            logger.info(f"Unregistered rule: {rule_id}")

    def get_all_rules(self) -> List[BaseDetectionRule]:
        # Sort by priority ascending (lower number = higher priority)
        return sorted(self._rules.values(), key=lambda r: (r.priority, r.rule_id))

    def get_rule(self, rule_id: str) -> BaseDetectionRule:
        if rule_id not in self._rules:
            raise KeyError(f"Rule with ID {rule_id} not found.")
        return self._rules[rule_id]

    def get_rule_metadata(self, rule_id: str) -> DetectionRuleMetadata:
        return self.get_rule(rule_id).metadata

    def list_rule_metadata(self) -> tuple[DetectionRuleMetadata, ...]:
        return tuple(rule.metadata for rule in self.get_all_rules())

# Global default registry
default_registry = RuleRegistry()
