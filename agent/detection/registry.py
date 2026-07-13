from typing import List, Dict
import logging

from agent.detection.detectors.base import BaseDetectionRule

logger = logging.getLogger(__name__)

class RuleRegistry:
    def __init__(self):
        self._rules: Dict[str, BaseDetectionRule] = {}

    def register(self, rule: BaseDetectionRule) -> None:
        if rule.rule_id in self._rules:
            return  # Already registered
        self._rules[rule.rule_id] = rule
        logger.info(f"Registered rule: {rule.rule_id} v{rule.version} ({rule.name})")

    def unregister(self, rule_id: str) -> None:
        if rule_id in self._rules:
            del self._rules[rule_id]
            logger.info(f"Unregistered rule: {rule_id}")

    def get_all_rules(self) -> List[BaseDetectionRule]:
        # Sort by priority ascending (lower number = higher priority)
        return sorted(self._rules.values(), key=lambda r: r.priority)

    def get_rule(self, rule_id: str) -> BaseDetectionRule:
        if rule_id not in self._rules:
            raise KeyError(f"Rule with ID {rule_id} not found.")
        return self._rules[rule_id]

# Global default registry
default_registry = RuleRegistry()
