# Phase 3 Detection and Correlation Engine

The Phase 3 Detection and Correlation engine replaces heuristic scripts with a deterministic, testable, robust, and extensible rules engine focused on generating low-false-positive `IncidentBundle` objects.

## Architecture

Data flows through the following stages:

1. **Role Classification**: `EventFilter` classifies parsed events as candidate, context, or probable noise for reporting and context selection. This role does not define detection eligibility.
2. **Eligibility Check**: All successfully parsed and semantically valid events are available to deterministic rules. `DetectionEngine` rejects invalid statuses, missing timestamps, and other ineligible inputs before rule execution.
3. **Rule Evaluation**: A `RuleRegistry` loads all implementations of `BaseDetectionRule`. Each rule owns its relevance decisions, evaluates the eligible log sequence using `sliding_window_scan`, and generates `DetectionSignal` objects.
4. **Signal Deduplication**: Redundant, identical signals across multiple windows are pruned.
5. **Signal Suppression**: Allows IP whitelisting to silently discard acceptable traffic (e.g. Vuln Scanners).
6. **Correlation & Incident Merging**: `DetectionSignal` objects related to the same primary entity or matching keys are merged into `IncidentBundle` objects. Role-classified context remains a bounded, same-source, nearby-time subset and cannot duplicate incident event IDs.

## Rule Development

To create a new rule, extend `BaseDetectionRule` from `agent.detection.detectors.base`.

```python
from agent.detection.detectors.base import BaseDetectionRule, DetectionContext

class CustomRule(BaseDetectionRule):
    rule_id = "custom_rule"
    version = "1.0.0"
    name = "Custom Rule"
    family = "custom"
    priority = 100

    def evaluate(self, events, context: DetectionContext):
        # Implementation...
        return signals
```

The system includes pre-built rules for:
- Horizontal Scan
- Vertical Scan
- Remote Service Probe (SSH/RDP)
- Network Flood (DoS)
- SPI Anomaly Burst

## Determinism

Incidents and signals use a deterministic hashing mechanism (`generate_signal_id`, `generate_incident_id`) based on entities, temporal bounds, and correlated events. This ensures that processing the exact same batch of logs repeatedly produces exactly the same incidents.

## APIs

The Detection Engine runs automatically before the LLM triage agent is invoked, passing deterministically discovered `signals` and `candidate_evidence` to the LangGraph state.

A standalone `POST /detect/file` endpoint and `--detect-file` CLI option are available for testing detection logic without invoking LLM tokens.
