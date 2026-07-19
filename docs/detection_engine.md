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

## Adding a Detection Rule

Extend `BaseDetectionRule` and declare one immutable `DetectionRuleMetadata` instance. Metadata is the single source of truth for the legacy `rule_id`, `version`, `name`, `family`, and `priority` attributes. Identifiers use lowercase snake case, versions use numeric `major.minor.patch` format, canonical field names must exist on `CanonicalLogEvent`, and threshold references must name real `DetectionSettings` fields.

```python
from agent.detection.contracts import DetectionRuleMetadata
from agent.detection.detectors.base import BaseDetectionRule

class ExampleRule(BaseDetectionRule):
    metadata = DetectionRuleMetadata(
        rule_id="example_rule",
        version="1.0.0",
        name="Example Rule",
        family="example_family",
        priority=500,
        supported_event_types=(),
        required_fields=("src_ip",),
        signal_type="example_signal",
        default_severity="low",
        mitre_techniques=(),
        window_setting=None,
        minimum_events_setting=None,
    )

    def evaluate(self, events, context):
        return []
```

`required_fields` is a rule-level relevance filter: `None` and blank strings are missing, while numeric zero and `False` remain valid. An empty tuple adds no field requirement. `supported_event_types` restricts only explicitly declared values; an empty tuple accepts all globally eligible events, including events without `event_type`. It never infers a type from parser or message content.

Registration validates the complete contract. Re-registering the same class, version, and metadata is an idempotent no-op; the same `rule_id` with another class, version, or incompatible metadata is rejected. Rules are always evaluated by ascending `(priority, rule_id)`.

Every emitted signal must match the producing rule's identity, version, name, family, and `signal_type`. A rule that intentionally preserves multiple legacy signal identities may declare an immutable `signal_variants` tuple; each emitted `(rule_id, rule_name, signal_type)` must then exactly match one declared variant, while version and family still match the parent rule metadata. Signals must also have a non-empty primary entity and event set, reference only events supplied to that rule, and keep every evidence event inside the signal event set. Invalid signals are excluded with a bounded warning, while other rules continue. Generate signal IDs from stable inputs with `generate_signal_id`; never use current time or unordered runtime data.

Rule tests should include positive, negative, and threshold-boundary cases, deterministic repeated evaluation, evidence ownership, and duplicate-signal checks. Detection and ingestion rules must remain completely local and make zero provider or agent calls.

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
