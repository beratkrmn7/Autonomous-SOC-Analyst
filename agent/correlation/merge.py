"""Phase 6E.4A: pure cross-job incident merge mechanics.

`merge_incident_bundles` is a pure function of its arguments: no database
access, no provider calls, no wall-clock reads. It reuses the existing
Phase 6E.2 precedence function and scoring helpers rather than inventing a
new formula, so a later, more specific signal can still promote a
persistent incident's identity exactly the way batch-local correlation
already promotes identity within one file.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence

from agent.detection.config import DetectionSettings
from agent.detection.incident_correlation import (
    MAX_INCIDENT_EVIDENCE,
    incident_title_source,
    signal_precedence_key,
)
from agent.detection.models import DetectionEvidence, DetectionSignal, IncidentBundle
from agent.detection.scoring import (
    IncidentSeverityFacts,
    calculate_incident_confidence,
    calculate_incident_severity,
    combine_incident_severity_facts,
)


_SEVERITY_RANK: dict[str, int] = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class IncidentMergeOutcome:
    incident: IncidentBundle
    primary_signal_id: str
    identity_promoted: bool
    scoring_recalculated: bool
    material_changes: tuple[str, ...]


def _valid_sorted_unique(
    evidence: Sequence[DetectionEvidence], incident_event_ids: set[str]
) -> list[DetectionEvidence]:
    seen: set[str] = set()
    result: list[DetectionEvidence] = []
    for item in sorted(evidence, key=lambda e: e.event_id):
        if item.event_id not in incident_event_ids or item.event_id in seen:
            continue
        result.append(item)
        seen.add(item.event_id)
    return result


def _merge_evidence(
    canonical_evidence: Sequence[DetectionEvidence],
    incoming_evidence: Sequence[DetectionEvidence],
    incident_event_ids: set[str],
) -> list[DetectionEvidence]:
    """Deterministic, duplicate-free, bounded evidence that never lets one
    side starve the other.

    A global event-ID sort can fill every MAX_INCIDENT_EVIDENCE slot with
    historical (canonical) evidence and drop the incoming job entirely when
    its event IDs happen to sort later. Instead: reserve one slot for the
    earliest canonical item (when canonical evidence exists) and one slot
    for the earliest incoming item (when incoming evidence exists), then
    fill any remaining slots deterministically from the full sorted,
    deduplicated pool.
    """
    canonical_valid = _valid_sorted_unique(canonical_evidence, incident_event_ids)
    incoming_valid = _valid_sorted_unique(incoming_evidence, incident_event_ids)

    selected: list[DetectionEvidence] = []
    selected_ids: set[str] = set()

    if canonical_valid and len(selected) < MAX_INCIDENT_EVIDENCE:
        selected.append(canonical_valid[0])
        selected_ids.add(canonical_valid[0].event_id)
    if (
        incoming_valid
        and incoming_valid[0].event_id not in selected_ids
        and len(selected) < MAX_INCIDENT_EVIDENCE
    ):
        selected.append(incoming_valid[0])
        selected_ids.add(incoming_valid[0].event_id)

    remaining_pool = sorted(
        {item.event_id: item for item in (*canonical_valid, *incoming_valid)}.values(),
        key=lambda e: e.event_id,
    )
    for item in remaining_pool:
        if len(selected) >= MAX_INCIDENT_EVIDENCE:
            break
        if item.event_id in selected_ids:
            continue
        selected.append(item)
        selected_ids.add(item.event_id)

    return sorted(selected, key=lambda e: e.event_id)[:MAX_INCIDENT_EVIDENCE]


def _select_anchor(
    canonical: IncidentBundle,
    incoming: IncidentBundle,
    available_signals: Optional[Sequence[DetectionSignal]],
) -> tuple[Optional[DetectionSignal], bool]:
    """Best-precedence anchor signal, or (None, False) when the available
    signal rows do not fully cover both bundles' signal_ids - in that case
    identity promotion and rescoring must both be skipped rather than
    computed from a partial, misleading cluster."""
    required_ids = set(canonical.signal_ids) | set(incoming.signal_ids)
    if not required_ids or not available_signals:
        return None, False
    by_id = {signal.signal_id: signal for signal in available_signals}
    if not required_ids.issubset(by_id.keys()):
        return None, False
    cluster = [by_id[sid] for sid in required_ids]
    anchor = min(cluster, key=signal_precedence_key)
    return anchor, True


def merge_incident_bundles(
    *,
    canonical: IncidentBundle,
    incoming: IncidentBundle,
    available_signals: Optional[Sequence[DetectionSignal]],
    settings: DetectionSettings,
    max_context_events: int,
) -> IncidentMergeOutcome:
    """Merge `incoming` into `canonical`, preserving canonical's incident_id.

    `available_signals` should be every DetectionSignal currently attached
    to either bundle (canonical's persisted signals plus incoming's newly
    detected signals). When it does not fully cover both bundles'
    signal_ids, this function fails conservatively: it still merges the
    mechanical fields (ids, timestamps, entities, MITRE techniques,
    evidence) but preserves canonical's existing incident_type/family/
    title/primary_entity and severity/confidence rather than promoting
    identity or recalculating a score from an incomplete signal set.
    """
    signal_ids = sorted(set(canonical.signal_ids) | set(incoming.signal_ids))
    event_ids = sorted(set(canonical.event_ids) | set(incoming.event_ids))
    event_id_set = set(event_ids)
    # An event promoted to incident evidence must never remain a context
    # event: subtract the merged event_ids before bounding context_event_ids.
    context_event_ids = sorted(
        (set(canonical.context_event_ids) | set(incoming.context_event_ids))
        - event_id_set
    )[:max_context_events]
    target_entities = sorted(set(canonical.target_entities) | set(incoming.target_entities))
    mitre_techniques = sorted(set(canonical.mitre_techniques) | set(incoming.mitre_techniques))
    first_seen = min(canonical.first_seen, incoming.first_seen)
    last_seen = max(canonical.last_seen, incoming.last_seen)
    evidence = _merge_evidence(canonical.evidence, incoming.evidence, event_id_set)

    anchor, scoring_recalculated = _select_anchor(canonical, incoming, available_signals)

    identity_promoted = False
    incident_type = canonical.incident_type
    incident_family = canonical.incident_family
    title = canonical.title
    primary_entity = canonical.primary_entity
    primary_signal_id = str(canonical.metrics.get("primary_signal_id") or "")
    if not primary_signal_id and canonical.signal_ids:
        primary_signal_id = canonical.signal_ids[0]

    severity = canonical.severity
    confidence = canonical.confidence

    severity_facts = None
    if anchor is not None:
        primary_signal_id = anchor.signal_id
        normalized_primary_entity = anchor.primary_entity
        if anchor.signal_family in {"firewall_exposure", "firewall_policy"}:
            source_bundle = (
                incoming if anchor.signal_id in incoming.signal_ids else canonical
            )
            normalized_primary_entity = source_bundle.primary_entity
        if (
            anchor.signal_type != canonical.incident_type
            or anchor.signal_family != canonical.incident_family
            or normalized_primary_entity != canonical.primary_entity
        ):
            identity_promoted = True
        incident_type = anchor.signal_type
        incident_family = anchor.signal_family
        title = f"Detected {anchor.rule_name} from {incident_title_source(anchor)}"
        primary_entity = normalized_primary_entity

        cluster = [
            signal
            for signal in (available_signals or ())
            if signal.signal_id in signal_ids
        ]
        canonical_facts = IncidentSeverityFacts.from_metrics(canonical.metrics)
        incoming_facts = IncidentSeverityFacts.from_metrics(incoming.metrics)
        if canonical_facts is not None and incoming_facts is not None:
            severity_facts = combine_incident_severity_facts(
                canonical_facts,
                incoming_facts,
                family=incident_family,
            )
        severity = calculate_incident_severity(
            cluster, primary_entity, settings, facts=severity_facts
        )
        confidence = calculate_incident_confidence(cluster)

    absorbed_signal_ids = sorted(sid for sid in signal_ids if sid != primary_signal_id)

    metrics: dict[str, int | float | str | bool] = dict(canonical.metrics)
    metrics["total_events"] = len(event_ids)
    metrics["correlated_signal_count"] = len(signal_ids)
    metrics["absorbed_signal_count"] = len(absorbed_signal_ids)
    metrics["primary_signal_id"] = primary_signal_id
    if anchor is not None and severity_facts is not None:
        metrics.update(severity_facts.as_metrics())

    merged = IncidentBundle(
        incident_id=canonical.incident_id,
        incident_type=incident_type,
        incident_family=incident_family,
        title=title,
        severity=severity,
        confidence=confidence,
        first_seen=first_seen,
        last_seen=last_seen,
        primary_entity=primary_entity,
        target_entities=target_entities,
        signal_ids=signal_ids,
        event_ids=event_ids,
        context_event_ids=context_event_ids,
        evidence=evidence,
        metrics=metrics,
        mitre_techniques=mitre_techniques,
        merge_key=canonical.merge_key,
        review_reason=canonical.review_reason,
        absorbed_signal_ids=absorbed_signal_ids,
    )

    material_changes: list[str] = []
    if len(event_ids) > len(canonical.event_ids):
        material_changes.append("events_added")
    if len(signal_ids) > len(canonical.signal_ids):
        material_changes.append("signals_added")
    if len(target_entities) > len(canonical.target_entities):
        material_changes.append("targets_added")
    if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(canonical.severity, 0):
        material_changes.append("severity_increased")
    if abs(confidence - canonical.confidence) > 1e-9:
        material_changes.append("confidence_changed")
    if identity_promoted:
        material_changes.append("primary_identity_promoted")
    if first_seen < canonical.first_seen or last_seen > canonical.last_seen:
        material_changes.append("time_window_extended")

    return IncidentMergeOutcome(
        incident=merged,
        primary_signal_id=primary_signal_id,
        identity_promoted=identity_promoted,
        scoring_recalculated=scoring_recalculated,
        material_changes=tuple(material_changes),
    )
