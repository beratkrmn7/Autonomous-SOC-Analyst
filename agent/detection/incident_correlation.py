"""Cross-rule incident correlation (Phase 6E.2 - Incident Correlation V2).

Detection rules run independently, so the same underlying activity (for
example a horizontal scan that turns into a repeated-blocked-scanner pattern
and a service-specific probe) can produce several signals from different
rules over the same events. This module clusters those cross-rule signals
into one deterministic incident per cluster, using shared event evidence -
never source IP, port, service name, or timing alone - as the correlation
gate, and a fixed precedence order to choose which signal defines the
incident's identity.

Everything here is a pure function of already-detected, deterministic
signals and events. Nothing calls a provider or mutates its inputs.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime

from agent.detection.config import DetectionSettings
from agent.detection.context_matching import events_are_bidirectionally_related
from agent.detection.models import (
    DetectionEvidence,
    DetectionSignal,
    IncidentBundle,
    generate_incident_id,
)
from agent.detection.scoring import calculate_incident_confidence, calculate_incident_severity
from agent.schema import CanonicalLogEvent


MAX_INCIDENT_EVIDENCE = 10

# Level 1: a sequence that progressed from blocks/scanning to an allowed
# connection. Highest priority - this is the strongest evidence available.
_LEVEL_1_SEQUENCE_TO_ALLOWED: tuple[str, ...] = (
    "scan_followed_by_allowed_connection",
    "blocked_then_allowed_same_service",
    "spi_followed_by_allowed_connection",
)

# Level 2: critical exposure and firewall policy, explicit business order.
_LEVEL_2_EXPOSURE_AND_POLICY: tuple[str, ...] = (
    "critical_management_service_exposed",
    "dnat_sensitive_service_exposure",
    "wan_to_lan_sensitive_service_allowed",
    "multi_source_allowed_sensitive_service",
    "wan_to_dmz_administrative_service_allowed",
    "inbound_sensitive_service_allowed",
)

# Level 3: service-specific probes, keyed by the emitted signal_type (variant
# rules like the remote/database/kubernetes/legacy-cleartext probes emit a
# per-service signal_type, not their parent registered rule_id).
_LEVEL_3_SERVICE_SPECIFIC_PROBES: tuple[str, ...] = (
    "rdp_probe",
    "ssh_probe",
    "smb_probe",
    "vnc_probe",
    "winrm_probe",
    "mssql_probe",
    "oracle_probe",
    "mysql_probe",
    "postgresql_probe",
    "redis_probe",
    "elasticsearch_probe",
    "mongodb_probe",
    "docker_daemon_probe",
    "kubernetes_api_probe",
    "kubelet_probe",
    "telnet_probe",
    "ftp_probe",
    "web_admin_panel_probe",
    # Parent registered rule_ids are never the emitted signal_type in
    # practice, but are listed defensively so a future direct signal still
    # lands at service-probe precedence rather than the generic fallback.
    "database_service_probe",
    "kubernetes_service_probe",
    "legacy_cleartext_service_probe",
)

# Level 4: advanced scanning patterns.
_LEVEL_4_ADVANCED_SCANNING: tuple[str, ...] = (
    "low_and_slow_horizontal_scan",
    "low_and_slow_vertical_scan",
    "internal_lateral_scan",
    "subnet_sweep",
    "distributed_scan",
    "multi_service_sweep",
)

# Level 5: generic scanning.
_LEVEL_5_GENERIC_SCANNING: tuple[str, ...] = (
    "horizontal_scan",
    "vertical_scan",
)

# Level 6: repeated generic blocked scanning.
_LEVEL_6_REPEATED_BLOCKED_SCANNING: tuple[str, ...] = ("repeated_blocked_scanner",)

_PRECEDENCE_LEVELS: tuple[tuple[str, ...], ...] = (
    _LEVEL_1_SEQUENCE_TO_ALLOWED,
    _LEVEL_2_EXPOSURE_AND_POLICY,
    _LEVEL_3_SERVICE_SPECIFIC_PROBES,
    _LEVEL_4_ADVANCED_SCANNING,
    _LEVEL_5_GENERIC_SCANNING,
    _LEVEL_6_REPEATED_BLOCKED_SCANNING,
)
# Level 7 (generic anomaly/volume/unlisted signals) is the deterministic
# fallback for any signal_type not explicitly classified above.
_FALLBACK_LEVEL = len(_PRECEDENCE_LEVELS) + 1

_SIGNAL_TYPE_PRECEDENCE: dict[str, tuple[int, int]] = {
    signal_type: (level_index, within_level_index)
    for level_index, level_types in enumerate(_PRECEDENCE_LEVELS, start=1)
    for within_level_index, signal_type in enumerate(level_types)
}

_SEVERITY_RANK: dict[str, int] = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _precedence_level(signal_type: str) -> tuple[int, int]:
    return _SIGNAL_TYPE_PRECEDENCE.get(signal_type, (_FALLBACK_LEVEL, 0))


def signal_precedence_key(
    signal: DetectionSignal,
) -> tuple[int, int, int, float, datetime, str, str, str]:
    """Deterministic ascending sort key: the smallest key is the best anchor.

    Ranks by explicit precedence level (and explicit within-level order for
    levels 1-6), then breaks ties using severity rank descending, confidence
    descending, first_seen ascending, rule_id ascending, signal_type
    ascending, and signal_id ascending - never registry, dict, or set order.
    """
    level, within_level_order = _precedence_level(signal.signal_type)
    return (
        level,
        within_level_order,
        -_SEVERITY_RANK.get(signal.severity, 0),
        -signal.confidence,
        signal.first_seen,
        signal.rule_id,
        signal.signal_type,
        signal.signal_id,
    )


def event_overlap_ratio(left: DetectionSignal, right: DetectionSignal) -> float:
    """Shared-event overlap ratio, normalized by the smaller event set.

    0 when either signal has no events. This is the only signal-to-signal
    relatedness measure used for correlation eligibility - never IP, port,
    service name, timing, or family alone.
    """
    left_ids = set(left.event_ids)
    right_ids = set(right.event_ids)
    if not left_ids or not right_ids:
        return 0.0
    intersection_count = len(left_ids & right_ids)
    return intersection_count / min(len(left_ids), len(right_ids))


def time_windows_are_compatible(
    left: DetectionSignal,
    right: DetectionSignal,
    window_seconds: int,
) -> bool:
    """True when the two signals' [first_seen, last_seen] windows overlap,
    or the gap between them is within `window_seconds`.

    Continuous gap comparison, never a quantized time bucket - two signals a
    few seconds apart must still be compatible even when their timestamps
    fall on opposite sides of an old bucket boundary.
    """
    if left.first_seen <= right.last_seen and right.first_seen <= left.last_seen:
        return True
    gap_seconds = max(
        (right.first_seen - left.last_seen).total_seconds(),
        (left.first_seen - right.last_seen).total_seconds(),
    )
    return gap_seconds <= window_seconds


# Exposure/policy rules intentionally use different entity viewpoints for
# the same underlying firewall event (for example the external source for
# critical_management_service_exposed vs. the effective internal
# destination for dnat_sensitive_service_exposure and
# wan_to_lan_sensitive_service_allowed). Exact primary_entity equality stays
# the default correlation rule; this is the only, narrow exception to it.
_CROSS_PRIMARY_ELIGIBLE_FAMILIES = frozenset({"firewall_exposure", "firewall_policy"})


def _has_shared_event_evidence(left: DetectionSignal, right: DetectionSignal) -> bool:
    return bool(set(left.event_ids) & set(right.event_ids))


def _entity_scope(signal: DetectionSignal) -> set[str]:
    scope = set(signal.target_entities)
    if signal.primary_entity:
        scope.add(signal.primary_entity)
    return scope


def _entity_scopes_are_compatible(left: DetectionSignal, right: DetectionSignal) -> bool:
    return bool(_entity_scope(left) & _entity_scope(right))


def _cross_primary_exposure_correlation_allowed(
    anchor: DetectionSignal,
    candidate: DetectionSignal,
    *,
    window_seconds: int,
) -> bool:
    """Narrow exception for exposure/policy signals with different primary
    entities but the same underlying event evidence.

    Requires: both signals in firewall_exposure/firewall_policy, both
    event-ID sets non-empty and *exactly* equal (never a partial/subset
    overlap - that would risk merging a broad multi-source signal into an
    unrelated source-specific incident), compatible entity scopes
    (primary_entity plus target_entities share at least one entity), and a
    compatible time window.
    """
    if anchor.signal_family not in _CROSS_PRIMARY_ELIGIBLE_FAMILIES:
        return False
    if candidate.signal_family not in _CROSS_PRIMARY_ELIGIBLE_FAMILIES:
        return False

    anchor_event_ids = set(anchor.event_ids)
    candidate_event_ids = set(candidate.event_ids)
    if not anchor_event_ids or not candidate_event_ids:
        return False
    if anchor_event_ids != candidate_event_ids:
        return False

    if not _entity_scopes_are_compatible(anchor, candidate):
        return False

    return time_windows_are_compatible(anchor, candidate, window_seconds)


def _signals_may_correlate(
    anchor: DetectionSignal,
    candidate: DetectionSignal,
    *,
    window_seconds: int,
    overlap_threshold: float,
) -> bool:
    if anchor.primary_entity and candidate.primary_entity and (
        anchor.primary_entity == candidate.primary_entity
    ):
        if not time_windows_are_compatible(anchor, candidate, window_seconds):
            return False
        # Require genuine shared-event evidence before comparing against the
        # configured ratio, so an overlap_threshold of 0.0 still means "any
        # positive shared-event overlap", not "no overlap required at all" -
        # empty and disjoint event sets never correlate regardless of
        # threshold.
        if not _has_shared_event_evidence(anchor, candidate):
            return False
        return event_overlap_ratio(anchor, candidate) >= overlap_threshold

    return _cross_primary_exposure_correlation_allowed(
        anchor, candidate, window_seconds=window_seconds
    )


def _best_anchor(
    candidate: DetectionSignal,
    eligible_anchors: Sequence[DetectionSignal],
) -> DetectionSignal:
    def sort_key(anchor: DetectionSignal) -> tuple:
        return (
            -event_overlap_ratio(anchor, candidate),
            signal_precedence_key(anchor),
            anchor.first_seen,
            anchor.signal_id,
        )

    return min(eligible_anchors, key=sort_key)


def cluster_signals(
    signals: Sequence[DetectionSignal],
    *,
    window_seconds: int,
    overlap_threshold: float,
) -> list[list[DetectionSignal]]:
    """Deterministic anchor-based clustering of cross-rule signals.

    Signals are processed in precedence order. The highest-precedence
    not-yet-absorbed signal becomes a cluster anchor; every later signal is
    tested only against existing anchors (never against a non-anchor
    cluster member), so a transitive bridge (A-B strongly overlap, B-C
    strongly overlap, A-C do not) cannot pull C into A's cluster through B.
    A signal eligible for more than one anchor joins the anchor with the
    highest overlap ratio, then highest anchor precedence, then earliest
    anchor first_seen, then anchor signal_id, in that order.

    Returns one list per cluster, anchor first, remaining members in
    precedence order. Identical inputs in any order produce identical
    clusters, because every ordering decision here is a total order (the
    final tie-break is always the unique signal_id).
    """
    ordered = sorted(signals, key=signal_precedence_key)

    anchors: list[DetectionSignal] = []
    members: dict[str, list[DetectionSignal]] = {}

    for candidate in ordered:
        eligible_anchors = [
            anchor
            for anchor in anchors
            if _signals_may_correlate(
                anchor,
                candidate,
                window_seconds=window_seconds,
                overlap_threshold=overlap_threshold,
            )
        ]
        if not eligible_anchors:
            anchors.append(candidate)
            members[candidate.signal_id] = [candidate]
            continue

        chosen_anchor = _best_anchor(candidate, eligible_anchors)
        members[chosen_anchor.signal_id].append(candidate)

    return [members[anchor.signal_id] for anchor in anchors]


def _select_context_event_ids(
    incident_event_ids: Sequence[str],
    event_lookup: dict[str, CanonicalLogEvent],
    sorted_context_events: Sequence[CanonicalLogEvent],
    first_seen: datetime,
    last_seen: datetime,
    settings: DetectionSettings,
) -> list[str]:
    incident_events = [
        event_lookup[eid] for eid in incident_event_ids if eid in event_lookup
    ]
    if not (sorted_context_events and incident_events):
        return []

    incident_event_id_set = set(incident_event_ids)
    start_window = first_seen.timestamp() - settings.INCIDENT_MERGE_WINDOW_SECONDS
    end_window = last_seen.timestamp() + settings.INCIDENT_MERGE_WINDOW_SECONDS

    context_ids: list[str] = []
    seen_context_ids: set[str] = set()
    for ce in sorted_context_events:
        if len(context_ids) >= settings.MAX_CONTEXT_EVENTS_PER_INCIDENT:
            break
        if ce.event_id in incident_event_id_set or ce.event_id in seen_context_ids:
            continue
        if not ce.timestamp:
            continue
        ts = ce.timestamp.timestamp()
        if not (start_window <= ts <= end_window):
            continue
        if any(
            events_are_bidirectionally_related(reference, ce)
            for reference in incident_events
        ):
            context_ids.append(ce.event_id)
            seen_context_ids.add(ce.event_id)
    return context_ids


def build_correlated_incident(
    cluster: Sequence[DetectionSignal],
    event_lookup: dict[str, CanonicalLogEvent],
    sorted_context_events: Sequence[CanonicalLogEvent],
    settings: DetectionSettings,
) -> IncidentBundle:
    """Build one IncidentBundle from a signal cluster.

    `cluster[0]` must be the anchor (as returned by `cluster_signals`); the
    remaining members must already be in precedence order. The anchor alone
    defines incident_type, incident_family, title, primary_entity, and the
    incident identity, so adding or removing a lower-priority supporting
    signal never changes the incident ID while the same anchor remains.
    """
    anchor = cluster[0]

    signal_ids = sorted({signal.signal_id for signal in cluster})
    absorbed_signal_ids = sorted(
        {signal.signal_id for signal in cluster if signal.signal_id != anchor.signal_id}
    )

    all_event_ids: set[str] = set()
    target_entities: set[str] = set()
    mitre_techniques: set[str] = set()
    for signal in cluster:
        all_event_ids.update(signal.event_ids)
        target_entities.update(signal.target_entities)
        mitre_techniques.update(signal.mitre_techniques)
    event_ids = sorted(all_event_ids)

    first_seen = min(signal.first_seen for signal in cluster)
    last_seen = max(signal.last_seen for signal in cluster)

    evidence = _collect_evidence(cluster, all_event_ids)

    severity = calculate_incident_severity(list(cluster), anchor.primary_entity, settings)
    confidence = calculate_incident_confidence(list(cluster))

    bucket = int(anchor.first_seen.timestamp()) // settings.INCIDENT_MERGE_WINDOW_SECONDS
    merge_key = f"v2:{anchor.rule_id}:{anchor.signal_id}:{bucket}"
    incident_id = generate_incident_id(
        anchor.signal_family,
        anchor.signal_type,
        anchor.primary_entity,
        merge_key,
        anchor.first_seen,
    )

    context_event_ids = _select_context_event_ids(
        event_ids, event_lookup, sorted_context_events, first_seen, last_seen, settings
    )

    metrics: dict[str, int | float | str | bool] = {
        "total_events": len(event_ids),
        "distinct_targets": len(target_entities),
        "correlated_signal_count": len(cluster),
        "absorbed_signal_count": len(absorbed_signal_ids),
        "primary_signal_id": anchor.signal_id,
        "correlation_version": "2",
    }

    return IncidentBundle(
        incident_id=incident_id,
        incident_type=anchor.signal_type,
        incident_family=anchor.signal_family,
        title=f"Detected {anchor.rule_name} from {anchor.primary_entity}",
        severity=severity,
        confidence=confidence,
        first_seen=first_seen,
        last_seen=last_seen,
        primary_entity=anchor.primary_entity,
        target_entities=sorted(target_entities),
        signal_ids=signal_ids,
        event_ids=event_ids,
        context_event_ids=context_event_ids,
        evidence=evidence,
        metrics=metrics,
        mitre_techniques=sorted(mitre_techniques),
        merge_key=merge_key,
        absorbed_signal_ids=absorbed_signal_ids,
    )


def _collect_evidence(
    cluster: Sequence[DetectionSignal],
    incident_event_ids: Iterable[str],
) -> list[DetectionEvidence]:
    incident_event_id_set = set(incident_event_ids)
    evidence: list[DetectionEvidence] = []
    seen_event_ids: set[str] = set()
    # cluster[0] is the anchor; cluster[1:] is already in precedence order,
    # so evidence naturally comes out anchor-first, then supporting signals
    # in precedence order, with event_id as the final tie-breaker below.
    for signal in cluster:
        for item in sorted(signal.evidence, key=lambda e: e.event_id):
            if len(evidence) >= MAX_INCIDENT_EVIDENCE:
                return evidence
            if item.event_id in seen_event_ids:
                continue
            if item.event_id not in incident_event_id_set:
                continue
            evidence.append(item)
            seen_event_ids.add(item.event_id)
    return evidence


def _incident_windows_overlap_or_touch(
    left: IncidentBundle, right: IncidentBundle
) -> bool:
    return left.first_seen <= right.last_seen and right.first_seen <= left.last_seen


def _incident_event_sets_overlap(
    left: IncidentBundle, right: IncidentBundle
) -> bool:
    left_ids = set(left.event_ids)
    right_ids = set(right.event_ids)
    if not left_ids or not right_ids:
        return False
    if left_ids <= right_ids or right_ids <= left_ids:
        return True
    return len(left_ids & right_ids) / len(left_ids | right_ids) >= 0.5


def _overlapping_incidents_are_mergeable(
    left: IncidentBundle, right: IncidentBundle
) -> bool:
    return bool(
        left.incident_type == right.incident_type
        and left.primary_entity == right.primary_entity
        and _incident_windows_overlap_or_touch(left, right)
        and _incident_event_sets_overlap(left, right)
    )


def _incident_keeper_key(
    incident: IncidentBundle,
) -> tuple[int, datetime, str]:
    return (-len(incident.event_ids), incident.first_seen, incident.incident_id)


def _merge_incident_pair(
    keeper: IncidentBundle,
    absorbed: IncidentBundle,
    signal_lookup: dict[str, DetectionSignal],
    settings: DetectionSettings,
) -> IncidentBundle:
    event_ids = sorted(set(keeper.event_ids) | set(absorbed.event_ids))
    event_id_set = set(event_ids)
    signal_ids = sorted(set(keeper.signal_ids) | set(absorbed.signal_ids))
    signals = [signal_lookup[signal_id] for signal_id in signal_ids]

    primary_signal_id = keeper.metrics.get("primary_signal_id")
    absorbed_signal_ids = sorted(
        (
            set(keeper.absorbed_signal_ids)
            | set(absorbed.signal_ids)
            | set(absorbed.absorbed_signal_ids)
        )
        - ({primary_signal_id} if isinstance(primary_signal_id, str) else set())
    )

    evidence: list[DetectionEvidence] = []
    seen_evidence: set[tuple[str, str, str, str]] = set()
    for item in [*keeper.evidence, *absorbed.evidence]:
        key = (item.event_id, item.source, item.reason, item.quote)
        if item.event_id not in event_id_set or key in seen_evidence:
            continue
        evidence.append(item)
        seen_evidence.add(key)
        if len(evidence) >= MAX_INCIDENT_EVIDENCE:
            break

    target_entities = sorted(
        set(keeper.target_entities) | set(absorbed.target_entities)
    )
    metrics = dict(keeper.metrics)
    metrics.update(
        {
            "total_events": len(event_ids),
            "distinct_targets": len(target_entities),
            "correlated_signal_count": len(signal_ids),
            "absorbed_signal_count": len(absorbed_signal_ids),
            "overlapping_incident_merge_count": int(
                metrics.get("overlapping_incident_merge_count", 0)
            )
            + 1
            + int(absorbed.metrics.get("overlapping_incident_merge_count", 0)),
        }
    )

    return keeper.model_copy(
        update={
            "severity": calculate_incident_severity(
                signals, keeper.primary_entity, settings
            ),
            "confidence": calculate_incident_confidence(signals),
            "first_seen": min(keeper.first_seen, absorbed.first_seen),
            "last_seen": max(keeper.last_seen, absorbed.last_seen),
            "target_entities": target_entities,
            "signal_ids": signal_ids,
            "event_ids": event_ids,
            "context_event_ids": sorted(
                (set(keeper.context_event_ids) | set(absorbed.context_event_ids))
                - event_id_set
            )[: settings.MAX_CONTEXT_EVENTS_PER_INCIDENT],
            "evidence": evidence,
            "metrics": metrics,
            "mitre_techniques": sorted(
                set(keeper.mitre_techniques) | set(absorbed.mitre_techniques)
            ),
            "absorbed_signal_ids": absorbed_signal_ids,
        }
    )


def merge_overlapping_incidents(
    incidents: Sequence[IncidentBundle],
    signals: Sequence[DetectionSignal],
    settings: DetectionSettings,
) -> tuple[list[IncidentBundle], int]:
    """Merge nested/high-overlap duplicate incidents deterministically.

    This is a presentation-independent, provider-free post-pass over already
    detected signals and incidents. The largest event set is always the
    canonical keeper; ties use first_seen and then incident_id.
    """
    signal_lookup = {signal.signal_id: signal for signal in signals}
    merged: list[IncidentBundle] = []
    absorbed_count = 0

    for candidate in sorted(incidents, key=_incident_keeper_key):
        eligible = [
            incident
            for incident in merged
            if _overlapping_incidents_are_mergeable(incident, candidate)
        ]
        if not eligible:
            merged.append(candidate)
            continue

        keeper = min(eligible, key=_incident_keeper_key)
        merged[merged.index(keeper)] = _merge_incident_pair(
            keeper, candidate, signal_lookup, settings
        )
        absorbed_count += 1

    merged.sort(key=lambda incident: (incident.first_seen, incident.incident_id))
    return merged, absorbed_count


def build_correlated_incidents(
    signals: Sequence[DetectionSignal],
    context_events: Sequence[CanonicalLogEvent],
    candidate_events: Sequence[CanonicalLogEvent],
    settings: DetectionSettings,
) -> tuple[list[IncidentBundle], int]:
    """Cluster cross-rule signals and build one incident per cluster.

    Returns the incidents (sorted deterministically) and the merge_count
    (the number of supporting signals absorbed into a correlated incident,
    i.e. sum(len(cluster) - 1) across every cluster).
    """
    if not signals:
        return [], 0

    event_lookup = {
        event.event_id: event for event in candidate_events if event.event_id
    }
    sorted_context_events = sorted(
        (event for event in context_events if event.event_id),
        key=lambda event: (
            event.timestamp.isoformat() if event.timestamp else "",
            event.event_id,
        ),
    )

    clusters = cluster_signals(
        signals,
        window_seconds=settings.INCIDENT_MERGE_WINDOW_SECONDS,
        overlap_threshold=settings.INCIDENT_EVENT_OVERLAP_THRESHOLD,
    )
    merge_count = sum(len(cluster) - 1 for cluster in clusters)

    incidents = [
        build_correlated_incident(cluster, event_lookup, sorted_context_events, settings)
        for cluster in clusters
    ]
    incidents, overlapping_merge_count = merge_overlapping_incidents(
        incidents, signals, settings
    )
    return incidents, merge_count + overlapping_merge_count
