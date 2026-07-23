"""Deterministic presentation grouping for the SOC brief.

Nothing here creates, mutates or replaces a canonical incident. Canonical
incidents stay queryable and keep their identities in the API; this module
only decides how existing rows are *shown* together, and every grouping keeps
the incident IDs it was built from.

``BriefActionItem`` is the single frozen type the brief renders. One item may
stand for one canonical incident, one source/service exposure group, or one
fixed-source-port presentation cluster, so the renderer never has to branch on
which of those it received - and group objects are never mixed into fields
typed as ``IncidentBundle``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict

from agent.detection.detectors.exposure_helpers import (
    effective_destination_ip,
    effective_destination_port,
    has_destination_translation,
    sensitive_service_for_port,
)
from agent.detection.detectors.scan_helpers import is_allowed, is_blocked
from agent.detection.fixed_source_port_cluster import FixedSourcePortCluster
from agent.detection.models import IncidentBundle
from agent.schema import CanonicalLogEvent
from agent.triage.disposition import (
    EVIDENCE_STRENGTH_RANK,
    EvidenceStrength,
    ExposureDisposition,
    classify_evidence_strength,
    derive_exposure_disposition,
    is_exposure_incident,
)


MAX_ITEM_SOURCES = 10
MAX_ITEM_DESTINATIONS = 10
MAX_ITEM_PORTS = 15
MAX_ITEM_EVENT_IDS = 20
MAX_ITEM_EVIDENCE_IDS = 5
MAX_ITEM_MEMBERS = 25

#: Two exposures of the same source and service are shown together when their
#: windows are this close. Wider gaps stay separate rows.
DEFAULT_GROUP_TIME_COMPATIBILITY_SECONDS = 300

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}

BriefItemKind = Literal["incident", "exposure_group", "scan_cluster"]


class ActionableExposureGroup(BaseModel):
    """Several canonical exposure incidents from one source and service."""

    model_config = ConfigDict(frozen=True)

    group_id: str
    member_incident_ids: tuple[str, ...]
    source_ips: tuple[str, ...]
    service: Optional[str]
    effective_destinations: tuple[str, ...]
    original_destinations: tuple[str, ...]
    ports: tuple[int, ...]
    event_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    event_count: int
    allowed_event_count: int
    blocked_event_count: int
    packet_count: int
    byte_count: int
    nat_observed: bool
    first_seen: datetime
    last_seen: datetime
    severity: str
    confidence: float
    verdict: str
    evidence_strength: EvidenceStrength


class BriefActionItem(BaseModel):
    """One row of the brief, whatever deterministic thing it stands for."""

    model_config = ConfigDict(frozen=True)

    item_id: str
    kind: BriefItemKind
    #: Always populated, so a reader can get back to canonical rows.
    member_incident_ids: tuple[str, ...]
    title: str
    incident_type: str
    incident_family: str
    service: Optional[str] = None
    evidence_strength: Optional[EvidenceStrength] = None
    source_ips: tuple[str, ...] = ()
    source_count: int = 0
    effective_destinations: tuple[str, ...] = ()
    original_destinations: tuple[str, ...] = ()
    destination_count: int = 0
    ports: tuple[int, ...] = ()
    event_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    event_count: int = 0
    allowed_event_count: int = 0
    blocked_event_count: int = 0
    packet_count: int = 0
    byte_count: int = 0
    nat_observed: bool = False
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    severity: str = "informational"
    confidence: float = 0.0
    verdict: str = "suspicious_activity"
    # ATT&CK technique and tactic are always separate values.
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    attack_context: str = ""
    #: Set only for fixed-source-port clusters, so a display title can name the
    #: pinned source port without re-deriving it from destination ports.
    fixed_source_port: Optional[int] = None

    @property
    def member_incident_count(self) -> int:
        return len(self.member_incident_ids)


def _incident_events(
    incident: IncidentBundle,
    event_lookup: Mapping[str, CanonicalLogEvent],
) -> list[CanonicalLogEvent]:
    return [
        event_lookup[event_id]
        for event_id in incident.event_ids
        if event_id in event_lookup
    ]


def _action_state(events: Sequence[CanonicalLogEvent]) -> str:
    if events and all(is_allowed(event) for event in events):
        return "allowed"
    if events and all(is_blocked(event) for event in events):
        return "blocked"
    return "mixed"


def _group_key(
    incident: IncidentBundle,
    events: Sequence[CanonicalLogEvent],
) -> Optional[tuple[str, str, str, bool]]:
    """The exact-source/service/action/NAT key two exposures must share."""
    sources = {event.src_ip for event in events if event.src_ip}
    if len(sources) != 1:
        # Grouping is by exact source IP only; never by network.
        return None
    services = {
        sensitive_service_for_port(effective_destination_port(event))
        for event in events
    }
    if len(services) != 1:
        return None
    service = next(iter(services))
    if service is None:
        return None
    action_state = _action_state(events)
    if action_state == "mixed":
        return None
    nat_observed = any(has_destination_translation(event) for event in events)
    return (next(iter(sources)), service, action_state, nat_observed)


def _windows_compatible(
    existing_first: datetime,
    existing_last: datetime,
    candidate: IncidentBundle,
    tolerance_seconds: int,
) -> bool:
    tolerance = timedelta(seconds=tolerance_seconds)
    return not (
        candidate.first_seen > existing_last + tolerance
        or candidate.last_seen < existing_first - tolerance
    )


def build_exposure_groups(
    incidents: Sequence[IncidentBundle],
    event_lookup: Mapping[str, CanonicalLogEvent],
    *,
    time_compatibility_seconds: int = DEFAULT_GROUP_TIME_COMPATIBILITY_SECONDS,
) -> tuple[ActionableExposureGroup, ...]:
    """Group compatible exposure incidents for presentation.

    Only ``firewall_exposure``/``firewall_policy`` incidents that share an
    exact source IP, a service classification, an action state, NAT semantics
    and a compatible time window are grouped. Everything else is left alone.
    """
    buckets: dict[tuple[str, str, str, bool], list[IncidentBundle]] = {}
    for incident in sorted(incidents, key=lambda item: item.incident_id):
        if not is_exposure_incident(incident):
            continue
        events = _incident_events(incident, event_lookup)
        if not events:
            continue
        key = _group_key(incident, events)
        if key is None:
            continue
        buckets.setdefault(key, []).append(incident)

    groups: list[ActionableExposureGroup] = []
    for key, members in sorted(buckets.items()):
        source_ip, service, action_state, nat_observed = key
        for burst, run in enumerate(
            _time_compatible_runs(members, time_compatibility_seconds)
        ):
            groups.append(
                _build_group(
                    source_ip,
                    service,
                    action_state,
                    nat_observed,
                    burst,
                    run,
                    event_lookup,
                )
            )
    return tuple(groups)


def _item_sort_key(item: BriefActionItem) -> tuple:
    return (
        -_SEVERITY_RANK.get(item.severity, 0),
        -item.confidence,
        item.first_seen or datetime.min,
        item.item_id,
    )


def item_from_incident(
    incident: IncidentBundle,
    event_lookup: Mapping[str, CanonicalLogEvent],
    disposition: Optional[ExposureDisposition] = None,
) -> BriefActionItem:
    """One canonical incident rendered as a brief row."""
    events = _incident_events(incident, event_lookup)
    if disposition is None and is_exposure_incident(incident):
        disposition = derive_exposure_disposition(incident, events)

    sources = tuple(sorted({event.src_ip for event in events if event.src_ip}))
    destinations = tuple(
        sorted(
            {
                address
                for event in events
                if (address := effective_destination_ip(event))
            }
        )
    )
    strength = (
        disposition.evidence_strength
        if disposition is not None
        else classify_evidence_strength(events)
    )
    return BriefActionItem(
        item_id=f"inc:{incident.incident_id}",
        kind="incident",
        member_incident_ids=(incident.incident_id,),
        title=incident.title,
        incident_type=incident.incident_type,
        incident_family=incident.incident_family,
        service=disposition.service if disposition is not None else None,
        evidence_strength=strength,
        source_ips=sources[:MAX_ITEM_SOURCES],
        source_count=len(sources),
        effective_destinations=destinations[:MAX_ITEM_DESTINATIONS],
        original_destinations=tuple(
            sorted({event.dst_ip for event in events if event.dst_ip})
        )[:MAX_ITEM_DESTINATIONS],
        destination_count=len(destinations),
        ports=tuple(
            sorted(
                {
                    port
                    for event in events
                    if (port := effective_destination_port(event)) is not None
                }
            )
        )[:MAX_ITEM_PORTS],
        event_ids=tuple(sorted(event.event_id for event in events))[
            :MAX_ITEM_EVENT_IDS
        ],
        evidence_ids=(
            disposition.representative_evidence_ids
            if disposition is not None
            else tuple(sorted({item.event_id for item in incident.evidence}))[
                :MAX_ITEM_EVIDENCE_IDS
            ]
        ),
        event_count=len(events),
        allowed_event_count=sum(1 for event in events if is_allowed(event)),
        blocked_event_count=sum(1 for event in events if is_blocked(event)),
        packet_count=sum(event.packets or 0 for event in events),
        byte_count=sum(event.bytes or 0 for event in events),
        nat_observed=any(has_destination_translation(event) for event in events),
        first_seen=incident.first_seen,
        last_seen=incident.last_seen,
        severity=(
            disposition.severity if disposition is not None else incident.severity
        ),
        confidence=incident.confidence,
        verdict=(
            disposition.verdict
            if disposition is not None
            else "suspicious_activity"
        ),
    )


def item_from_exposure_group(group: ActionableExposureGroup) -> BriefActionItem:
    service = group.service or "service"
    return BriefActionItem(
        item_id=group.group_id,
        kind="exposure_group",
        member_incident_ids=group.member_incident_ids,
        title=(
            f"Externally allowed {service} exposure from {group.source_ips[0]}"
            if group.source_ips
            else f"Externally allowed {service} exposure"
        ),
        incident_type="inbound_sensitive_service_allowed",
        incident_family="firewall_exposure",
        service=group.service,
        evidence_strength=group.evidence_strength,
        source_ips=group.source_ips,
        source_count=len(group.source_ips),
        effective_destinations=group.effective_destinations,
        original_destinations=group.original_destinations,
        destination_count=len(group.effective_destinations),
        ports=group.ports,
        event_ids=group.event_ids,
        evidence_ids=group.evidence_ids,
        event_count=group.event_count,
        allowed_event_count=group.allowed_event_count,
        blocked_event_count=group.blocked_event_count,
        packet_count=group.packet_count,
        byte_count=group.byte_count,
        nat_observed=group.nat_observed,
        first_seen=group.first_seen,
        last_seen=group.last_seen,
        severity=group.severity,
        confidence=group.confidence,
        verdict=group.verdict,
    )


def item_from_scan_cluster(cluster: FixedSourcePortCluster) -> BriefActionItem:
    return BriefActionItem(
        item_id=cluster.cluster_id,
        kind="scan_cluster",
        # A presentation cluster owns no canonical incident identity.
        member_incident_ids=(),
        title=(
            f"Fixed source port {cluster.fixed_source_port} service enumeration "
            f"from {cluster.source_count} source(s)"
        ),
        incident_type="fixed_source_port_scan",
        incident_family="network_scanning",
        service=None,
        evidence_strength=EvidenceStrength.SYN_ONLY,
        source_ips=cluster.contributing_source_ips[:MAX_ITEM_SOURCES],
        source_count=cluster.source_count,
        destination_count=cluster.distinct_destination_ip_count,
        ports=cluster.destination_ports[:MAX_ITEM_PORTS],
        event_ids=cluster.event_ids[:MAX_ITEM_EVENT_IDS],
        event_count=cluster.event_count,
        allowed_event_count=cluster.allowed_event_count,
        blocked_event_count=cluster.blocked_event_count,
        first_seen=cluster.first_seen,
        last_seen=cluster.last_seen,
        severity=cluster.severity,
        confidence=0.8,
        verdict="suspicious_activity",
        mitre_technique=cluster.mitre_technique,
        mitre_tactic=cluster.mitre_tactic,
        fixed_source_port=cluster.fixed_source_port,
    )


def _time_compatible_runs(
    incidents: Sequence[IncidentBundle], tolerance_seconds: int
) -> list[list[IncidentBundle]]:
    ordered = sorted(incidents, key=lambda item: (item.first_seen, item.incident_id))
    runs: list[list[IncidentBundle]] = []
    current: list[IncidentBundle] = []
    for incident in ordered:
        if not current:
            current = [incident]
            continue
        first = min(member.first_seen for member in current)
        last = max(member.last_seen for member in current)
        if _windows_compatible(first, last, incident, tolerance_seconds):
            current.append(incident)
        else:
            runs.append(current)
            current = [incident]
    if current:
        runs.append(current)
    return runs


class BriefSelection(BaseModel):
    """The deterministic rows the brief will show, before any enrichment."""

    model_config = ConfigDict(frozen=True)

    act_now: tuple[BriefActionItem, ...] = ()
    investigate: tuple[BriefActionItem, ...] = ()
    exposure_groups: tuple[ActionableExposureGroup, ...] = ()
    scan_clusters: tuple[FixedSourcePortCluster, ...] = ()

    @property
    def all_items(self) -> tuple[BriefActionItem, ...]:
        return self.act_now + self.investigate


def build_brief_selection(
    incidents: Sequence[IncidentBundle],
    event_lookup: Mapping[str, CanonicalLogEvent],
    *,
    eligible_incident_ids: Optional[frozenset[str]] = None,
    scan_clusters: Sequence[FixedSourcePortCluster] = (),
    max_items_per_section: int = 5,
    time_compatibility_seconds: int = DEFAULT_GROUP_TIME_COMPATIBILITY_SECONDS,
) -> BriefSelection:
    """Select and order the deterministic ACT NOW / INVESTIGATE rows.

    ``eligible_incident_ids`` is the set routing marked batch-enrichment
    eligible. Incidents routed to a deterministic report, a digest or
    store-only are shown in their own sections and never become action rows,
    which is what keeps those routes at zero provider calls.

    Grouped exposures are represented once by their group; every other
    eligible incident is represented by itself.

    Every ``needs_review`` row is placed in INVESTIGATE regardless of severity,
    so the section can never claim zero items while one is hidden.
    """
    if eligible_incident_ids is not None:
        incidents = [
            incident
            for incident in incidents
            if incident.incident_id in eligible_incident_ids
        ]

    groups = build_exposure_groups(
        incidents,
        event_lookup,
        time_compatibility_seconds=time_compatibility_seconds,
    )
    grouped_incident_ids = {
        incident_id for group in groups for incident_id in group.member_incident_ids
    }

    items: list[BriefActionItem] = [item_from_exposure_group(group) for group in groups]
    for incident in incidents:
        if incident.incident_id in grouped_incident_ids:
            continue
        items.append(item_from_incident(incident, event_lookup))
    items.extend(item_from_scan_cluster(cluster) for cluster in scan_clusters)

    ordered = sorted(items, key=_item_sort_key)
    act_now = [
        item
        for item in ordered
        if item.severity in {"critical", "high"} and item.verdict != "needs_review"
    ]
    # Everything else eligible lands in INVESTIGATE, including every
    # needs_review row. A row that routing judged worth showing is never
    # dropped for being below a severity threshold.
    act_now_ids = {item.item_id for item in act_now}
    investigate = [item for item in ordered if item.item_id not in act_now_ids]
    return BriefSelection(
        act_now=tuple(act_now[:max_items_per_section]),
        investigate=tuple(investigate[:max_items_per_section]),
        exposure_groups=groups,
        scan_clusters=tuple(scan_clusters),
    )


def _build_group(
    source_ip: str,
    service: str,
    action_state: str,
    nat_observed: bool,
    burst: int,
    members: Sequence[IncidentBundle],
    event_lookup: Mapping[str, CanonicalLogEvent],
) -> ActionableExposureGroup:
    events: list[CanonicalLogEvent] = []
    seen: set[str] = set()
    for incident in members:
        for event in _incident_events(incident, event_lookup):
            if event.event_id not in seen:
                seen.add(event.event_id)
                events.append(event)

    dispositions = [
        derive_exposure_disposition(incident, _incident_events(incident, event_lookup))
        for incident in members
    ]
    strength = max(
        (item.evidence_strength for item in dispositions),
        key=lambda value: EVIDENCE_STRENGTH_RANK[value],
        default=classify_evidence_strength(events),
    )
    severity = max(
        (item.severity for item in dispositions),
        key=lambda value: _SEVERITY_RANK.get(value, 0),
        default="informational",
    )
    verdict = (
        "needs_review"
        if any(item.verdict == "needs_review" for item in dispositions)
        else "suspicious_activity"
    )

    evidence_ids: list[str] = []
    for item in dispositions:
        for evidence_id in item.representative_evidence_ids:
            if evidence_id not in evidence_ids:
                evidence_ids.append(evidence_id)

    suffix = "" if burst == 0 else f":{burst}"
    return ActionableExposureGroup(
        group_id=f"exp:{source_ip}:{service}:{action_state}{suffix}",
        member_incident_ids=tuple(
            sorted(incident.incident_id for incident in members)
        )[:MAX_ITEM_MEMBERS],
        source_ips=(source_ip,),
        service=service,
        effective_destinations=tuple(
            sorted(
                {
                    address
                    for event in events
                    if (address := effective_destination_ip(event))
                }
            )
        )[:MAX_ITEM_DESTINATIONS],
        original_destinations=tuple(
            sorted({event.dst_ip for event in events if event.dst_ip})
        )[:MAX_ITEM_DESTINATIONS],
        ports=tuple(
            sorted(
                {
                    port
                    for event in events
                    if (port := effective_destination_port(event)) is not None
                }
            )
        )[:MAX_ITEM_PORTS],
        event_ids=tuple(sorted(event.event_id for event in events))[
            :MAX_ITEM_EVENT_IDS
        ],
        evidence_ids=tuple(evidence_ids[:MAX_ITEM_EVIDENCE_IDS]),
        event_count=len(events),
        allowed_event_count=sum(1 for event in events if is_allowed(event)),
        blocked_event_count=sum(1 for event in events if is_blocked(event)),
        packet_count=sum(event.packets or 0 for event in events),
        byte_count=sum(event.bytes or 0 for event in events),
        nat_observed=nat_observed,
        first_seen=min(incident.first_seen for incident in members),
        last_seen=max(incident.last_seen for incident in members),
        severity=severity,
        confidence=max(incident.confidence for incident in members),
        verdict=verdict,
        evidence_strength=strength,
    )
