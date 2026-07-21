"""Deterministic, family-aware triage guardrails (Phase 6E.3).

Replaces the old incident-type allow list with structured, typed fact
profiles derived from the deterministic IncidentBundle, every attached
TriageSignalView (including Phase 6E.2 supporting signals), incident
events, and bounded context events. The provider may explain an incident;
these facts - never the provider - decide what can be claimed about it.

Key semantic boundary encoded here: a firewall allow/pass event only proves
that the firewall permitted traffic. It never by itself proves a successful
application session, authentication, exploitation, or compromise.
"""

from __future__ import annotations

from typing import Any, Literal, Union

from pydantic import BaseModel, Field

from agent.detection.context_matching import events_are_bidirectionally_related
from agent.detection.detectors.scan_helpers import (
    bounded_sorted_values,
    classify_service,
    is_allowed,
    is_blocked,
    is_private_unicast,
)
from agent.triage.models import TriageIncidentContext, TriageSignalView
from agent.schema import CanonicalLogEvent


MAX_FACT_LIST_ITEMS = 20

SCAN_PROBE_FAMILIES = frozenset({"network_scanning", "service_probing"})
EXPOSURE_POLICY_FAMILIES = frozenset({"firewall_exposure", "firewall_policy"})
SEQUENCE_SIGNAL_TYPES = frozenset(
    {
        "scan_followed_by_allowed_connection",
        "blocked_then_allowed_same_service",
        "spi_followed_by_allowed_connection",
    }
)

# A single small packet (typical SYN/ACK/RST) is well under this; anything
# larger, or a longer-lived flow, is treated as "meaningful" transport
# activity rather than a bare firewall decision on one packet.
_NON_TRIVIAL_BYTES_THRESHOLD = 200
_NON_TRIVIAL_DURATION_MS_THRESHOLD = 1000


def _bounded_sorted_ports(ports: set[int]) -> list[int]:
    return sorted(ports)[:MAX_FACT_LIST_ITEMS]


class IncidentClassification(BaseModel):
    """Which deterministic fact profile applies, and why."""

    is_scan_probe: bool = False
    is_exposure_policy: bool = False
    is_sequence: bool = False
    matched_signal_types: list[str] = Field(default_factory=list)

    @property
    def is_firewall_only(self) -> bool:
        """True when the incident is exposure/policy or an allowed-sequence -
        the only families this deterministic engine can prove are firewall-only
        telemetry with no application/authentication evidence source."""
        return self.is_exposure_policy or self.is_sequence


def classify_incident(
    context: TriageIncidentContext,
    signal_views: list[TriageSignalView] | None = None,
) -> IncidentClassification:
    signal_views = signal_views or []
    incident = context.incident

    families = {incident.incident_family} | {sv.signal_family for sv in signal_views}
    types = {incident.incident_type} | {sv.signal_type for sv in signal_views}

    matched = sorted(types & SEQUENCE_SIGNAL_TYPES)

    return IncidentClassification(
        is_scan_probe=bool(families & SCAN_PROBE_FAMILIES),
        is_exposure_policy=bool(families & EXPOSURE_POLICY_FAMILIES),
        is_sequence=bool(matched),
        matched_signal_types=matched,
    )


class ScanProbeFacts(BaseModel):
    kind: Literal["scan_probe"] = "scan_probe"
    incident_type: str
    primary_entity: str
    event_count: int
    distinct_target_count: int
    destination_ports: list[int]
    protocols: list[str]
    blocked_event_count: int
    all_attempts_blocked: bool
    syn_event_count: int
    syn_only: bool
    first_seen: str
    last_seen: str


class FirewallExposureFacts(BaseModel):
    kind: Literal["firewall_exposure"] = "firewall_exposure"
    incident_type: str
    # Renamed from `primary_entity`: exposure rules intentionally use
    # different entity viewpoints (for example DNAT/WAN-to-LAN rules set the
    # internal effective destination as IncidentBundle.primary_entity, not
    # the network source). Never labeled "Source" - see source_ips below.
    incident_primary_entity: str
    service: str | None = None
    total_event_count: int
    allowed_event_count: int
    blocked_event_count: int
    source_ips: list[str]
    external_source_ips: list[str]
    original_destination_ips: list[str]
    original_destination_ports: list[int]
    effective_destination_ips: list[str]
    effective_destination_ports: list[int]
    translated_destination_ips: list[str]
    translated_destination_ports: list[int]
    inbound_zones: list[str]
    outbound_zones: list[str]
    nat_event_count: int
    total_packets: int
    total_bytes: int
    max_duration_ms: int
    single_packet_allowed_event_count: int
    multi_packet_allowed_event_count: int
    bidirectional_related_flow_observed: bool
    policy_allow_observed: bool
    transport_activity_observed: bool
    # Firewall/network telemetry alone can never prove either of these -
    # they stay False unless a future evidence source (application,
    # authentication, endpoint/EDR) explicitly sets them.
    application_success_proven: bool = False
    compromise_proven: bool = False
    first_seen: str
    last_seen: str


class SequenceFacts(BaseModel):
    kind: Literal["sequence"] = "sequence"
    incident_type: str
    primary_entity: str
    sequence_signal_types: list[str]
    event_count: int
    blocked_event_count: int
    allowed_event_count: int
    application_success_proven: bool = False
    compromise_proven: bool = False
    first_seen: str
    last_seen: str


class GenericIncidentFacts(BaseModel):
    kind: Literal["generic"] = "generic"
    incident_type: str


IncidentFacts = Union[ScanProbeFacts, FirewallExposureFacts, SequenceFacts, GenericIncidentFacts]


def _metric_int(value: Any, fallback: int) -> int:
    if isinstance(value, bool):
        return fallback
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _sum_numeric(events: list[CanonicalLogEvent], attr: str) -> int:
    total = 0
    for event in events:
        value = getattr(event, attr, None)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            total += int(value)
    return total


def _max_numeric(events: list[CanonicalLogEvent], attr: str) -> int:
    values = [
        int(getattr(event, attr))
        for event in events
        if isinstance(getattr(event, attr, None), (int, float))
        and not isinstance(getattr(event, attr, None), bool)
    ]
    return max(values, default=0)


def _has_destination_translation(event: CanonicalLogEvent) -> bool:
    return bool(
        (event.translated_dst_ip and event.translated_dst_ip.strip())
        or event.translated_dst_port is not None
    )


def _is_nat_event(event: CanonicalLogEvent) -> bool:
    return bool(
        _has_destination_translation(event)
        or (event.translated_src_ip and event.translated_src_ip.strip())
        or event.translated_src_port is not None
        or (event.nat_type and event.nat_type.strip())
    )


def _derive_scan_probe_facts(context: TriageIncidentContext) -> ScanProbeFacts:
    incident = context.incident
    events = context.events
    metrics = incident.metrics
    event_count = _metric_int(
        metrics.get("total_events"),
        len(incident.event_ids) or len(events),
    )
    target_count = _metric_int(
        metrics.get("distinct_targets"),
        len(incident.target_entities),
    )
    ports = sorted({event.dst_port for event in events if event.dst_port is not None})
    protocols = sorted({str(event.protocol).upper() for event in events if event.protocol})
    blocked_count = sum(1 for event in events if is_blocked(event))
    tcp_events = [event for event in events if str(event.protocol or "").upper() == "TCP"]
    syn_count = sum(1 for event in tcp_events if str(event.tcp_flags or "").upper() == "SYN")

    return ScanProbeFacts(
        incident_type=incident.incident_type,
        primary_entity=incident.primary_entity,
        event_count=event_count,
        distinct_target_count=target_count,
        destination_ports=_bounded_sorted_ports(set(ports)),
        protocols=protocols[:MAX_FACT_LIST_ITEMS],
        blocked_event_count=blocked_count,
        all_attempts_blocked=bool(events) and blocked_count == len(events),
        syn_event_count=syn_count,
        syn_only=bool(tcp_events) and syn_count == len(tcp_events),
        first_seen=incident.first_seen.isoformat(),
        last_seen=incident.last_seen.isoformat(),
    )


def _bidirectional_related_flow_observed(
    events: list[CanonicalLogEvent],
    context_events: list[CanonicalLogEvent],
) -> bool:
    """Reuses the Phase 6E.1 bidirectional/NAT-aware relationship helper
    as-is: same protocol-compatibility, endpoint, and service-port rules."""
    return any(
        events_are_bidirectionally_related(incident_event, context_event)
        for incident_event in events
        for context_event in context_events
    )


def _effective_destination_ip(event: CanonicalLogEvent) -> str | None:
    return event.translated_dst_ip or event.dst_ip


def _effective_destination_port(event: CanonicalLogEvent) -> int | None:
    if event.translated_dst_port is not None:
        return event.translated_dst_port
    return event.dst_port


def _derive_exposure_facts(
    context: TriageIncidentContext,
    incident_type: str,
) -> FirewallExposureFacts:
    incident = context.incident
    events = context.events

    allowed_events = [event for event in events if is_allowed(event)]
    blocked_count = sum(1 for event in events if is_blocked(event))

    source_ips = {event.src_ip for event in events if event.src_ip}
    external_source_ips = {ip for ip in source_ips if not is_private_unicast(ip)}

    original_destination_ips = {event.dst_ip for event in events if event.dst_ip}
    original_destination_ports = {
        event.dst_port for event in events if event.dst_port is not None
    }
    effective_destination_ips = {
        ip
        for event in events
        if (ip := _effective_destination_ip(event)) is not None
    }
    effective_destination_ports = {
        port
        for event in events
        if (port := _effective_destination_port(event)) is not None
    }
    translated_destination_ips = {
        event.translated_dst_ip for event in events if event.translated_dst_ip
    }
    translated_destination_ports = {
        event.translated_dst_port
        for event in events
        if event.translated_dst_port is not None
    }
    inbound_zones = {event.inbound_zone for event in events if event.inbound_zone}
    outbound_zones = {event.outbound_zone for event in events if event.outbound_zone}
    nat_event_count = sum(1 for event in events if _is_nat_event(event))

    single_packet_allowed = sum(
        1 for event in allowed_events if event.packets == 1
    )
    multi_packet_allowed = sum(
        1 for event in allowed_events if event.packets is not None and event.packets > 1
    )

    total_bytes = _sum_numeric(events, "bytes")
    max_duration_ms = _max_numeric(events, "duration_ms")
    bidirectional_flow = _bidirectional_related_flow_observed(events, context.context_events)

    policy_allow_observed = bool(allowed_events)
    transport_activity_observed = bool(
        multi_packet_allowed > 0
        or total_bytes > _NON_TRIVIAL_BYTES_THRESHOLD
        or max_duration_ms > _NON_TRIVIAL_DURATION_MS_THRESHOLD
        or bidirectional_flow
    )

    service = None
    for port in sorted(effective_destination_ports) + sorted(original_destination_ports):
        service = classify_service(port)
        if service:
            break

    return FirewallExposureFacts(
        incident_type=incident_type,
        incident_primary_entity=incident.primary_entity,
        service=service,
        total_event_count=len(events),
        allowed_event_count=len(allowed_events),
        blocked_event_count=blocked_count,
        source_ips=bounded_sorted_values(source_ips, limit=MAX_FACT_LIST_ITEMS),
        external_source_ips=bounded_sorted_values(
            external_source_ips, limit=MAX_FACT_LIST_ITEMS
        ),
        original_destination_ips=bounded_sorted_values(
            original_destination_ips, limit=MAX_FACT_LIST_ITEMS
        ),
        original_destination_ports=_bounded_sorted_ports(original_destination_ports),
        effective_destination_ips=bounded_sorted_values(
            effective_destination_ips, limit=MAX_FACT_LIST_ITEMS
        ),
        effective_destination_ports=_bounded_sorted_ports(effective_destination_ports),
        translated_destination_ips=bounded_sorted_values(
            translated_destination_ips, limit=MAX_FACT_LIST_ITEMS
        ),
        translated_destination_ports=_bounded_sorted_ports(translated_destination_ports),
        inbound_zones=bounded_sorted_values(inbound_zones, limit=MAX_FACT_LIST_ITEMS),
        outbound_zones=bounded_sorted_values(outbound_zones, limit=MAX_FACT_LIST_ITEMS),
        nat_event_count=nat_event_count,
        total_packets=_sum_numeric(events, "packets"),
        total_bytes=total_bytes,
        max_duration_ms=max_duration_ms,
        single_packet_allowed_event_count=single_packet_allowed,
        multi_packet_allowed_event_count=multi_packet_allowed,
        bidirectional_related_flow_observed=bidirectional_flow,
        policy_allow_observed=policy_allow_observed,
        transport_activity_observed=transport_activity_observed,
        application_success_proven=False,
        compromise_proven=False,
        first_seen=incident.first_seen.isoformat(),
        last_seen=incident.last_seen.isoformat(),
    )


def _derive_sequence_facts(
    context: TriageIncidentContext,
    classification: IncidentClassification,
) -> SequenceFacts:
    incident = context.incident
    events = context.events
    return SequenceFacts(
        incident_type=incident.incident_type,
        primary_entity=incident.primary_entity,
        sequence_signal_types=classification.matched_signal_types,
        event_count=len(events),
        blocked_event_count=sum(1 for event in events if is_blocked(event)),
        allowed_event_count=sum(1 for event in events if is_allowed(event)),
        application_success_proven=False,
        compromise_proven=False,
        first_seen=incident.first_seen.isoformat(),
        last_seen=incident.last_seen.isoformat(),
    )


def derive_incident_facts(
    context: TriageIncidentContext,
    signal_views: list[TriageSignalView] | None = None,
) -> IncidentFacts:
    """Deterministic, typed fact profile for the incident.

    Precedence when more than one classification matches (Phase 6E.2 can
    attach signals from several families to one correlated incident):
    sequence > exposure/policy > scan/probe > generic. A sequence incident
    keeps its own narrative even when an exposure signal is also attached;
    an exposure signal absorbed under a non-exposure/scan anchor is still
    recognized via the attached signal_views, not only the anchor family.
    """
    classification = classify_incident(context, signal_views)
    if classification.is_sequence:
        return _derive_sequence_facts(context, classification)
    if classification.is_exposure_policy:
        return _derive_exposure_facts(context, context.incident.incident_type)
    if classification.is_scan_probe:
        return _derive_scan_probe_facts(context)
    return GenericIncidentFacts(incident_type=context.incident.incident_type)


def build_deterministic_summary(facts: IncidentFacts) -> str:
    """Concise deterministic summary. For scan/probe facts this preserves
    the original wording; exposure/policy and sequence facts get their own
    wording that never overstates what firewall-only telemetry proves."""
    if isinstance(facts, ScanProbeFacts):
        return _build_scan_probe_summary(facts)
    if isinstance(facts, FirewallExposureFacts):
        return _build_exposure_summary(facts)
    if isinstance(facts, SequenceFacts):
        return _build_sequence_summary(facts)
    return f"Deterministic incident of type {facts.incident_type}."


def _build_scan_probe_summary(facts: ScanProbeFacts) -> str:
    ports = ", ".join(str(port) for port in facts.destination_ports) or "unknown"
    protocols = ", ".join(facts.protocols) or "unknown"
    blocked_text = (
        "All incident-scope attempts were blocked"
        if facts.all_attempts_blocked
        else f"{facts.blocked_event_count} incident-scope events were blocked"
    )
    syn_text = " and TCP traffic was SYN-only" if facts.syn_only else ""
    outcome = (
        "; these events do not establish a successful connection or compromise."
        if facts.all_attempts_blocked
        else "."
    )
    return (
        f"Observed {facts.incident_type} activity from "
        f"{facts.primary_entity} across {facts.event_count} events targeting "
        f"{facts.distinct_target_count} distinct destinations on {protocols} "
        f"port(s) {ports}. {blocked_text}{syn_text}{outcome}"
    )


def _build_exposure_summary(facts: FirewallExposureFacts) -> str:
    service_text = f" to a {facts.service} service" if facts.service else " service"
    source_text = ", ".join(facts.source_ips) or facts.incident_primary_entity or "an unknown source"

    if not facts.policy_allow_observed:
        return (
            f"The firewall recorded {facts.total_event_count} event(s){service_text} "
            f"from {source_text}, with {facts.blocked_event_count} blocked and "
            "no allowed connection observed. This does not establish policy exposure, "
            "an application session, or compromise."
        )

    original_destination_text = ", ".join(facts.original_destination_ips) or "unknown"
    original_ports_text = (
        ", ".join(str(port) for port in facts.original_destination_ports) or "unknown"
    )
    base = (
        f"The firewall permitted inbound traffic{service_text} from {source_text} "
        f"to {original_destination_text} ({original_ports_text} port(s))"
    )
    if facts.effective_destination_ips and set(facts.effective_destination_ips) != set(
        facts.original_destination_ips
    ):
        effective_destination_text = ", ".join(facts.effective_destination_ips)
        effective_ports_text = (
            ", ".join(str(port) for port in facts.effective_destination_ports) or "unknown"
        )
        base += (
            f", translated to effective destination {effective_destination_text} "
            f"({effective_ports_text} port(s))"
        )
    base += ". The available record establishes policy exposure"

    if facts.transport_activity_observed:
        return (
            f"{base}, and the available telemetry contains multi-packet or "
            "bidirectional network activity. This confirms network traffic was "
            "observed, but it does not prove successful authentication, "
            "exploitation, or compromise."
        )
    return (
        f"{base} but does not prove an application session, successful "
        "authentication, or compromise."
    )


def _build_sequence_summary(facts: SequenceFacts) -> str:
    return (
        f"Repeated blocked attempts ({facts.blocked_event_count} event(s)) were "
        f"followed by an allowed firewall event ({facts.allowed_event_count} event(s)) "
        f"to the same service from {facts.primary_entity}. The allowed event warrants "
        "investigation, but the available firewall telemetry does not prove "
        "application-level success or compromise."
    )
