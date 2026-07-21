"""Deterministic, provider-free triage routing for detected incidents.

Classifies each incident into one of four routes before any provider call,
so only high-value incidents reach the LangGraph/LLM triage flow:

- ``individual_triage``: an allowed-connection exposure or a blocked/scan/SPI
  sequence that culminated in an allowed connection. Uses the existing
  LangGraph/LLM flow unchanged.
- ``deterministic_report``: fully blocked reconnaissance with no allowed
  connection. Gets a short deterministic report; no provider call.
- ``digest``: low-severity, fully blocked scanning-family incidents (chiefly
  ``repeated_blocked_scanner``) are batched into one deterministic digest
  instead of individual reports; no provider call.
- ``store_only``: incidents verified as likely firewall SPI state
  desynchronization are retained with no report and no provider call.

All routing decisions are pure functions of already-detected, deterministic
evidence. Nothing here calls a provider or mutates canonical events.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Optional

from agent.detection.config import DetectionSettings
from agent.detection.context_matching import events_are_bidirectionally_related
from agent.detection.detectors.scan_helpers import (
    classify_service,
    event_tcp_flag_tokens,
    is_allowed,
    is_blocked,
    is_spi_anomaly_event,
)
from agent.detection.models import IncidentBundle
from agent.schema import CanonicalLogEvent


TriageRoute = Literal[
    "individual_triage", "deterministic_report", "digest", "store_only"
]

# Rule IDs whose contract requires an observed allowed connection: the
# inbound exposure/policy pack plus the blocked/scan/SPI-then-allowed
# sequence rules. Any incident carrying one of these signals is high value
# and always goes through individual LLM triage.
HIGH_VALUE_RULE_IDS = frozenset(
    {
        "inbound_sensitive_service_allowed",
        "critical_management_service_exposed",
        "dnat_sensitive_service_exposure",
        "wan_to_lan_sensitive_service_allowed",
        "wan_to_dmz_administrative_service_allowed",
        "blocked_then_allowed_same_service",
        "multi_source_allowed_sensitive_service",
        "scan_followed_by_allowed_connection",
        "spi_followed_by_allowed_connection",
    }
)

_RESPONSE_ORIENTED_FLAGS = frozenset({"ACK", "RST", "FIN"})

# The only triage_verdict value deterministic_report may persist. It is a
# valid, honest verdict label - never the internal route name
# "deterministic_report" itself.
DETERMINISTIC_TRIAGE_VERDICT = "suspicious_activity"


@dataclass(frozen=True)
class RoutingDecision:
    route: TriageRoute
    reason: str
    triage_origin: Literal["llm", "deterministic", "none"]
    llm_invoked: bool


def _response_oriented_without_syn(event: CanonicalLogEvent) -> bool:
    tokens = event_tcp_flag_tokens(event)
    return "SYN" not in tokens and bool(tokens & _RESPONSE_ORIENTED_FLAGS)


def is_likely_spi_state_desync(
    incident: IncidentBundle,
    incident_events: Sequence[CanonicalLogEvent],
    related_context_events: Sequence[CanonicalLogEvent],
    *,
    fallback_raw_match: bool,
) -> bool:
    """Verified-only classification for likely firewall SPI state desync.

    Requires an explicitly SPI-classified, response-oriented (no SYN) event
    plus a related allowed flow found through bidirectional/NAT-aware
    context matching. A source service port such as 443 is intentionally
    never consulted here - it may support an analyst's read but must never
    be sufficient alone, so it plays no role in this deterministic check.
    """
    if incident.incident_family != "network_anomaly":
        return False

    spi_response_events = [
        event
        for event in incident_events
        if is_spi_anomaly_event(event, fallback_raw_match=fallback_raw_match)
        and _response_oriented_without_syn(event)
    ]
    if not spi_response_events:
        return False

    return any(
        is_allowed(context_event)
        and any(
            events_are_bidirectionally_related(spi_event, context_event)
            for spi_event in spi_response_events
        )
        for context_event in related_context_events
    )


def decide_route(
    incident: IncidentBundle,
    incident_events: Sequence[CanonicalLogEvent],
    related_context_events: Sequence[CanonicalLogEvent],
    signal_rule_ids: frozenset[str],
    settings: DetectionSettings,
) -> RoutingDecision:
    high_value_rules = signal_rule_ids & HIGH_VALUE_RULE_IDS
    if high_value_rules:
        return RoutingDecision(
            route="individual_triage",
            reason=f"high_value_rule:{sorted(high_value_rules)[0]}",
            triage_origin="llm",
            llm_invoked=True,
        )

    if any(is_allowed(event) for event in incident_events):
        return RoutingDecision(
            route="individual_triage",
            reason="allowed_connection_observed",
            triage_origin="llm",
            llm_invoked=True,
        )

    if is_likely_spi_state_desync(
        incident,
        incident_events,
        related_context_events,
        fallback_raw_match=settings.SPI_ANOMALY_FALLBACK_RAW_MATCH,
    ):
        return RoutingDecision(
            route="store_only",
            reason="verified_spi_state_desynchronization",
            triage_origin="none",
            llm_invoked=False,
        )

    # A deterministic report or digest may only claim "everything was
    # blocked" when that is literally true of every incident event. Empty
    # evidence and mixed/unrecognized-action incidents are not safe to
    # summarize deterministically as blocked reconnaissance, so they fall
    # back to individual LLM triage rather than a fabricated "all blocked"
    # narrative.
    fully_blocked = bool(incident_events) and all(
        is_blocked(event) for event in incident_events
    )
    if not fully_blocked:
        return RoutingDecision(
            route="individual_triage",
            reason="not_fully_blocked_conservative",
            triage_origin="llm",
            llm_invoked=True,
        )

    if incident.incident_family == "network_scanning" and incident.severity == "low":
        return RoutingDecision(
            route="digest",
            reason="low_severity_fully_blocked_scanner",
            triage_origin="deterministic",
            llm_invoked=False,
        )

    return RoutingDecision(
        route="deterministic_report",
        reason="fully_blocked_reconnaissance",
        triage_origin="deterministic",
        llm_invoked=False,
    )


def generate_deterministic_report(
    incident: IncidentBundle,
    incident_events: Sequence[CanonicalLogEvent],
) -> str:
    """Short, honest, provider-free report for straightforward blocked recon."""
    event_count = len(incident_events)
    blocked_count = sum(1 for event in incident_events if is_blocked(event))
    target_ips = sorted({event.dst_ip for event in incident_events if event.dst_ip})
    ports = sorted(
        {event.dst_port for event in incident_events if event.dst_port is not None}
    )
    services = sorted(
        {
            service
            for port in ports
            if (service := classify_service(port)) is not None
        }
    )

    target_summary = ", ".join(target_ips[:10]) or "unknown"
    if len(target_ips) > 10:
        target_summary += ", ..."
    port_summary = ", ".join(str(port) for port in ports[:15]) or "none observed"
    if len(ports) > 15:
        port_summary += ", ..."
    service_summary = ", ".join(services) or "none classified"

    lines = [
        f"# Deterministic Report: {incident.title}",
        "",
        f"- **Observed activity:** {incident.incident_type} ({incident.incident_family})",
        f"- **Source:** {incident.primary_entity}",
        f"- **Events:** {event_count} total, {blocked_count} blocked",
        f"- **Distinct targets:** {len(target_ips)} ({target_summary})",
        f"- **Ports:** {port_summary}",
        f"- **Services:** {service_summary}",
        f"- **Window:** {incident.first_seen.isoformat()} to {incident.last_seen.isoformat()}",
        "",
    ]
    if event_count > 0 and blocked_count == event_count:
        lines.append(
            f"All {event_count} observed event(s) were blocked by the firewall. "
            "No successful connection, authentication, exploitation, or "
            "compromise was proven by this deterministic analysis."
        )
    else:
        lines.append(
            f"{blocked_count} of {event_count} observed event(s) were blocked by "
            "the firewall. No successful connection, authentication, "
            "exploitation, or compromise was proven by this deterministic "
            "analysis."
        )
    return "\n".join(lines)


@dataclass(frozen=True)
class DigestMember:
    incident_id: str
    primary_entity: Optional[str]
    events: Sequence[CanonicalLogEvent]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]


def build_digest(incident_type: str, members: Sequence[DigestMember]) -> dict:
    """One deterministic batch digest for a group of low-value incidents."""
    sources = sorted({member.primary_entity for member in members if member.primary_entity})
    all_events = [event for member in members for event in member.events]
    total_blocked_events = sum(1 for event in all_events if is_blocked(event))
    distinct_targets = sorted({event.dst_ip for event in all_events if event.dst_ip})

    port_counts: dict[int, int] = {}
    for event in all_events:
        if event.dst_port is not None:
            port_counts[event.dst_port] = port_counts.get(event.dst_port, 0) + 1
    common_ports = [
        port
        for port, _count in sorted(
            port_counts.items(), key=lambda item: (-item[1], item[0])
        )[:10]
    ]

    first_seen_values = [member.first_seen for member in members if member.first_seen]
    last_seen_values = [member.last_seen for member in members if member.last_seen]
    bounded_sources = sources[:20]

    return {
        "incident_type": incident_type,
        "incident_count": len(members),
        "incident_ids": sorted(member.incident_id for member in members),
        "source_count": len(sources),
        "sources": bounded_sources,
        "sources_truncated": len(sources) > len(bounded_sources),
        "total_blocked_events": total_blocked_events,
        "distinct_target_count": len(distinct_targets),
        "common_ports": common_ports,
        "time_range_start": min(first_seen_values).isoformat() if first_seen_values else None,
        "time_range_end": max(last_seen_values).isoformat() if last_seen_values else None,
        "statement": (
            "No allowed connection was observed for any incident in this "
            "digest; all activity was blocked reconnaissance."
        ),
    }
