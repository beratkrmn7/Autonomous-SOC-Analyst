from __future__ import annotations

from typing import Any

from agent.triage.models import TriageIncidentContext


NETWORK_SCAN_TYPES = {
    "horizontal_scan",
    "vertical_scan",
    "port_scan",
    "rdp_probe",
    "ssh_probe",
}
BLOCK_ACTIONS = {"block", "blocked", "deny", "drop"}


def _metric_int(value: Any, fallback: int) -> int:
    if isinstance(value, bool):
        return fallback
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def derive_network_incident_facts(
    context: TriageIncidentContext,
) -> dict[str, Any] | None:
    """Return trusted, deterministic facts for scan/probe incidents."""
    incident = context.incident
    if incident.incident_type not in NETWORK_SCAN_TYPES:
        return None

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
    protocols = sorted(
        {
            str(event.protocol).upper()
            for event in events
            if event.protocol
        }
    )
    blocked_count = sum(
        1 for event in events if str(event.action or "").lower() in BLOCK_ACTIONS
    )
    tcp_events = [
        event for event in events if str(event.protocol or "").upper() == "TCP"
    ]
    syn_count = sum(
        1 for event in tcp_events if str(event.tcp_flags or "").upper() == "SYN"
    )

    return {
        "incident_type": incident.incident_type,
        "primary_entity": incident.primary_entity,
        "event_count": event_count,
        "distinct_target_count": target_count,
        "destination_ports": ports,
        "protocols": protocols,
        "blocked_event_count": blocked_count,
        "all_attempts_blocked": bool(events) and blocked_count == len(events),
        "syn_event_count": syn_count,
        "syn_only": bool(tcp_events) and syn_count == len(tcp_events),
        "first_seen": incident.first_seen.isoformat(),
        "last_seen": incident.last_seen.isoformat(),
    }


def build_deterministic_network_summary(facts: dict[str, Any]) -> str:
    ports = ", ".join(str(port) for port in facts["destination_ports"]) or "unknown"
    protocols = ", ".join(facts["protocols"]) or "unknown"
    blocked_text = (
        "All incident-scope attempts were blocked"
        if facts["all_attempts_blocked"]
        else f"{facts['blocked_event_count']} incident-scope events were blocked"
    )
    syn_text = " and TCP traffic was SYN-only" if facts["syn_only"] else ""
    outcome = (
        "; these events do not establish a successful connection or compromise."
        if facts["all_attempts_blocked"]
        else "."
    )
    return (
        f"Observed {facts['incident_type']} activity from "
        f"{facts['primary_entity']} across {facts['event_count']} events targeting "
        f"{facts['distinct_target_count']} distinct destinations on {protocols} "
        f"port(s) {ports}. {blocked_text}{syn_text}{outcome}"
    )
