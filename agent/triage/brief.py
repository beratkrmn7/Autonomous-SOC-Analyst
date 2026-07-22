"""Rich, provider-free rendering for the bounded SOC triage brief."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agent.detection.detectors.exposure_helpers import (
    effective_destination_ip,
    effective_destination_port,
)
from agent.detection.detectors.scan_helpers import is_allowed
from agent.detection.models import IncidentBundle
from agent.detection.rollup import RollupResult
from agent.schema import CanonicalLogEvent
from agent.triage.provenance import format_event_provenance


MAX_BRIEF_EVIDENCE_IDS = 3
MAX_BRIEF_ASSETS = 10


def _format_timestamp(value: datetime) -> str:
    return value.isoformat(sep=" ", timespec="seconds")


def _format_duration(seconds: float) -> str:
    total = max(0, int(seconds))
    minutes, remainder = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {remainder:02d}s"
    return f"{minutes}m {remainder:02d}s"


def _source_timezone(
    event_lookup: Mapping[str, CanonicalLogEvent],
) -> timezone | None:
    offsets = sorted(
        {
            value
            for event in event_lookup.values()
            if isinstance(event.parser_metadata, dict)
            if isinstance(
                value := event.parser_metadata.get("source_timezone_offset"), str
            )
        }
    )
    if len(offsets) != 1:
        return None
    value = offsets[0]
    if len(value) != 6 or value[0] not in {"+", "-"} or value[3] != ":":
        return None
    try:
        hours = int(value[1:3])
        minutes = int(value[4:6])
    except ValueError:
        return None
    if hours > 23 or minutes > 59:
        return None
    direction = 1 if value[0] == "+" else -1
    return timezone(direction * timedelta(hours=hours, minutes=minutes))


def _in_source_timezone(value: datetime, source_timezone: timezone) -> datetime:
    # SQLite may hydrate an originally aware UTC value as a naive datetime.
    # Canonical timestamps are normalized to UTC before persistence, so UTC is
    # the only safe interpretation for a naive hydrated value here.
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(source_timezone)


def _incident_events(
    incident: IncidentBundle,
    event_lookup: Mapping[str, CanonicalLogEvent],
) -> list[CanonicalLogEvent]:
    return [
        event_lookup[event_id]
        for event_id in incident.event_ids
        if event_id in event_lookup
    ]


def _incident_evidence_ids(incident: IncidentBundle) -> str:
    ids = [item.event_id for item in incident.evidence]
    if not ids:
        ids = list(incident.event_ids)
    bounded = sorted(set(ids))[:MAX_BRIEF_EVIDENCE_IDS]
    return ", ".join(bounded) or "none"


def _incident_flow(
    incident: IncidentBundle,
    event_lookup: Mapping[str, CanonicalLogEvent],
) -> str:
    events = _incident_events(incident, event_lookup)
    sources = sorted({event.src_ip for event in events if event.src_ip})
    destinations = sorted(
        {
            destination
            for event in events
            if (destination := effective_destination_ip(event))
        }
    )
    ports = sorted(
        {
            port
            for event in events
            if (port := effective_destination_port(event)) is not None
        }
    )
    source_text = ", ".join(sources[:2]) or "unknown source"
    destination_text = ", ".join(destinations[:2]) or incident.primary_entity
    port_text = ",".join(str(port) for port in ports[:6]) or "unknown port"
    allowed = sum(1 for event in events if is_allowed(event))
    action_text = "ALLOWED" if allowed else "BLOCKED/MIXED"
    return f"{source_text} -> {destination_text}:{port_text} · {action_text}"


def _next_action(incident: IncidentBundle) -> str:
    if incident.incident_family in {"firewall_exposure", "firewall_policy"}:
        return "Confirm firewall intent; restrict external access; review service logs."
    if incident.incident_family == "network_intrusion_candidate":
        return "Validate the policy transition; review the destination service timeline."
    return "Review the bounded evidence and verify the affected source/target scope."


def _action_table(
    title: str,
    incidents: Sequence[IncidentBundle],
    event_lookup: Mapping[str, CanonicalLogEvent],
) -> Table:
    table = Table(title=title, expand=True, show_lines=True)
    table.add_column("Priority", no_wrap=True)
    table.add_column("Incident / observed flow", ratio=3)
    table.add_column("Events", no_wrap=True)
    table.add_column("Evidence / next", ratio=3)
    for incident in incidents:
        priority = "P1" if incident.severity == "critical" else (
            "P2" if incident.severity == "high" else "P3"
        )
        event_summary = format_event_provenance(
            len(incident.event_ids), incident.metrics
        )
        mitre = ", ".join(incident.mitre_techniques) or "none mapped"
        table.add_row(
            f"[{priority}]\n{incident.severity.upper()}\nconf {incident.confidence:.2f}",
            f"{incident.title}\n{_incident_flow(incident, event_lookup)}",
            event_summary,
            (
                f"Evidence: {_incident_evidence_ids(incident)}\n"
                f"ATT&CK: {mitre}\nNext: {_next_action(incident)}"
            ),
        )
    if not incidents:
        table.add_row("-", "No items in this section.", "0", "-")
    return table


def render_soc_brief(
    console: Console,
    *,
    rollup: RollupResult,
    event_lookup: Mapping[str, CanonicalLogEvent],
    source_name: str,
    job_id: str | None,
    provider_call_count: int,
    generated_at: datetime | None = None,
) -> None:
    """Render a concise deterministic brief without invoking any provider."""
    generated_at = generated_at or datetime.now().astimezone()
    timestamps = sorted(
        event.timestamp for event in event_lookup.values() if event.timestamp is not None
    )
    if timestamps:
        first_seen, last_seen = timestamps[0], timestamps[-1]
        source_timezone = _source_timezone(event_lookup)
        if source_timezone is not None:
            first_seen = _in_source_timezone(first_seen, source_timezone)
            last_seen = _in_source_timezone(last_seen, source_timezone)
        window = (
            f"{_format_timestamp(first_seen)} - {_format_timestamp(last_seen)} | "
            f"{_format_duration((last_seen - first_seen).total_seconds())}"
        )
    else:
        window = "unknown"

    header = (
        "SOC TRIAGE BRIEF\n"
        f"Source : {source_name}\n"
        f"Window : {window}\n"
        f"Run    : {job_id or 'not persisted'} | Generated: "
        f"{_format_timestamp(generated_at)}"
    )
    console.print(Panel(header, border_style="cyan"))

    funnel = rollup.funnel
    console.print(
        Text(
            "FUNNEL  "
            f"{funnel.get('total_events', 0):,} events -> "
            f"{funnel.get('blocked_events', 0):,} blocked -> "
            f"{funnel.get('policy_exposures', 0):,} policy exposures -> "
            f"{funnel.get('action_items', 0):,} action items",
            style="bold",
        )
    )
    summary = (
        f"{len(rollup.act_now)} high-priority item(s), "
        f"{len(rollup.investigate)} investigation item(s), "
        f"{len(rollup.recon_groups)} fully blocked reconnaissance group(s), and "
        f"{len(rollup.exposed_assets)} exposed asset/service row(s). "
        "Firewall pass proves policy exposure only; it does not prove authentication, "
        "exploitation, or compromise."
    )
    console.print(Panel(summary, title="ANALYST SUMMARY", border_style="yellow"))

    console.print(_action_table("§1 ACT NOW", rollup.act_now, event_lookup))
    console.print(_action_table("§2 INVESTIGATE", rollup.investigate, event_lookup))

    recon = Table(title="§3 BLOCKED — FYI", expand=True)
    recon.add_column("Source scope")
    recon.add_column("Family / service scope")
    recon.add_column("Sources", justify="right")
    recon.add_column("Targets", justify="right")
    recon.add_column("Ports")
    recon.add_column("Events", justify="right")
    for group in rollup.recon_groups:
        ports = ",".join(str(port) for port in group.ports[:8]) or "none"
        recon.add_row(
            group.source_cidr,
            f"{group.incident_family} / {group.service_scope}",
            str(group.source_count),
            str(group.distinct_target_count),
            ports,
            str(group.total_event_count),
        )
    if not rollup.recon_groups:
        recon.add_row("-", "No fully blocked recon groups", "0", "0", "-", "0")
    console.print(recon)

    suppressed = Table(title="§4 SUPPRESSED", expand=True)
    suppressed.add_column("Source")
    suppressed.add_column("Targets")
    suppressed.add_column("Reason")
    suppressed.add_column("Events", justify="right")
    for suppressed_entry in rollup.suppressed:
        suppressed.add_row(
            suppressed_entry.source,
            ", ".join(suppressed_entry.targets) or "unknown",
            suppressed_entry.reason,
            str(suppressed_entry.event_count),
        )
    if not rollup.suppressed:
        suppressed.add_row("-", "-", "No suppressed signals", "0")
    console.print(suppressed)

    assets = Table(title="§5 EXPOSED ASSET INVENTORY", expand=True)
    assets.add_column("Effective destination")
    assets.add_column("Service / ports")
    assets.add_column("Sources", justify="right")
    assets.add_column("NAT / public destination")
    for exposed_asset in rollup.exposed_assets[:MAX_BRIEF_ASSETS]:
        nat_text = "no NAT"
        if exposed_asset.nat_observed:
            public = (
                ", ".join(exposed_asset.public_destinations)
                or "public address unknown"
            )
            nat_text = (
                f"{public} -> "
                f"{exposed_asset.internal_address or exposed_asset.effective_destination_ip}"
            )
        assets.add_row(
            exposed_asset.effective_destination_ip,
            f"{exposed_asset.service} / "
            f"{','.join(str(port) for port in exposed_asset.ports)}",
            str(exposed_asset.distinct_external_source_count),
            nat_text,
        )
    if not rollup.exposed_assets:
        assets.add_row("-", "No exposed sensitive services", "0", "-")
    console.print(assets)
    if len(rollup.exposed_assets) > MAX_BRIEF_ASSETS:
        console.print(
            f"[dim]{len(rollup.exposed_assets) - MAX_BRIEF_ASSETS} additional asset/service "
            "row(s) remain available in the full canonical result.[/dim]"
        )
    console.print(f"Provider calls for this request: {provider_call_count}")
