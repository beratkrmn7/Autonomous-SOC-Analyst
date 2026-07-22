"""Pure presentation roll-ups over canonical detection results.

Nothing in this module mutates detection objects or feeds data back into
correlation, persistence, routing, or incident identity.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agent.detection.detectors.exposure_helpers import (
    effective_destination_ip,
    effective_destination_port,
    has_destination_translation,
    has_external_inbound_evidence,
    is_public_source,
    sensitive_service_for_port,
)
from agent.detection.detectors.scan_helpers import classify_service, is_allowed, is_blocked
from agent.detection.models import DetectionSignal, IncidentBundle
from agent.schema import CanonicalLogEvent


MAX_ACTION_ITEMS_PER_SECTION = 5
MAX_REPRESENTATIVE_SOURCES = 5
MAX_SUPPRESSED_TARGETS = 5
MAX_ASSET_PUBLIC_DESTINATIONS = 5
DEFAULT_RECON_TIME_COMPATIBILITY_SECONDS = 300

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_RECON_FAMILIES = frozenset({"network_scanning", "service_probing"})
_EXPOSURE_FAMILIES = frozenset({"firewall_exposure", "firewall_policy"})


class ReconGroup(BaseModel):
    model_config = ConfigDict(frozen=True)

    source_cidr: str
    incident_family: str
    service_scope: str
    source_count: int
    total_event_count: int
    distinct_target_count: int
    ports: tuple[int, ...] = ()
    first_seen: datetime
    last_seen: datetime
    representative_sources: tuple[str, ...] = ()


class SuppressedEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    signal_id: str
    source: str
    targets: tuple[str, ...] = ()
    event_count: int
    reason: str


class ExposedAsset(BaseModel):
    model_config = ConfigDict(frozen=True)

    effective_destination_ip: str
    service: str
    ports: tuple[int, ...]
    distinct_external_source_count: int
    event_count: int
    nat_observed: bool
    internal_address: str | None = None
    public_destinations: tuple[str, ...] = ()


class RollupResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    act_now: tuple[IncidentBundle, ...] = ()
    investigate: tuple[IncidentBundle, ...] = ()
    recon_groups: tuple[ReconGroup, ...] = ()
    suppressed: tuple[SuppressedEntry, ...] = ()
    exposed_assets: tuple[ExposedAsset, ...] = ()
    funnel: dict[str, int] = Field(default_factory=dict)


def _incident_events(
    incident: IncidentBundle,
    event_lookup: Mapping[str, CanonicalLogEvent],
) -> list[CanonicalLogEvent]:
    return [
        event_lookup[event_id]
        for event_id in incident.event_ids
        if event_id in event_lookup
    ]


def _is_fully_blocked_recon(
    incident: IncidentBundle,
    event_lookup: Mapping[str, CanonicalLogEvent],
) -> bool:
    if incident.incident_family not in _RECON_FAMILIES or not incident.event_ids:
        return False
    allowed_count = incident.metrics.get("allowed_event_count")
    blocked_count = incident.metrics.get("blocked_event_count")
    total_count = incident.metrics.get("severity_total_event_count")
    if (
        isinstance(allowed_count, int)
        and isinstance(blocked_count, int)
        and isinstance(total_count, int)
    ):
        return bool(allowed_count == 0 and blocked_count == total_count and total_count > 0)

    events = _incident_events(incident, event_lookup)
    # Fail closed when canonical events are incomplete; presentation must never
    # guess that unseen prior-job activity was blocked.
    return bool(
        len(events) == len(set(incident.event_ids))
        and events
        and all(is_blocked(event) for event in events)
    )


def _incident_action_key(incident: IncidentBundle) -> tuple[int, float, datetime, str]:
    return (
        -_SEVERITY_RANK.get(incident.severity, 0),
        -incident.confidence,
        incident.first_seen,
        incident.incident_id,
    )


def _source_network(value: str | None) -> str | None:
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    prefix = 24 if address.version == 4 else 64
    return ipaddress.ip_network(f"{address}/{prefix}", strict=False).with_prefixlen


def _service_scope(events: Sequence[CanonicalLogEvent]) -> str:
    services = sorted(
        {
            service
            for event in events
            if (service := classify_service(event.dst_port)) is not None
        }
    )
    if services:
        return "services:" + ",".join(services)
    ports = sorted({event.dst_port for event in events if event.dst_port is not None})
    if len(ports) <= 5:
        return "ports:" + ",".join(str(port) for port in ports)
    return "ports:varied"


def _build_recon_groups(
    incidents: Sequence[IncidentBundle],
    event_lookup: Mapping[str, CanonicalLogEvent],
    *,
    time_compatibility_seconds: int,
) -> tuple[ReconGroup, ...]:
    contributions: list[dict[str, Any]] = []
    for incident in incidents:
        if not _is_fully_blocked_recon(incident, event_lookup):
            continue
        events = _incident_events(incident, event_lookup)
        events_by_cidr: dict[str, list[CanonicalLogEvent]] = {}
        for event in events:
            cidr = _source_network(event.src_ip)
            if cidr is not None:
                events_by_cidr.setdefault(cidr, []).append(event)
        for cidr, scoped_events in events_by_cidr.items():
            contributions.append(
                {
                    "source_cidr": cidr,
                    "incident_family": incident.incident_family,
                    "service_scope": _service_scope(scoped_events),
                    "first_seen": min(
                        event.timestamp for event in scoped_events if event.timestamp
                    ),
                    "last_seen": max(
                        event.timestamp for event in scoped_events if event.timestamp
                    ),
                    "events": scoped_events,
                }
            )

    contributions.sort(
        key=lambda item: (
            item["source_cidr"],
            item["incident_family"],
            item["service_scope"],
            item["first_seen"],
        )
    )
    groups: list[dict[str, Any]] = []
    compatibility = timedelta(seconds=time_compatibility_seconds)
    for contribution in contributions:
        compatible = [
            group
            for group in groups
            if group["source_cidr"] == contribution["source_cidr"]
            and group["incident_family"] == contribution["incident_family"]
            and group["service_scope"] == contribution["service_scope"]
            and contribution["first_seen"] <= group["last_seen"] + compatibility
        ]
        if not compatible:
            groups.append(
                {
                    **contribution,
                    "events": {
                        event.event_id: event for event in contribution["events"]
                    },
                }
            )
            continue
        group = min(compatible, key=lambda item: (item["first_seen"], item["source_cidr"]))
        group["first_seen"] = min(group["first_seen"], contribution["first_seen"])
        group["last_seen"] = max(group["last_seen"], contribution["last_seen"])
        group["events"].update(
            {event.event_id: event for event in contribution["events"]}
        )

    result: list[ReconGroup] = []
    for group in groups:
        events = list(group["events"].values())
        sources = sorted({event.src_ip for event in events if event.src_ip})
        targets = {event.dst_ip for event in events if event.dst_ip}
        ports = tuple(sorted({event.dst_port for event in events if event.dst_port is not None}))
        result.append(
            ReconGroup(
                source_cidr=group["source_cidr"],
                incident_family=group["incident_family"],
                service_scope=group["service_scope"],
                source_count=len(sources),
                total_event_count=len({event.event_id for event in events}),
                distinct_target_count=len(targets),
                ports=ports,
                first_seen=group["first_seen"],
                last_seen=group["last_seen"],
                representative_sources=tuple(
                    sources[:MAX_REPRESENTATIVE_SOURCES]
                ),
            )
        )
    return tuple(
        sorted(
            result,
            key=lambda group: (
                group.first_seen,
                group.source_cidr,
                group.incident_family,
                group.service_scope,
            ),
        )
    )


def _build_suppressed_entries(
    signals: Sequence[DetectionSignal],
) -> tuple[SuppressedEntry, ...]:
    return tuple(
        SuppressedEntry(
            signal_id=signal.signal_id,
            source=signal.primary_entity,
            targets=tuple(sorted(set(signal.target_entities))[:MAX_SUPPRESSED_TARGETS]),
            event_count=len(set(signal.event_ids)),
            reason=signal.suppression_reason or "suppressed_by_policy",
        )
        for signal in sorted(signals, key=lambda item: (item.first_seen, item.signal_id))
    )


def _build_exposed_assets(
    incidents: Sequence[IncidentBundle],
    event_lookup: Mapping[str, CanonicalLogEvent],
) -> tuple[ExposedAsset, ...]:
    exposure_event_ids = {
        event_id
        for incident in incidents
        if incident.incident_family in _EXPOSURE_FAMILIES
        for event_id in incident.event_ids
    }
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for event_id in sorted(exposure_event_ids):
        event = event_lookup.get(event_id)
        if event is None or not is_allowed(event) or not has_external_inbound_evidence(event):
            continue
        destination = effective_destination_ip(event)
        port = effective_destination_port(event)
        service = sensitive_service_for_port(port)
        if not destination or port is None or service is None:
            continue
        item = grouped.setdefault(
            (destination, service),
            {
                "ports": set(),
                "sources": set(),
                "event_ids": set(),
                "nat_observed": False,
                "internal_address": None,
                "public_destinations": set(),
            },
        )
        item["ports"].add(port)
        if is_public_source(event) and event.src_ip:
            item["sources"].add(event.src_ip)
        item["event_ids"].add(event.event_id)
        if has_destination_translation(event):
            item["nat_observed"] = True
            item["internal_address"] = event.translated_dst_ip or destination
            if event.dst_ip:
                item["public_destinations"].add(event.dst_ip)

    return tuple(
        ExposedAsset(
            effective_destination_ip=destination,
            service=service,
            ports=tuple(sorted(item["ports"])),
            distinct_external_source_count=len(item["sources"]),
            event_count=len(item["event_ids"]),
            nat_observed=bool(item["nat_observed"]),
            internal_address=item["internal_address"],
            public_destinations=tuple(
                sorted(item["public_destinations"])[
                    :MAX_ASSET_PUBLIC_DESTINATIONS
                ]
            ),
        )
        for (destination, service), item in sorted(grouped.items())
    )


def build_rollup(
    incidents: Sequence[IncidentBundle],
    event_lookup: Mapping[str, CanonicalLogEvent],
    *,
    suppressed_signals: Sequence[DetectionSignal] = (),
    run_event_ids: Sequence[str] | None = None,
    time_compatibility_seconds: int = DEFAULT_RECON_TIME_COMPATIBILITY_SECONDS,
) -> RollupResult:
    """Build a deterministic, bounded SOC presentation roll-up."""
    fully_blocked_recon_ids = {
        incident.incident_id
        for incident in incidents
        if _is_fully_blocked_recon(incident, event_lookup)
    }
    actionable = [
        incident
        for incident in incidents
        if incident.incident_id not in fully_blocked_recon_ids
    ]
    act_now = tuple(
        sorted(
            (
                incident
                for incident in actionable
                if incident.severity in {"critical", "high"}
            ),
            key=_incident_action_key,
        )[:MAX_ACTION_ITEMS_PER_SECTION]
    )
    investigate = tuple(
        sorted(
            (incident for incident in actionable if incident.severity == "medium"),
            key=_incident_action_key,
        )[:MAX_ACTION_ITEMS_PER_SECTION]
    )

    run_ids = set(run_event_ids) if run_event_ids is not None else set(event_lookup)
    run_events = [
        event for event_id, event in event_lookup.items() if event_id in run_ids
    ]
    policy_exposure_ids = {
        event.event_id
        for event in run_events
        if is_allowed(event)
        and has_external_inbound_evidence(event)
        and sensitive_service_for_port(effective_destination_port(event)) is not None
    }
    return RollupResult(
        act_now=act_now,
        investigate=investigate,
        recon_groups=_build_recon_groups(
            incidents,
            event_lookup,
            time_compatibility_seconds=time_compatibility_seconds,
        ),
        suppressed=_build_suppressed_entries(suppressed_signals),
        exposed_assets=_build_exposed_assets(incidents, event_lookup),
        funnel={
            "total_events": len({event.event_id for event in run_events}),
            "blocked_events": sum(1 for event in run_events if is_blocked(event)),
            "policy_exposures": len(policy_exposure_ids),
            "action_items": len(act_now) + len(investigate),
        },
    )
