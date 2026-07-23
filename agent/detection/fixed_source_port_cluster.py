"""Presentation clustering for fixed-source-port scanning.

Detection reports one canonical finding per exact source IP. This module only
decides how those findings are *shown*: several exact sources inside one /24
that share the same fixed source port, overlap in time and cover a compatible
target scope are displayed as one cluster row.

The cluster is presentation-only. It creates no canonical incident, mutates
nothing, and never claims that a whole /24 is a single attacker - every
contributing exact source IP is preserved and rendered.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from agent.detection.detectors.scan_helpers import FixedSourcePortGroup


# Deterministic ATT&CK mapping, technique and tactic kept apart.
CLUSTER_TECHNIQUE = "T1046"
CLUSTER_TACTIC = "TA0007"

MAX_CLUSTER_SOURCES = 20
MAX_CLUSTER_PORTS = 20


class FixedSourcePortCluster(BaseModel):
    """One bounded presentation cluster of fixed-source-port scanners."""

    model_config = ConfigDict(frozen=True)

    cluster_id: str
    source_cidr: str
    #: Every contributing exact source IP, never collapsed into the CIDR.
    contributing_source_ips: tuple[str, ...]
    fixed_source_port: int
    event_count: int
    allowed_event_count: int
    blocked_event_count: int
    distinct_destination_ip_count: int
    distinct_destination_port_count: int
    destination_ports: tuple[int, ...]
    sensitive_destination_ports: tuple[int, ...]
    event_ids: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
    severity: str
    mitre_technique: str = CLUSTER_TECHNIQUE
    mitre_tactic: str = CLUSTER_TACTIC

    @property
    def source_count(self) -> int:
        return len(self.contributing_source_ips)


def _source_network(value: str) -> str | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.version != 4:
        return None
    return str(ipaddress.ip_network(f"{value}/24", strict=False))


def _time_compatible_runs(
    groups: Sequence[FixedSourcePortGroup], window_seconds: int
) -> list[list[FixedSourcePortGroup]]:
    """Split groups into maximal runs that share one short window.

    A source scanning the same /24 from the same fixed port two minutes later
    is a separate burst. It must start its own run rather than stretch - and
    thereby invalidate - the run its neighbours formed.
    """
    ordered = sorted(groups, key=lambda group: (group.first_seen, group.source_ip))
    runs: list[list[FixedSourcePortGroup]] = []
    current: list[FixedSourcePortGroup] = []
    for group in ordered:
        if not current:
            current = [group]
            continue
        span_start = min(member.first_seen for member in current)
        span_end = max(max(member.last_seen for member in current), group.last_seen)
        if (span_end - span_start).total_seconds() <= window_seconds:
            current.append(group)
        else:
            runs.append(current)
            current = [group]
    if current:
        runs.append(current)
    return runs


def build_fixed_source_port_clusters(
    groups: Sequence[FixedSourcePortGroup],
    *,
    min_sources: int,
    min_events_per_source: int,
    min_total_events: int,
    window_seconds: int,
    sensitive_ports: frozenset[int] = frozenset(),
) -> tuple[FixedSourcePortCluster, ...]:
    """Combine compatible exact-source findings into presentation clusters.

    A cluster requires at least ``min_sources`` exact sources that each
    contribute at least ``min_events_per_source`` compatible events, at least
    ``min_total_events`` events overall, one shared fixed source port, and an
    overlapping short window. Groups that do not meet these conditions are
    simply not clustered; they are still shown on their own.
    """
    candidates: dict[tuple[str, int], list[FixedSourcePortGroup]] = {}
    for group in groups:
        if group.event_count < min_events_per_source:
            continue
        network = _source_network(group.source_ip)
        if network is None:
            continue
        candidates.setdefault((network, group.source_port), []).append(group)

    clusters: list[FixedSourcePortCluster] = []
    for (network, source_port), bucket in sorted(candidates.items()):
        for burst, members in enumerate(
            _time_compatible_runs(bucket, window_seconds)
        ):
            if len({member.source_ip for member in members}) < min_sources:
                continue
            if sum(member.event_count for member in members) < min_total_events:
                continue
            clusters.append(
                _build_cluster(
                    network,
                    source_port,
                    burst,
                    members,
                    sensitive_ports=sensitive_ports,
                )
            )
    return tuple(clusters)


def _build_cluster(
    network: str,
    source_port: int,
    burst: int,
    members: Sequence[FixedSourcePortGroup],
    *,
    sensitive_ports: frozenset[int],
) -> FixedSourcePortCluster:
    destination_ports = sorted(
        {port for member in members for port in member.destination_ports}
    )
    destination_ips = {
        address for member in members for address in member.destination_ips
    }
    event_ids = sorted(
        {event.event_id for member in members for event in member.events}
    )
    total_events = sum(member.event_count for member in members)
    allowed = sum(member.allowed_event_count for member in members)
    blocked = sum(member.blocked_event_count for member in members)
    cluster_sensitive_ports = tuple(
        port for port in destination_ports if port in sensitive_ports
    )

    # A firewall pass proves policy exposure, never compromise.
    if allowed == 0:
        severity = "low" if total_events < 10 else "medium"
    elif cluster_sensitive_ports:
        severity = "high"
    else:
        severity = "medium"

    contributing = tuple(sorted({member.source_ip for member in members}))
    suffix = "" if burst == 0 else f":{burst}"
    return FixedSourcePortCluster(
        cluster_id=f"fsp:{network}:{source_port}{suffix}",
        source_cidr=network,
        contributing_source_ips=contributing[:MAX_CLUSTER_SOURCES],
        fixed_source_port=source_port,
        event_count=total_events,
        allowed_event_count=allowed,
        blocked_event_count=blocked,
        distinct_destination_ip_count=len(destination_ips),
        distinct_destination_port_count=len(destination_ports),
        destination_ports=tuple(destination_ports[:MAX_CLUSTER_PORTS]),
        sensitive_destination_ports=cluster_sensitive_ports[:MAX_CLUSTER_PORTS],
        event_ids=tuple(event_ids),
        first_seen=min(member.first_seen for member in members),
        last_seen=max(member.last_seen for member in members),
        severity=severity,
    )
