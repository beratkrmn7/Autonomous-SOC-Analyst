import ipaddress
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType

from agent.schema import CanonicalLogEvent
from agent.tcp_flags import canonicalize_tcp_flags, parse_tcp_flag_tokens


BLOCKED_ACTIONS = frozenset({"block", "blocked", "deny", "denied", "drop", "dropped", "reject", "rejected"})
ALLOWED_ACTIONS = frozenset({"allow", "allowed", "accept", "accepted", "pass", "passed"})

SERVICE_PORTS = MappingProxyType(
    {
        "database": (1433, 1521, 3306, 5432),
        "docker": (2375, 2376),
        "elasticsearch": (9200,),
        "ftp": (21,),
        "ftp_data": (20,),
        "ipmi": (623,),
        "kubernetes": (6443, 10250),
        "ldap": (389,),
        "memcached": (11211,),
        "mongodb": (27017,),
        "msrpc": (135,),
        "rdp": (3389,),
        "redis": (6379,),
        "smb": (139, 445),
        "snmp": (161,),
        "ssh": (22, 2022, 2222),
        "telnet": (23,),
        "vnc": (5900, 5901, 5902, 5903, 5904, 5905),
        "winrm": (5985, 5986),
    }
)
PORT_TO_SERVICE = MappingProxyType(
    {
        port: service
        for service, ports in SERVICE_PORTS.items()
        for port in ports
    }
)


def normalized_protocol(event: CanonicalLogEvent) -> str:
    return str(event.protocol).upper() if event.protocol else "UNKNOWN"


def is_blocked(event: CanonicalLogEvent) -> bool:
    return bool(event.action and event.action.strip().lower() in BLOCKED_ACTIONS)


def is_allowed(event: CanonicalLogEvent) -> bool:
    return bool(event.action and event.action.strip().lower() in ALLOWED_ACTIONS)


def event_tcp_flag_tokens(event: CanonicalLogEvent) -> frozenset[str]:
    return parse_tcp_flag_tokens(event.tcp_flags)


def has_exact_tcp_flags(
    event: CanonicalLogEvent,
    expected: frozenset[str],
) -> bool:
    return event_tcp_flag_tokens(event) == expected


def has_tcp_flags(
    event: CanonicalLogEvent,
    required: frozenset[str],
) -> bool:
    return required.issubset(event_tcp_flag_tokens(event))


def is_explicit_tcp_null(event: CanonicalLogEvent) -> bool:
    metadata = event.parser_metadata or {}
    if (
        metadata.get("tcp_flags_present") is True
        and metadata.get("tcp_flags_explicit_none") is True
    ):
        return True
    normalized = canonicalize_tcp_flags(
        event.tcp_flags,
        field_present=event.tcp_flags is not None,
    )
    return normalized.explicit_none


def is_tcp_syn(event: CanonicalLogEvent) -> bool:
    if normalized_protocol(event) != "TCP":
        return False
    tokens = event_tcp_flag_tokens(event)
    return "SYN" in tokens and "ACK" not in tokens


def is_tcp_initial_connection_probe(event: CanonicalLogEvent) -> bool:
    """True only for a structural initial TCP connection probe (bare SYN-style).

    Excludes response-side traffic (ACK, ACK+RST, FIN+ACK, SYN+RST, SYN+ACK),
    missing flags, and explicit NULL flags.
    """
    if normalized_protocol(event) != "TCP":
        return False
    tokens = event_tcp_flag_tokens(event)
    return "SYN" in tokens and not (tokens & {"ACK", "RST", "FIN"})


def is_spi_anomaly_event(
    event: CanonicalLogEvent,
    *,
    fallback_raw_match: bool,
) -> bool:
    if event.action_reason and "spi" in str(event.action_reason).lower():
        return True
    if event.event_outcome and "spi" in str(event.event_outcome).lower():
        return True
    if event.action and "spi" in str(event.action).lower():
        return True
    if event.parser_metadata and event.parser_metadata.get("spi_anomaly") is True:
        return True
    return bool(
        fallback_raw_match
        and event.safe_message_excerpt
        and "blocked by spi" in str(event.safe_message_excerpt).lower()
    )


def is_spi_block_event(
    event: CanonicalLogEvent,
    *,
    fallback_raw_match: bool,
) -> bool:
    if not is_spi_anomaly_event(event, fallback_raw_match=fallback_raw_match):
        return False
    action = str(event.action).lower() if event.action else ""
    return bool(
        is_blocked(event)
        or any(marker in action for marker in ("block", "deny", "drop"))
        or (
            fallback_raw_match
            and event.safe_message_excerpt
            and "blocked by spi" in str(event.safe_message_excerpt).lower()
        )
    )


def event_ratios(events: Sequence[CanonicalLogEvent]) -> tuple[float, float]:
    if not events:
        return 0.0, 0.0
    event_count = len(events)
    block_ratio = sum(1 for event in events if is_blocked(event)) / event_count
    syn_ratio = sum(1 for event in events if is_tcp_syn(event)) / event_count
    return block_ratio, syn_ratio


def observed_span_seconds(events: Sequence[CanonicalLogEvent]) -> float:
    timestamps = [event.timestamp for event in events if event.timestamp is not None]
    if len(timestamps) < 2:
        return 0.0
    return max(0.0, (max(timestamps) - min(timestamps)).total_seconds())


def parse_ip_address(
    value: str | None,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not value:
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_private_unicast(value: str | None) -> bool:
    address = parse_ip_address(value)
    return bool(
        address
        and address.is_private
        and not address.is_loopback
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_link_local
    )


def destination_subnet(
    value: str | None,
    ipv4_prefix: int,
    ipv6_prefix: int,
) -> str | None:
    address = parse_ip_address(value)
    if address is None:
        return None
    prefix = ipv4_prefix if address.version == 4 else ipv6_prefix
    try:
        return ipaddress.ip_network(f"{address}/{prefix}", strict=False).with_prefixlen
    except ValueError:
        return None


def classify_service(port: int | None) -> str | None:
    if port is None:
        return None
    return PORT_TO_SERVICE.get(port)


def bounded_sorted_values(values: Iterable[str], limit: int = 20) -> list[str]:
    return sorted(set(values))[:limit]


@dataclass(frozen=True)
class FixedSourcePortGroup:
    """One exact source scanning from a constant, service-looking source port.

    Grouping is always by exact source IP. A whole /24 is never treated as one
    attacker here; combining several exact sources is a presentation concern
    handled well above detection.
    """

    source_ip: str
    source_port: int
    events: tuple[CanonicalLogEvent, ...]
    destination_ips: tuple[str, ...]
    destination_ports: tuple[int, ...]
    allowed_event_count: int
    blocked_event_count: int
    first_seen: datetime
    last_seen: datetime

    @property
    def event_count(self) -> int:
        return len(self.events)


def find_fixed_source_port_groups(
    events: Sequence[CanonicalLogEvent],
    *,
    source_ports: Sequence[int],
    min_events: int,
    min_distinct_destination_ports: int,
    window_seconds: int,
    is_external_inbound: Callable[[CanonicalLogEvent], bool],
) -> list[FixedSourcePortGroup]:
    """Find exact-source constant-source-port TCP SYN sweeps.

    A scanner that pins its source port to 53, 80 or 443 is trying to look
    like return traffic from a common service. The pattern is recognised only
    from deterministic event facts: TCP initial SYN, external inbound zone, a
    constant source port drawn from a bounded configured set, a bounded time
    window, and deduplicated event IDs.

    Reaching ``min_distinct_destination_ports`` on a single destination host
    is accepted as the equivalent target scope of touching several hosts: the
    behaviour is the same service enumeration either way.

    ``is_external_inbound`` is injected by the caller because the zone helpers
    live in a module that already imports this one.
    """
    allowed_source_ports = frozenset(source_ports)
    grouped: dict[tuple[str, int], list[CanonicalLogEvent]] = {}
    seen_event_ids: set[str] = set()

    for event in events:
        if event.event_id in seen_event_ids:
            continue
        if not event.src_ip or event.src_port is None:
            continue
        if event.src_port not in allowed_source_ports:
            continue
        if not is_tcp_initial_connection_probe(event):
            continue
        if not is_external_inbound(event):
            continue
        if event.dst_port is None or not event.dst_ip:
            continue
        seen_event_ids.add(event.event_id)
        grouped.setdefault((event.src_ip, event.src_port), []).append(event)

    results: list[FixedSourcePortGroup] = []
    for (source_ip, source_port), group_events in sorted(grouped.items()):
        ordered = sorted(
            group_events,
            key=lambda item: (item.timestamp or datetime.min, item.event_id),
        )
        timestamps = [event.timestamp for event in ordered if event.timestamp]
        if not timestamps:
            continue
        if (timestamps[-1] - timestamps[0]).total_seconds() > window_seconds:
            continue
        if len(ordered) < min_events:
            continue
        destination_ports = sorted(
            {event.dst_port for event in ordered if event.dst_port is not None}
        )
        if len(destination_ports) < min_distinct_destination_ports:
            continue

        results.append(
            FixedSourcePortGroup(
                source_ip=source_ip,
                source_port=source_port,
                events=tuple(ordered),
                destination_ips=tuple(
                    sorted({event.dst_ip for event in ordered if event.dst_ip})
                ),
                destination_ports=tuple(destination_ports),
                allowed_event_count=sum(1 for event in ordered if is_allowed(event)),
                blocked_event_count=sum(1 for event in ordered if is_blocked(event)),
                first_seen=timestamps[0],
                last_seen=timestamps[-1],
            )
        )
    return results
