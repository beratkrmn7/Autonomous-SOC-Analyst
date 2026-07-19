import ipaddress
import re
from collections.abc import Iterable, Sequence
from types import MappingProxyType

from agent.schema import CanonicalLogEvent


BLOCKED_ACTIONS = frozenset({"block", "blocked", "deny", "denied", "drop", "dropped", "reject", "rejected"})
ALLOWED_ACTIONS = frozenset({"allow", "allowed", "accept", "accepted", "pass", "passed"})

SERVICE_PORTS = MappingProxyType(
    {
        "database": (1433, 1521, 3306, 5432, 6379, 9200, 27017),
        "docker": (2375, 2376),
        "ftp": (20, 21),
        "kubernetes": (6443, 10250),
        "rdp": (3389,),
        "smb": (139, 445),
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


def is_tcp_syn(event: CanonicalLogEvent) -> bool:
    if normalized_protocol(event) != "TCP" or not event.tcp_flags:
        return False
    tokens = {
        token
        for token in re.split(r"[^A-Z]+", event.tcp_flags.upper())
        if token
    }
    return "SYN" in tokens and "ACK" not in tokens


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
