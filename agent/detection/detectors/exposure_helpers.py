import re

from agent.detection.detectors.scan_helpers import classify_service, parse_ip_address
from agent.schema import CanonicalLogEvent


MAX_ZONE_TEXT_CHARS = 128
MAX_ZONE_TOKENS = 16

WAN_ZONE_TOKENS = frozenset({"wan", "internet", "external", "outside", "untrust"})
LAN_ZONE_TOKENS = frozenset({"lan", "internal", "inside", "trust"})
DMZ_ZONE_TOKENS = frozenset({"dmz"})

SENSITIVE_SERVICE_PORTS = frozenset(
    {20, 21, 22, 23, 135, 139, 389, 445, 1433, 3306, 3389, 5432, 5900}
)
DMZ_ADMINISTRATIVE_PORTS = frozenset(
    {8000, 8080, 8443, 8888, 9000, 9443, 10000}
)
CRITICAL_MANAGEMENT_PORTS = frozenset(
    {161, 623, 2375, 5985, 6379, 9200, 10250, 11211, 27017}
)
EXPOSURE_SERVICE_PORTS = SENSITIVE_SERVICE_PORTS | CRITICAL_MANAGEMENT_PORTS


def _zone_tokens(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    bounded = str(value).casefold()[:MAX_ZONE_TEXT_CHARS]
    return tuple(
        token
        for token in re.split(r"[-_\s]+", bounded)
        if token
    )[:MAX_ZONE_TOKENS]


def _contains_zone_token(
    value: object,
    expected: frozenset[str],
    *,
    allow_numbered_wan: bool = False,
) -> bool:
    tokens = _zone_tokens(value)
    return any(
        token in expected
        or (allow_numbered_wan and re.fullmatch(r"wan\d+", token) is not None)
        for token in tokens
    )


def is_explicit_wan_zone(value: object) -> bool:
    return _contains_zone_token(value, WAN_ZONE_TOKENS, allow_numbered_wan=True)


def is_explicit_lan_zone(value: object) -> bool:
    return _contains_zone_token(value, LAN_ZONE_TOKENS)


def is_explicit_dmz_zone(value: object) -> bool:
    return _contains_zone_token(value, DMZ_ZONE_TOKENS)


def bounded_zone(value: object) -> str:
    if value is None:
        return "unknown"
    normalized = " ".join(str(value).split())[:MAX_ZONE_TEXT_CHARS]
    return normalized or "unknown"


def effective_destination_ip(event: CanonicalLogEvent) -> str | None:
    return event.translated_dst_ip or event.dst_ip


def effective_destination_port(event: CanonicalLogEvent) -> int | None:
    if event.translated_dst_port is not None:
        return event.translated_dst_port
    return event.dst_port


def is_usable_ip(value: str | None) -> bool:
    address = parse_ip_address(value)
    return bool(
        address
        and not address.is_loopback
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_link_local
    )


def is_public_source(event: CanonicalLogEvent) -> bool:
    address = parse_ip_address(event.src_ip)
    return bool(address and is_usable_ip(event.src_ip) and address.is_global)


def is_private_source(event: CanonicalLogEvent) -> bool:
    address = parse_ip_address(event.src_ip)
    return bool(address and is_usable_ip(event.src_ip) and address.is_private)


def is_private_effective_destination(event: CanonicalLogEvent) -> bool:
    value = effective_destination_ip(event)
    address = parse_ip_address(value)
    return bool(address and is_usable_ip(value) and address.is_private)


def has_destination_translation(event: CanonicalLogEvent) -> bool:
    return bool(
        (event.translated_dst_ip and event.translated_dst_ip.strip())
        or event.translated_dst_port is not None
    )


def has_private_destination_translation(event: CanonicalLogEvent) -> bool:
    address = parse_ip_address(event.translated_dst_ip)
    return bool(
        has_destination_translation(event)
        and address
        and is_usable_ip(event.translated_dst_ip)
        and address.is_private
    )


def has_public_to_private_destination_translation(
    event: CanonicalLogEvent,
) -> bool:
    original = parse_ip_address(event.dst_ip)
    return bool(
        original
        and is_usable_ip(event.dst_ip)
        and original.is_global
        and has_private_destination_translation(event)
    )


def has_external_inbound_evidence(event: CanonicalLogEvent) -> bool:
    if is_private_source(event) and is_private_effective_destination(event):
        return False
    return bool(
        is_explicit_wan_zone(event.inbound_zone)
        or (is_public_source(event) and is_private_effective_destination(event))
        or has_public_to_private_destination_translation(event)
    )


def classify_network_direction(event: CanonicalLogEvent) -> str:
    if is_private_source(event) and is_private_effective_destination(event):
        return "private_internal"
    inbound_wan = is_explicit_wan_zone(event.inbound_zone)
    outbound_lan = is_explicit_lan_zone(event.outbound_zone)
    outbound_dmz = is_explicit_dmz_zone(event.outbound_zone)
    if inbound_wan and outbound_lan:
        return "wan_to_lan"
    if inbound_wan and outbound_dmz:
        return "wan_to_dmz"
    if inbound_wan:
        return "external_inbound"
    if has_public_to_private_destination_translation(event):
        return "dnat_inbound"
    if is_public_source(event) and is_private_effective_destination(event):
        return "public_to_private"
    return "unknown"


def sensitive_service_for_port(port: int | None) -> str | None:
    if port not in EXPOSURE_SERVICE_PORTS:
        return None
    return classify_service(port)


def administrative_service_for_port(port: int | None) -> str | None:
    service = sensitive_service_for_port(port)
    if service is not None:
        return service
    if port in DMZ_ADMINISTRATIVE_PORTS:
        return "web_admin"
    return None


def is_critical_management_port(port: int | None) -> bool:
    return port in CRITICAL_MANAGEMENT_PORTS
