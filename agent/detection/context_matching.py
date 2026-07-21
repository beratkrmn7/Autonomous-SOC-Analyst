"""Bidirectional, NAT-aware relatedness checks between canonical events.

Used to decide whether a context (non-incident) event should be attached to an
incident, and whether a related allowed flow exists for likely SPI
state-desynchronization classification. A single shared IP is never treated as
sufficient evidence of relatedness.
"""

from collections.abc import Iterable, Sequence

from agent.detection.detectors.scan_helpers import classify_service
from agent.schema import CanonicalLogEvent


def _endpoint_ip_sets(
    event: CanonicalLogEvent,
) -> tuple[frozenset[str], frozenset[str]]:
    src_ips = frozenset(
        ip for ip in (event.src_ip, event.translated_src_ip) if ip
    )
    dst_ips = frozenset(
        ip for ip in (event.dst_ip, event.translated_dst_ip) if ip
    )
    return src_ips, dst_ips


def _endpoint_port_sets(
    event: CanonicalLogEvent,
) -> tuple[frozenset[int], frozenset[int]]:
    src_ports = frozenset(
        port
        for port in (event.src_port, event.translated_src_port)
        if port is not None
    )
    dst_ports = frozenset(
        port
        for port in (event.dst_port, event.translated_dst_port)
        if port is not None
    )
    return src_ports, dst_ports


def _protocols_compatible(
    reference: CanonicalLogEvent,
    candidate: CanonicalLogEvent,
) -> bool:
    """True unless both protocols are known and differ.

    A TCP SPI response must not be related to a UDP (or other non-TCP)
    allowed flow just because their IPs and ports line up; when either side
    has no recorded protocol, the check is not blocking.
    """
    ref_protocol = str(reference.protocol).upper() if reference.protocol else None
    cand_protocol = str(candidate.protocol).upper() if candidate.protocol else None
    if ref_protocol and cand_protocol:
        return ref_protocol == cand_protocol
    return True


def _is_likely_service_port(port: int) -> bool:
    """True for a well-known/registered port, never an ephemeral client port.

    Ports below 1024 are the IANA well-known range; ports already recognized
    by `classify_service` (for example RDP, SSH, database ports) also count.
    This intentionally does not special-case 443 in the service map - it
    already falls below 1024.
    """
    return port < 1024 or classify_service(port) is not None


def events_are_bidirectionally_related(
    reference: CanonicalLogEvent,
    candidate: CanonicalLogEvent,
) -> bool:
    """True when `candidate` is strongly related to `reference`.

    Relatedness requires compatible protocols (when both are known), an exact
    endpoint relationship (forward or reverse source/destination, including
    NAT-translated IPs), combined with a port relationship. The port
    relationship may be: a full forward or reversed port match, a
    NAT/classified-service match, or - for a confirmed reverse IP
    relationship only - a one-sided match on a well-known/service-side port
    (for example an incident event's destination 443 matching the
    candidate's reverse source 443), so that differing client-side ephemeral
    ports on an otherwise reverse HTTPS/NAT flow do not block the match. A
    one-sided match on a non-service (ephemeral) port never counts. Events
    with no ports at all (for example ICMP) may match on endpoints alone.
    Sharing exactly one IP with no other relationship is never sufficient.
    """
    if not _protocols_compatible(reference, candidate):
        return False

    ref_src_ips, ref_dst_ips = _endpoint_ip_sets(reference)
    cand_src_ips, cand_dst_ips = _endpoint_ip_sets(candidate)

    forward_ip = bool(ref_src_ips & cand_src_ips) and bool(ref_dst_ips & cand_dst_ips)
    reverse_ip = bool(ref_src_ips & cand_dst_ips) and bool(ref_dst_ips & cand_src_ips)
    if not (forward_ip or reverse_ip):
        return False

    ref_src_ports, ref_dst_ports = _endpoint_port_sets(reference)
    cand_src_ports, cand_dst_ports = _endpoint_port_sets(candidate)

    forward_ports = bool(ref_src_ports & cand_src_ports) and bool(
        ref_dst_ports & cand_dst_ports
    )
    reverse_ports = bool(ref_src_ports & cand_dst_ports) and bool(
        ref_dst_ports & cand_src_ports
    )
    # Reverse HTTPS/NAT flows keep the fixed service-side port but the
    # client-side ephemeral port legitimately differs between the request
    # and response/allowed log entries. Accept a one-sided match only when
    # the IP relationship is genuinely reverse AND the matched port on the
    # reference side is itself a well-known/service port - never a
    # coincidentally shared client ephemeral port - and never as a
    # substitute for the exact endpoint check above.
    ref_service_src_ports = {port for port in ref_src_ports if _is_likely_service_port(port)}
    ref_service_dst_ports = {port for port in ref_dst_ports if _is_likely_service_port(port)}
    reverse_service_port_match = reverse_ip and (
        bool(ref_service_dst_ports & cand_src_ports)
        or bool(ref_service_src_ports & cand_dst_ports)
    )

    all_ref_ports = ref_src_ports | ref_dst_ports
    all_cand_ports = cand_src_ports | cand_dst_ports
    if not all_ref_ports and not all_cand_ports:
        return True

    ref_services = {
        service
        for port in all_ref_ports
        if (service := classify_service(port)) is not None
    }
    cand_services = {
        service
        for port in all_cand_ports
        if (service := classify_service(port)) is not None
    }
    compatible_service = bool(ref_services & cand_services)

    return forward_ports or reverse_ports or compatible_service or reverse_service_port_match


def find_related_context_events(
    reference_events: Sequence[CanonicalLogEvent],
    context_events: Iterable[CanonicalLogEvent],
) -> list[CanonicalLogEvent]:
    """Return the subset of `context_events` related to any `reference_events`."""
    return [
        candidate
        for candidate in context_events
        if any(
            events_are_bidirectionally_related(reference, candidate)
            for reference in reference_events
        )
    ]
