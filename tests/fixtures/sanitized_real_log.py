"""Canonical events reproducing the facts of a real pf firewall capture.

Every address here is synthetic. Public/external addresses use the RFC 5737
documentation ranges (``192.0.2.0/24``, ``198.51.100.0/24``,
``203.0.113.0/24``) and translated internal addresses use RFC 1918 space. No
original record from the source capture is committed to this repository.

What *is* preserved from the capture, because the deterministic tests assert
on it: event counts, address distinctness, source/destination port values,
TCP flags, packet and byte counts, action states, inbound zones and the
relative timing that drives windowing and grouping.

Two capture files are represented:

``file 0`` - an SSH sweep in progress, a 56-packet Docker daemon exposure, a
one-packet Redis exposure, one fixed-source-port scanner that meets the
canonical exact-source threshold on its own, and one that reaches the same
event and port counts but has no TCP flags recorded.

``file 1`` - the remainder of the SSH sweep (four single-packet port-22
records plus two port-22022 records), a 122-packet Redis exposure, two
sub-threshold fixed-source-port scanners that together form one presentation
cluster, and a separate fully blocked fixed-source-port scanner in a
disjoint time window.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from agent.schema import CanonicalLogEvent


TZ = timezone(timedelta(hours=3))
BASE = datetime(2026, 7, 10, 9, 51, 25, tzinfo=TZ)

# Sanitized external sources.
SSH_SWEEP_SOURCE = "192.0.2.10"
DOCKER_EXPOSURE_SOURCE = "192.0.2.26"
REDIS_EXPOSURE_SOURCE_FILE0 = "192.0.2.149"
REDIS_EXPOSURE_SOURCE_FILE1 = "192.0.2.29"

# Sanitized fixed-source-port scanners, all inside one documentation /24.
FSP_NET = "203.0.113"
FSP_SOURCE_CANONICAL_A = f"{FSP_NET}.101"  # 7 SYN events, meets exact-source rule
FSP_SOURCE_NO_FLAGS = f"{FSP_NET}.103"  # 5 events, but no TCP flags recorded
FSP_SOURCE_CLUSTER_A = f"{FSP_NET}.102"  # 3 events, sub-threshold alone
FSP_SOURCE_CLUSTER_B = f"{FSP_NET}.111"  # 4 events, sub-threshold alone
FSP_SOURCE_BLOCKED = f"{FSP_NET}.112"  # 4 blocked events, disjoint window

FIXED_SOURCE_PORT = 443


def _event(
    event_id: str,
    *,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    action: str,
    offset_seconds: float,
    packets: Optional[int] = 1,
    byte_count: int = 0,
    tcp_flags: Optional[str] = None,
    duration_ms: int = 0,
    inbound_zone: str = "wan1-zone",
    outbound_zone: Optional[str] = None,
    nat_type: Optional[str] = None,
    translated_dst_ip: Optional[str] = None,
    translated_dst_port: Optional[int] = None,
) -> CanonicalLogEvent:
    timestamp = BASE + timedelta(seconds=offset_seconds)
    return CanonicalLogEvent(
        event_id=event_id,
        timestamp=timestamp,
        observed_at=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol="TCP",
        action=action,
        action_reason="match",
        event_type="network_flow",
        event_category="network",
        event_outcome="success" if action == "pass" else "failure",
        tcp_flags=tcp_flags,
        inbound_interface="ice0",
        outbound_interface="ixl1",
        inbound_zone=inbound_zone,
        outbound_zone=outbound_zone,
        bytes=byte_count,
        packets=packets,
        duration_ms=duration_ms,
        nat_type=nat_type,
        translated_dst_ip=translated_dst_ip,
        translated_dst_port=translated_dst_port,
        parser_name="pf_firewall",
        parser_version="2.2.0",
        parser_confidence=1.0,
        parse_status="parsed",
        source_name="sanitized-capture",
        safe_message_excerpt="",
    )


# ---------------------------------------------------------------------------
# SSH sweep: one external source touching many internal port-22 hosts.
# ---------------------------------------------------------------------------

#: Four single-packet, zero-byte, no-TCP-flag port-22 records with four
#: distinct destinations and four distinct source ports. These are the records
#: that must share one deterministic policy outcome while keeping their own
#: destination IPs and source ports.
SSH_SWEEP_PORT_22 = (
    _event(
        "f1-ssh-1",
        src_ip=SSH_SWEEP_SOURCE,
        src_port=40488,
        dst_ip="198.51.100.236",
        dst_port=22,
        action="pass",
        offset_seconds=19.647,
    ),
    _event(
        "f1-ssh-2",
        src_ip=SSH_SWEEP_SOURCE,
        src_port=51211,
        dst_ip="198.51.100.173",
        dst_port=22,
        action="pass",
        offset_seconds=20.152,
    ),
    _event(
        "f1-ssh-3",
        src_ip=SSH_SWEEP_SOURCE,
        src_port=49386,
        dst_ip="198.51.100.242",
        dst_port=22,
        action="pass",
        offset_seconds=21.413,
    ),
    _event(
        "f1-ssh-4",
        src_ip=SSH_SWEEP_SOURCE,
        src_port=46145,
        dst_ip="198.51.100.250",
        dst_port=22,
        action="pass",
        offset_seconds=20.140,
    ),
)

#: Same source, same host, port 22022. The deterministic service classifier
#: does not recognise 22022 as SSH, so these must not join the SSH group.
SSH_SWEEP_PORT_22022 = (
    _event(
        "f1-alt-1",
        src_ip=SSH_SWEEP_SOURCE,
        src_port=33771,
        dst_ip="198.51.100.96",
        dst_port=22022,
        action="pass",
        offset_seconds=22.387,
        packets=3,
        byte_count=124,
        tcp_flags="S",
        duration_ms=1627,
    ),
    _event(
        "f1-alt-2",
        src_ip=SSH_SWEEP_SOURCE,
        src_port=33770,
        dst_ip="198.51.100.96",
        dst_port=22022,
        action="pass",
        offset_seconds=15.322,
        packets=3,
        byte_count=124,
        tcp_flags="S",
        duration_ms=6712,
    ),
)

#: File 0 portion of the same sweep.
SSH_SWEEP_FILE0 = (
    _event(
        "f0-ssh-1",
        src_ip=SSH_SWEEP_SOURCE,
        src_port=57122,
        dst_ip="198.51.100.128",
        dst_port=22,
        action="pass",
        offset_seconds=18.837,
    ),
    _event(
        "f0-ssh-2",
        src_ip=SSH_SWEEP_SOURCE,
        src_port=44391,
        dst_ip="198.51.100.73",
        dst_port=22,
        action="pass",
        offset_seconds=19.021,
    ),
    _event(
        "f0-alt-1",
        src_ip=SSH_SWEEP_SOURCE,
        src_port=33769,
        dst_ip="198.51.100.96",
        dst_port=22022,
        action="pass",
        offset_seconds=0.422,
        packets=5,
        byte_count=251,
        tcp_flags="SAP",
        duration_ms=14612,
    ),
)


# ---------------------------------------------------------------------------
# Critical-management exposures with high packet counts but SYN-only flags.
# ---------------------------------------------------------------------------

#: 56 packets to the Docker daemon port. Must never classify as syn_only.
DOCKER_EXPOSURE = _event(
    "f0-docker-1",
    src_ip=DOCKER_EXPOSURE_SOURCE,
    src_port=64467,
    dst_ip="198.51.100.150",
    dst_port=2375,
    action="pass",
    offset_seconds=30.0,
    packets=56,
    byte_count=2296,
    tcp_flags="S",
    duration_ms=8000,
)

#: 122 packets to Redis. Must never classify as syn_only.
REDIS_EXPOSURE_MULTI_PACKET = _event(
    "f1-redis-1",
    src_ip=REDIS_EXPOSURE_SOURCE_FILE1,
    src_port=49485,
    dst_ip="198.51.100.157",
    dst_port=6379,
    action="pass",
    offset_seconds=35.0,
    packets=122,
    byte_count=5368,
    tcp_flags="S",
    duration_ms=12000,
)

#: One packet, SYN only. This is the syn_only reference case.
REDIS_EXPOSURE_SINGLE_SYN = _event(
    "f0-redis-1",
    src_ip=REDIS_EXPOSURE_SOURCE_FILE0,
    src_port=49552,
    dst_ip="198.51.100.221",
    dst_port=6379,
    action="pass",
    offset_seconds=28.0,
    packets=1,
    byte_count=44,
    tcp_flags="S",
)

#: A DNAT-published internal database service.
DNAT_DATABASE_EXPOSURE = _event(
    "f1-dnat-1",
    src_ip="192.0.2.77",
    src_port=51551,
    dst_ip="198.51.100.44",
    dst_port=3306,
    action="pass",
    offset_seconds=40.0,
    packets=1,
    byte_count=52,
    tcp_flags="S",
    nat_type="dnat",
    translated_dst_ip="10.12.138.7",
    translated_dst_port=3306,
)


# ---------------------------------------------------------------------------
# Fixed-source-port scanning: constant source port 443, TCP SYN, one /24.
# ---------------------------------------------------------------------------


def _fixed_source_port_events(
    prefix: str,
    source: str,
    destinations: tuple[str, ...],
    ports: tuple[int, ...],
    *,
    action: str,
    start_offset: float,
    step: float,
    packets: int = 1,
    tcp_flags: Optional[str] = "S",
) -> tuple[CanonicalLogEvent, ...]:
    events = []
    for index, port in enumerate(ports):
        events.append(
            _event(
                f"{prefix}-{index + 1}",
                src_ip=source,
                src_port=FIXED_SOURCE_PORT,
                dst_ip=destinations[index % len(destinations)],
                dst_port=port,
                action=action,
                offset_seconds=start_offset + index * step,
                packets=packets,
                tcp_flags=tcp_flags,
            )
        )
    return tuple(events)


#: 7 allowed events, 7 distinct destination ports, one destination host.
#: Meets the canonical exact-source threshold on its own.
FSP_CANONICAL_A = _fixed_source_port_events(
    "f0-fsp-a",
    FSP_SOURCE_CANONICAL_A,
    ("198.51.100.185",),
    (22, 53, 80, 179, 443, 3306, 3389),
    action="pass",
    start_offset=108.123,
    step=0.026,
    packets=2,
)

#: 5 allowed events across 5 destination ports, but the capture recorded no
#: TCP flags for them. Without an observed SYN this is not a confirmed initial
#: connection probe, so it must not be reported as a fixed-source-port scan.
FSP_NO_FLAGS = _fixed_source_port_events(
    "f0-fsp-b",
    FSP_SOURCE_NO_FLAGS,
    ("198.51.100.83",),
    (22, 25, 80, 179, 3389),
    action="pass",
    start_offset=107.556,
    step=0.002,
    tcp_flags=None,
)

#: 3 allowed events - below the canonical exact-source threshold.
FSP_CLUSTER_A = _fixed_source_port_events(
    "f1-fsp-a",
    FSP_SOURCE_CLUSTER_A,
    ("198.51.100.14",),
    (443, 3306, 3389),
    action="pass",
    start_offset=23.099,
    step=0.027,
)

#: 4 allowed events - also below the canonical threshold. Together with
#: FSP_CLUSTER_A this forms one 7-event presentation cluster.
FSP_CLUSTER_B = _fixed_source_port_events(
    "f1-fsp-b",
    FSP_SOURCE_CLUSTER_B,
    ("198.51.100.135",),
    (22, 80, 179, 3306),
    action="pass",
    start_offset=23.021,
    step=0.006,
)

#: 4 blocked events roughly two minutes later - a disjoint window that must
#: stay separate from the allowed cluster.
FSP_BLOCKED = _fixed_source_port_events(
    "f1-fsp-blocked",
    FSP_SOURCE_BLOCKED,
    ("198.51.100.9", "198.51.100.245"),
    (25, 123, 25, 123),
    action="block",
    start_offset=135.648,
    step=0.349,
    packets=2,
)


FILE0_EVENTS = (
    *SSH_SWEEP_FILE0,
    DOCKER_EXPOSURE,
    REDIS_EXPOSURE_SINGLE_SYN,
    *FSP_CANONICAL_A,
    *FSP_NO_FLAGS,
)

FILE1_EVENTS = (
    *SSH_SWEEP_PORT_22,
    *SSH_SWEEP_PORT_22022,
    REDIS_EXPOSURE_MULTI_PACKET,
    DNAT_DATABASE_EXPOSURE,
    *FSP_CLUSTER_A,
    *FSP_CLUSTER_B,
    *FSP_BLOCKED,
)
