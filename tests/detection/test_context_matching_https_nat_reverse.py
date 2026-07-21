"""Focused tests for bidirectional/NAT-aware event relatedness.

A reverse HTTPS/NAT flow must be recognized as related even when the
client-side ephemeral port differs between the two log entries, but a single
shared IP alone must never be enough.
"""

from agent.detection.context_matching import events_are_bidirectionally_related
from tests.detection.helpers import build_event


def test_https_reverse_flow_with_different_ephemeral_ports_is_related() -> None:
    reference = build_event(
        "spi-response",
        src_ip="203.0.113.5",
        src_port=443,
        dst_ip="192.0.2.10",
        dst_port=51000,
        protocol="TCP",
        action="block",
        tcp_flags="ACK,RST",
    )
    candidate = build_event(
        "allowed-request",
        src_ip="192.0.2.10",
        src_port=52222,
        dst_ip="203.0.113.5",
        dst_port=443,
        protocol="TCP",
        action="allow",
        tcp_flags="SYN",
    )

    assert events_are_bidirectionally_related(reference, candidate) is True


def test_events_sharing_only_one_ip_are_not_related() -> None:
    reference = build_event(
        "ref",
        src_ip="192.0.2.10",
        src_port=51000,
        dst_ip="198.51.100.20",
        dst_port=443,
    )
    candidate = build_event(
        "cand",
        src_ip="192.0.2.10",
        src_port=61234,
        dst_ip="203.0.113.99",
        dst_port=8080,
    )

    assert events_are_bidirectionally_related(reference, candidate) is False


def test_cross_protocol_reverse_flow_is_not_related() -> None:
    reference = build_event(
        "spi-response",
        src_ip="203.0.113.5",
        src_port=443,
        dst_ip="192.0.2.10",
        dst_port=51000,
        protocol="TCP",
        action="block",
        tcp_flags="ACK,RST",
    )
    candidate = build_event(
        "allowed-udp",
        src_ip="192.0.2.10",
        src_port=52222,
        dst_ip="203.0.113.5",
        dst_port=443,
        protocol="UDP",
        action="allow",
    )

    assert events_are_bidirectionally_related(reference, candidate) is False


def test_reverse_endpoints_sharing_only_an_ephemeral_port_are_not_related() -> None:
    reference = build_event(
        "ref",
        src_ip="203.0.113.5",
        src_port=51000,
        dst_ip="192.0.2.10",
        dst_port=443,
        protocol="TCP",
    )
    candidate = build_event(
        "cand",
        src_ip="192.0.2.10",
        src_port=8080,
        dst_ip="203.0.113.5",
        dst_port=51000,
        protocol="TCP",
    )

    assert events_are_bidirectionally_related(reference, candidate) is False
