from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from typing import List, Optional, Set, Tuple

from agent.detection.detectors.scan_helpers import is_blocked
from agent.detection.models import DetectionSignal
from agent.schema import CanonicalLogEvent
from agent.tcp_flags import parse_tcp_flag_tokens


LATE_RST_SERVICE_SOURCE_PORTS = frozenset({22, 53, 80, 443, 993, 995})
LATE_RST_MIN_EPHEMERAL_PORT = 32_768
LATE_RST_MIN_EVENTS = 2
LATE_RST_SUPPRESSION_REASON = "late_rst_from_established_service"
_RESET_FLAG_SETS = frozenset(
    {
        frozenset({"RST"}),
        frozenset({"RST", "ACK"}),
    }
)


def _is_explicit_spi_block(event: CanonicalLogEvent) -> bool:
    metadata = event.parser_metadata or {}
    original_action = str(metadata.get("original_device_action", "")).strip().casefold()
    canonical_action = str(event.action or "").strip().casefold()
    explicit_spi = bool(
        metadata.get("spi_anomaly") is True
        or original_action == "blocked by spi"
        or canonical_action == "blocked by spi"
    )
    return explicit_spi and (is_blocked(event) or canonical_action == "blocked by spi")


def _is_late_rst_spi_pattern(
    signal: DetectionSignal,
    event_lookup: Mapping[str, CanonicalLogEvent] | None,
) -> bool:
    if signal.signal_type != "spi_anomaly" or signal.rule_id != "spi_anomaly_burst":
        return False
    if not event_lookup or not signal.event_ids:
        return False
    events = [event_lookup.get(event_id) for event_id in signal.event_ids]
    if any(event is None for event in events):
        return False
    canonical_events = [event for event in events if event is not None]
    if len(canonical_events) < LATE_RST_MIN_EVENTS or not all(
        _is_explicit_spi_block(event) for event in canonical_events
    ):
        return False

    source_ports = {event.src_port for event in canonical_events}
    if len(source_ports) != 1 or next(iter(source_ports)) not in LATE_RST_SERVICE_SOURCE_PORTS:
        return False

    destination_ports = [event.dst_port for event in canonical_events]
    if any(
        port is None or port < LATE_RST_MIN_EPHEMERAL_PORT
        for port in destination_ports
    ):
        return False
    if len(set(destination_ports)) != len(destination_ports):
        return False

    destination_ips = {event.dst_ip for event in canonical_events if event.dst_ip}
    if len(destination_ips) != 1:
        return False

    return all(
        parse_tcp_flag_tokens(event.tcp_flags) in _RESET_FLAG_SETS
        for event in canonical_events
    )


class SuppressionPolicy:
    def __init__(self) -> None:
        self.allowed_sources: List[str] = []
        self.allowed_destinations: List[str] = []
        self.allowed_rules: Set[str] = set()
        self.allowed_ports: Set[int] = set()
        self.allowed_ip_pairs: List[Tuple[str, str]] = []

    def add_allowed_source(self, cidr: str) -> None:
        if cidr in {"0.0.0.0/0", "::/0"}:
            return
        self.allowed_sources.append(cidr)

    def add_allowed_destination(self, cidr: str) -> None:
        if cidr in {"0.0.0.0/0", "::/0"}:
            return
        self.allowed_destinations.append(cidr)

    def is_suppressed(
        self,
        signal: DetectionSignal,
        event_lookup: Mapping[str, CanonicalLogEvent] | None = None,
    ) -> Optional[str]:
        if _is_late_rst_spi_pattern(signal, event_lookup):
            return LATE_RST_SUPPRESSION_REASON

        if signal.rule_id in self.allowed_rules:
            return f"Rule {signal.rule_id} is globally allowed"

        src_ip = None
        if signal.primary_entity:
            try:
                src_ip = ipaddress.ip_address(signal.primary_entity)
            except ValueError:
                pass

        if src_ip:
            for allowed in self.allowed_sources:
                try:
                    if src_ip in ipaddress.ip_network(allowed, strict=False):
                        return f"Source {signal.primary_entity} is in allowed sources"
                except ValueError:
                    continue

        if signal.target_entities:
            for target in signal.target_entities:
                try:
                    dst_ip = ipaddress.ip_address(target)
                except ValueError:
                    continue

                for allowed in self.allowed_destinations:
                    try:
                        if dst_ip in ipaddress.ip_network(allowed, strict=False):
                            return f"Destination {target} is in allowed destinations"
                    except ValueError:
                        continue

                if src_ip:
                    for src_cidr, dst_cidr in self.allowed_ip_pairs:
                        try:
                            if src_ip in ipaddress.ip_network(
                                src_cidr, strict=False
                            ) and dst_ip in ipaddress.ip_network(dst_cidr, strict=False):
                                return (
                                    f"IP pair {signal.primary_entity} -> {target} is allowed"
                                )
                        except ValueError:
                            continue

        return None
