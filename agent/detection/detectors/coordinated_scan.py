from collections import defaultdict, deque
from collections.abc import Sequence
from typing import Any

from agent.detection.contracts import DetectionRuleMetadata
from agent.detection.correlation import sliding_window_scan
from agent.detection.detectors.base import BaseDetectionRule, DetectionContext
from agent.detection.detectors.scan_helpers import (
    bounded_sorted_values,
    event_ratios,
    is_blocked,
    is_spi_anomaly_event,
    is_tcp_initial_connection_probe,
    normalized_protocol,
    parse_ip_address,
)
from agent.detection.evidence import select_representative_evidence
from agent.detection.models import DetectionSignal, generate_signal_id
from agent.detection.scoring import calculate_signal_confidence
from agent.schema import CanonicalLogEvent


class RepeatedBlockedScannerRule(BaseDetectionRule):
    metadata = DetectionRuleMetadata(
        rule_id="repeated_blocked_scanner",
        version="1.1.0",
        name="Repeated Blocked Scanner",
        family="network_scanning",
        priority=110,
        supported_event_types=(),
        required_fields=("src_ip", "action"),
        signal_type="repeated_blocked_scanner",
        default_severity="low",
        mitre_techniques=("T1046",),
        window_setting="REPEATED_BLOCKED_SCANNER_WINDOW_SECONDS",
        minimum_events_setting="REPEATED_BLOCKED_SCANNER_MIN_EVENTS",
    )

    def evaluate(
        self,
        events: Sequence[CanonicalLogEvent],
        context: DetectionContext,
    ) -> list[DetectionSignal]:
        settings = context.settings
        groups: dict[tuple[str, str], list[CanonicalLogEvent]] = defaultdict(list)
        for event in events:
            if not (
                event.src_ip
                and parse_ip_address(event.src_ip) is not None
                and (event.dst_ip is None or parse_ip_address(event.dst_ip) is not None)
            ):
                continue
            if is_spi_anomaly_event(
                event, fallback_raw_match=settings.SPI_ANOMALY_FALLBACK_RAW_MATCH
            ):
                continue
            protocol = normalized_protocol(event)
            if protocol == "TCP" and not is_tcp_initial_connection_probe(event):
                continue
            groups[(event.src_ip, protocol)].append(event)

        signals: list[DetectionSignal] = []
        for (src_ip, protocol), grouped_events in groups.items():
            if len(grouped_events) < settings.REPEATED_BLOCKED_SCANNER_MIN_EVENTS:
                continue

            def matches(window: deque[CanonicalLogEvent]) -> tuple[bool, dict[str, Any]]:
                window_events = list(window)
                if len(window_events) < settings.REPEATED_BLOCKED_SCANNER_MIN_EVENTS:
                    return False, {}
                blocked_events = sum(1 for event in window_events if is_blocked(event))
                block_ratio = blocked_events / len(window_events)
                if block_ratio < settings.REPEATED_BLOCKED_SCANNER_MIN_BLOCK_RATIO:
                    return False, {}
                distinct_targets = {
                    event.dst_ip
                    for event in window_events
                    if event.dst_ip and parse_ip_address(event.dst_ip) is not None
                }
                distinct_ports = {
                    event.dst_port for event in window_events if event.dst_port is not None
                }
                has_target_diversity = (
                    len(distinct_targets)
                    >= settings.REPEATED_BLOCKED_SCANNER_MIN_DISTINCT_TARGETS
                )
                has_port_diversity = (
                    len(distinct_ports)
                    >= settings.REPEATED_BLOCKED_SCANNER_MIN_DISTINCT_PORTS
                )
                if not (has_target_diversity or has_port_diversity):
                    return False, {}
                return True, {
                    "event_count": len(window_events),
                    "blocked_events": blocked_events,
                    "block_ratio": block_ratio,
                    "distinct_targets": len(distinct_targets),
                    "distinct_ports": len(distinct_ports),
                }

            matches_found = sliding_window_scan(
                grouped_events,
                settings.REPEATED_BLOCKED_SCANNER_WINDOW_SECONDS,
                matches,
            )
            for match_events, metrics in matches_found:
                event_ids = [event.event_id for event in match_events]
                first_seen = match_events[0].timestamp or context.analysis_started_at
                last_seen = match_events[-1].timestamp or context.analysis_started_at
                signal_id = generate_signal_id(
                    self.rule_id,
                    self.version,
                    src_ip,
                    f"blocked_scanner_{protocol}",
                    first_seen,
                    event_ids,
                )
                signals.append(
                    DetectionSignal(
                        signal_id=signal_id,
                        rule_id=self.rule_id,
                        rule_version=self.version,
                        rule_name=self.name,
                        signal_type=self.metadata.signal_type,
                        signal_family=self.family,
                        severity=self.metadata.default_severity,
                        confidence=calculate_signal_confidence(
                            len(match_events),
                            settings.REPEATED_BLOCKED_SCANNER_MIN_EVENTS,
                            base_confidence=0.55,
                            max_confidence=0.8,
                        ),
                        first_seen=first_seen,
                        last_seen=last_seen,
                        event_ids=event_ids,
                        primary_entity=src_ip,
                        target_entities=bounded_sorted_values(
                            event.dst_ip for event in match_events if event.dst_ip
                        ),
                        metrics=metrics,
                        evidence=select_representative_evidence(
                            match_events,
                            max_evidence=3,
                            reason="Repeated blocked scanner-like activity",
                            source_rule=self.rule_id,
                            correlation_context=metrics,
                        ),
                        mitre_techniques=list(self.metadata.mitre_techniques),
                        tags=["network", "scan", "blocked"],
                    )
                )
        return signals


class DistributedScanRule(BaseDetectionRule):
    metadata = DetectionRuleMetadata(
        rule_id="distributed_scan",
        version="1.0.0",
        name="Distributed Scan",
        family="network_scanning",
        priority=70,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "dst_port"),
        signal_type="distributed_scan",
        default_severity="medium",
        mitre_techniques=("T1046",),
        window_setting="DISTRIBUTED_SCAN_WINDOW_SECONDS",
        minimum_events_setting="DISTRIBUTED_SCAN_MIN_EVENTS",
    )

    def evaluate(
        self,
        events: Sequence[CanonicalLogEvent],
        context: DetectionContext,
    ) -> list[DetectionSignal]:
        settings = context.settings
        groups: dict[tuple[str, int, str], list[CanonicalLogEvent]] = defaultdict(list)
        for event in events:
            if (
                event.src_ip is None
                or event.dst_ip is None
                or event.dst_port is None
                or parse_ip_address(event.src_ip) is None
                or parse_ip_address(event.dst_ip) is None
            ):
                continue
            groups[(event.dst_ip, event.dst_port, normalized_protocol(event))].append(event)

        signals: list[DetectionSignal] = []
        for (dst_ip, dst_port, protocol), grouped_events in groups.items():
            if len(grouped_events) < settings.DISTRIBUTED_SCAN_MIN_EVENTS:
                continue

            def matches(window: deque[CanonicalLogEvent]) -> tuple[bool, dict[str, Any]]:
                window_events = list(window)
                if len(window_events) < settings.DISTRIBUTED_SCAN_MIN_EVENTS:
                    return False, {}
                distinct_sources = {event.src_ip for event in window_events if event.src_ip}
                if len(distinct_sources) < settings.DISTRIBUTED_SCAN_MIN_DISTINCT_SOURCES:
                    return False, {}
                block_ratio, syn_ratio = event_ratios(window_events)
                required_block_ratio = settings.DISTRIBUTED_SCAN_MIN_BLOCK_RATIO
                required_syn_ratio = settings.DISTRIBUTED_SCAN_MIN_SYN_RATIO
                if dst_port in {80, 443}:
                    required_block_ratio = max(required_block_ratio, 0.9)
                    required_syn_ratio = max(required_syn_ratio, 0.8)
                if block_ratio < required_block_ratio:
                    return False, {}
                if protocol == "TCP" and syn_ratio < required_syn_ratio:
                    return False, {}
                return True, {
                    "event_count": len(window_events),
                    "distinct_sources": len(distinct_sources),
                    "destination_port": dst_port,
                    "block_ratio": block_ratio,
                    "syn_ratio": syn_ratio,
                }

            matches_found = sliding_window_scan(
                grouped_events,
                settings.DISTRIBUTED_SCAN_WINDOW_SECONDS,
                matches,
            )
            for match_events, metrics in matches_found:
                event_ids = [event.event_id for event in match_events]
                first_seen = match_events[0].timestamp or context.analysis_started_at
                last_seen = match_events[-1].timestamp or context.analysis_started_at
                signal_id = generate_signal_id(
                    self.rule_id,
                    self.version,
                    dst_ip,
                    f"service_{dst_port}_{protocol}",
                    first_seen,
                    event_ids,
                )
                signals.append(
                    DetectionSignal(
                        signal_id=signal_id,
                        rule_id=self.rule_id,
                        rule_version=self.version,
                        rule_name=self.name,
                        signal_type=self.metadata.signal_type,
                        signal_family=self.family,
                        severity=self.metadata.default_severity,
                        confidence=calculate_signal_confidence(
                            len(match_events),
                            settings.DISTRIBUTED_SCAN_MIN_EVENTS,
                            base_confidence=0.7,
                            max_confidence=0.9,
                        ),
                        first_seen=first_seen,
                        last_seen=last_seen,
                        event_ids=event_ids,
                        primary_entity=dst_ip,
                        target_entities=bounded_sorted_values(
                            event.src_ip for event in match_events if event.src_ip
                        ),
                        metrics=metrics,
                        evidence=select_representative_evidence(
                            match_events,
                            max_evidence=3,
                            reason=f"Distributed scan targeting {dst_ip}:{dst_port}",
                            source_rule=self.rule_id,
                            correlation_context=metrics,
                        ),
                        mitre_techniques=list(self.metadata.mitre_techniques),
                        tags=["network", "scan", "distributed"],
                    )
                )
        return signals
