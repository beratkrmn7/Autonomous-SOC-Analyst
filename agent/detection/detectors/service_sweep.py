from collections import defaultdict, deque
from collections.abc import Sequence
from typing import Any

from agent.detection.contracts import DetectionRuleMetadata
from agent.detection.correlation import sliding_window_scan
from agent.detection.detectors.base import BaseDetectionRule, DetectionContext
from agent.detection.detectors.scan_helpers import (
    bounded_sorted_values,
    classify_service,
    event_ratios,
    is_allowed,
    is_private_unicast,
    normalized_protocol,
    parse_ip_address,
)
from agent.detection.evidence import select_representative_evidence
from agent.detection.models import DetectionSignal, generate_signal_id
from agent.detection.scoring import calculate_signal_confidence
from agent.schema import CanonicalLogEvent


class InternalLateralScanRule(BaseDetectionRule):
    metadata = DetectionRuleMetadata(
        rule_id="internal_lateral_scan",
        version="1.0.0",
        name="Internal Lateral Scan",
        family="lateral_movement_candidate",
        priority=60,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "dst_port"),
        signal_type="internal_lateral_scan",
        default_severity="high",
        mitre_techniques=("T1046",),
        window_setting="INTERNAL_LATERAL_SCAN_WINDOW_SECONDS",
        minimum_events_setting="INTERNAL_LATERAL_SCAN_MIN_EVENTS",
    )

    def evaluate(
        self,
        events: Sequence[CanonicalLogEvent],
        context: DetectionContext,
    ) -> list[DetectionSignal]:
        settings = context.settings
        sensitive_ports = set(settings.INTERNAL_LATERAL_SCAN_PORTS)
        groups: dict[str, list[CanonicalLogEvent]] = defaultdict(list)
        for event in events:
            if (
                not is_private_unicast(event.src_ip)
                or not is_private_unicast(event.dst_ip)
                or event.dst_port not in sensitive_ports
                or normalized_protocol(event) != "TCP"
            ):
                continue
            if parse_ip_address(event.src_ip) == parse_ip_address(event.dst_ip):
                continue
            if event.src_ip:
                groups[event.src_ip].append(event)

        signals: list[DetectionSignal] = []
        for src_ip, grouped_events in groups.items():
            if len(grouped_events) < settings.INTERNAL_LATERAL_SCAN_MIN_EVENTS:
                continue

            def matches(window: deque[CanonicalLogEvent]) -> tuple[bool, dict[str, Any]]:
                window_events = list(window)
                if len(window_events) < settings.INTERNAL_LATERAL_SCAN_MIN_EVENTS:
                    return False, {}
                distinct_targets = {event.dst_ip for event in window_events if event.dst_ip}
                if len(distinct_targets) < settings.INTERNAL_LATERAL_SCAN_MIN_DISTINCT_TARGETS:
                    return False, {}
                block_ratio, syn_ratio = event_ratios(window_events)
                if block_ratio < settings.INTERNAL_LATERAL_SCAN_MIN_BLOCK_RATIO:
                    return False, {}
                if syn_ratio < settings.INTERNAL_LATERAL_SCAN_MIN_SYN_RATIO:
                    return False, {}
                services = {
                    classify_service(event.dst_port) or f"port_{event.dst_port}"
                    for event in window_events
                }
                return True, {
                    "event_count": len(window_events),
                    "distinct_targets": len(distinct_targets),
                    "distinct_services": len(services),
                    "block_ratio": block_ratio,
                    "syn_ratio": syn_ratio,
                    "allowed_events": sum(
                        1 for event in window_events if is_allowed(event)
                    ),
                }

            matches_found = sliding_window_scan(
                grouped_events,
                settings.INTERNAL_LATERAL_SCAN_WINDOW_SECONDS,
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
                    "private_admin_services",
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
                            settings.INTERNAL_LATERAL_SCAN_MIN_EVENTS,
                            base_confidence=0.75,
                            max_confidence=0.95,
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
                            reason="Private source scanning internal administrative services",
                            source_rule=self.rule_id,
                            correlation_context=metrics,
                        ),
                        mitre_techniques=list(self.metadata.mitre_techniques),
                        tags=["network", "scan", "internal", "lateral_candidate"],
                    )
                )
        return signals


class MultiServiceSweepRule(BaseDetectionRule):
    metadata = DetectionRuleMetadata(
        rule_id="multi_service_sweep",
        version="1.0.0",
        name="Multi-Service Sweep",
        family="service_probing",
        priority=80,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "dst_port", "protocol"),
        signal_type="multi_service_sweep",
        default_severity="high",
        mitre_techniques=("T1046",),
        window_setting="MULTI_SERVICE_SWEEP_WINDOW_SECONDS",
        minimum_events_setting="MULTI_SERVICE_SWEEP_MIN_EVENTS",
    )

    def evaluate(
        self,
        events: Sequence[CanonicalLogEvent],
        context: DetectionContext,
    ) -> list[DetectionSignal]:
        settings = context.settings
        groups: dict[str, list[CanonicalLogEvent]] = defaultdict(list)
        for event in events:
            if (
                not event.src_ip
                or not event.dst_ip
                or parse_ip_address(event.src_ip) is None
                or parse_ip_address(event.dst_ip) is None
                or normalized_protocol(event) != "TCP"
                or classify_service(event.dst_port) is None
            ):
                continue
            groups[event.src_ip].append(event)

        signals: list[DetectionSignal] = []
        for src_ip, grouped_events in groups.items():
            if len(grouped_events) < settings.MULTI_SERVICE_SWEEP_MIN_EVENTS:
                continue

            def matches(window: deque[CanonicalLogEvent]) -> tuple[bool, dict[str, Any]]:
                window_events = list(window)
                if len(window_events) < settings.MULTI_SERVICE_SWEEP_MIN_EVENTS:
                    return False, {}
                services = sorted(
                    {
                        service
                        for event in window_events
                        if (service := classify_service(event.dst_port)) is not None
                    }
                )
                distinct_targets = {event.dst_ip for event in window_events if event.dst_ip}
                if len(services) < settings.MULTI_SERVICE_SWEEP_MIN_DISTINCT_SERVICES:
                    return False, {}
                if len(distinct_targets) < settings.MULTI_SERVICE_SWEEP_MIN_DISTINCT_TARGETS:
                    return False, {}
                block_ratio, syn_ratio = event_ratios(window_events)
                if block_ratio < settings.MULTI_SERVICE_SWEEP_MIN_BLOCK_RATIO:
                    return False, {}
                if syn_ratio < settings.MULTI_SERVICE_SWEEP_MIN_SYN_RATIO:
                    return False, {}
                return True, {
                    "event_count": len(window_events),
                    "distinct_targets": len(distinct_targets),
                    "distinct_services": len(services),
                    "services": ",".join(services[:10]),
                    "block_ratio": block_ratio,
                    "syn_ratio": syn_ratio,
                }

            matches_found = sliding_window_scan(
                grouped_events,
                settings.MULTI_SERVICE_SWEEP_WINDOW_SECONDS,
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
                    "multi_service",
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
                            settings.MULTI_SERVICE_SWEEP_MIN_EVENTS,
                            base_confidence=0.75,
                            max_confidence=0.95,
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
                            reason="Correlated probing across multiple sensitive services",
                            source_rule=self.rule_id,
                            correlation_context=metrics,
                        ),
                        mitre_techniques=list(self.metadata.mitre_techniques),
                        tags=["network", "scan", "service_probe", "multi_service"],
                    )
                )
        return signals
