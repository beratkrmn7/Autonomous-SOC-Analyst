from collections import defaultdict, deque
from collections.abc import Sequence
from typing import Any

from agent.detection.contracts import DetectionRuleMetadata
from agent.detection.correlation import sliding_window_scan
from agent.detection.detectors.base import BaseDetectionRule, DetectionContext
from agent.detection.detectors.scan_helpers import (
    bounded_sorted_values,
    destination_subnet,
    event_ratios,
    normalized_protocol,
    parse_ip_address,
)
from agent.detection.evidence import select_representative_evidence
from agent.detection.models import DetectionSignal, generate_signal_id
from agent.detection.scoring import calculate_signal_confidence
from agent.schema import CanonicalLogEvent


class SubnetSweepRule(BaseDetectionRule):
    metadata = DetectionRuleMetadata(
        rule_id="subnet_sweep",
        version="1.0.0",
        name="Subnet Sweep",
        family="network_scanning",
        priority=90,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "dst_port"),
        signal_type="subnet_sweep",
        default_severity="medium",
        mitre_techniques=("T1046",),
        window_setting="SUBNET_SWEEP_WINDOW_SECONDS",
        minimum_events_setting="SUBNET_SWEEP_MIN_EVENTS",
    )

    def evaluate(
        self,
        events: Sequence[CanonicalLogEvent],
        context: DetectionContext,
    ) -> list[DetectionSignal]:
        settings = context.settings
        groups: dict[tuple[str, str, int, str], list[CanonicalLogEvent]] = defaultdict(
            list
        )
        for event in events:
            if (
                event.src_ip is None
                or event.dst_port is None
                or parse_ip_address(event.src_ip) is None
            ):
                continue
            network = destination_subnet(
                event.dst_ip,
                settings.SUBNET_SWEEP_IPV4_PREFIX,
                settings.SUBNET_SWEEP_IPV6_PREFIX,
            )
            if network is None:
                continue
            groups[
                (event.src_ip, network, event.dst_port, normalized_protocol(event))
            ].append(event)

        signals: list[DetectionSignal] = []
        for (src_ip, network, dst_port, protocol), grouped_events in groups.items():
            if len(grouped_events) < settings.SUBNET_SWEEP_MIN_EVENTS:
                continue

            def matches(window: deque[CanonicalLogEvent]) -> tuple[bool, dict[str, Any]]:
                window_events = list(window)
                if len(window_events) < settings.SUBNET_SWEEP_MIN_EVENTS:
                    return False, {}
                distinct_targets = {event.dst_ip for event in window_events if event.dst_ip}
                if len(distinct_targets) < settings.SUBNET_SWEEP_MIN_DISTINCT_TARGETS:
                    return False, {}
                block_ratio, syn_ratio = event_ratios(window_events)
                if block_ratio < settings.SUBNET_SWEEP_MIN_BLOCK_RATIO:
                    return False, {}
                if protocol == "TCP" and syn_ratio < settings.SUBNET_SWEEP_MIN_SYN_RATIO:
                    return False, {}
                return True, {
                    "destination_subnet": network,
                    "event_count": len(window_events),
                    "distinct_targets": len(distinct_targets),
                    "destination_port": dst_port,
                    "block_ratio": block_ratio,
                    "syn_ratio": syn_ratio,
                }

            matches_found = sliding_window_scan(
                grouped_events,
                settings.SUBNET_SWEEP_WINDOW_SECONDS,
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
                    f"subnet_{network}_{dst_port}_{protocol}",
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
                            settings.SUBNET_SWEEP_MIN_EVENTS,
                            base_confidence=0.65,
                            max_confidence=0.9,
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
                            reason=f"Subnet sweep detected in {network}",
                            source_rule=self.rule_id,
                            correlation_context=metrics,
                        ),
                        mitre_techniques=list(self.metadata.mitre_techniques),
                        tags=["network", "scan", "subnet_sweep"],
                    )
                )
        return signals
