from collections import defaultdict
from collections.abc import Sequence

from agent.detection.contracts import DetectionRuleMetadata
from agent.detection.detectors.base import BaseDetectionRule, DetectionContext
from agent.detection.detectors.scan_helpers import (
    bounded_sorted_values,
    classify_service,
    is_allowed,
    is_blocked,
    parse_ip_address,
)
from agent.detection.evidence import (
    create_evidence_from_event,
    select_representative_evidence,
)
from agent.detection.models import DetectionSignal, generate_signal_id
from agent.detection.scoring import calculate_signal_confidence
from agent.schema import CanonicalLogEvent


class ScanFollowedByAllowedConnectionRule(BaseDetectionRule):
    metadata = DetectionRuleMetadata(
        rule_id="scan_followed_by_allowed_connection",
        version="1.0.0",
        name="Scan Followed by Allowed Connection",
        family="network_intrusion_candidate",
        priority=40,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "dst_port", "action"),
        signal_type="scan_followed_by_allowed_connection",
        default_severity="high",
        mitre_techniques=("T1046",),
        window_setting="SCAN_THEN_ALLOWED_WINDOW_SECONDS",
        minimum_events_setting="SCAN_THEN_ALLOWED_MIN_BLOCKED_EVENTS",
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
                event.src_ip
                and event.dst_ip
                and parse_ip_address(event.src_ip) is not None
                and parse_ip_address(event.dst_ip) is not None
            ):
                groups[event.src_ip].append(event)

        signals: list[DetectionSignal] = []
        for src_ip, grouped_events in groups.items():
            ordered_events = sorted(
                grouped_events,
                key=lambda event: (
                    event.timestamp or context.analysis_started_at,
                    event.event_id,
                ),
            )
            for allowed_index, allowed_event in enumerate(ordered_events):
                if not is_allowed(allowed_event) or allowed_event.timestamp is None:
                    continue
                blocked_events = [
                    event
                    for event in ordered_events[:allowed_index]
                    if is_blocked(event)
                    and event.timestamp is not None
                    and 0
                    <= (allowed_event.timestamp - event.timestamp).total_seconds()
                    <= settings.SCAN_THEN_ALLOWED_WINDOW_SECONDS
                ]
                if len(blocked_events) < settings.SCAN_THEN_ALLOWED_MIN_BLOCKED_EVENTS:
                    continue
                distinct_targets = {
                    event.dst_ip for event in blocked_events if event.dst_ip is not None
                }
                distinct_ports = {
                    event.dst_port
                    for event in blocked_events
                    if event.dst_port is not None
                }
                has_target_diversity = (
                    len(distinct_targets)
                    >= settings.SCAN_THEN_ALLOWED_MIN_DISTINCT_TARGETS
                )
                has_port_diversity = (
                    len(distinct_ports) >= settings.SCAN_THEN_ALLOWED_MIN_DISTINCT_PORTS
                )
                if not (has_target_diversity or has_port_diversity):
                    continue
                allowed_service = classify_service(allowed_event.dst_port)
                has_related_block = any(
                    event.dst_ip == allowed_event.dst_ip
                    and (
                        event.dst_port == allowed_event.dst_port
                        or (
                            allowed_service is not None
                            and classify_service(event.dst_port) == allowed_service
                        )
                    )
                    for event in blocked_events
                )
                if not has_related_block:
                    continue

                first_seen = blocked_events[0].timestamp or context.analysis_started_at
                last_seen = allowed_event.timestamp
                event_ids = [event.event_id for event in blocked_events]
                event_ids.append(allowed_event.event_id)
                metrics: dict[str, int | float | str | bool] = {
                    "blocked_event_count": len(blocked_events),
                    "distinct_targets": len(distinct_targets),
                    "distinct_ports": len(distinct_ports),
                    "allowed_event_id": allowed_event.event_id,
                    "allowed_destination": allowed_event.dst_ip or "unknown",
                    "allowed_destination_port": (
                        allowed_event.dst_port
                        if allowed_event.dst_port is not None
                        else 0
                    ),
                    "time_to_allowed_seconds": max(
                        0.0, (last_seen - first_seen).total_seconds()
                    ),
                }
                evidence = select_representative_evidence(
                    blocked_events,
                    max_evidence=2,
                    reason="Representative blocked scan activity before an allowed connection",
                    source_rule=self.rule_id,
                    correlation_context=metrics,
                )
                evidence.append(
                    create_evidence_from_event(
                        allowed_event,
                        reason="Allowed connection after related blocked scan activity",
                        source_rule=self.rule_id,
                        correlation_context=metrics,
                    )
                )
                signal_id = generate_signal_id(
                    self.rule_id,
                    self.version,
                    src_ip,
                    f"allowed_{allowed_event.dst_ip}_{allowed_event.dst_port}",
                    first_seen,
                    event_ids,
                )
                targets = bounded_sorted_values(
                    [
                        *(
                            event.dst_ip
                            for event in blocked_events
                            if event.dst_ip is not None
                        ),
                        allowed_event.dst_ip or "unknown",
                    ]
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
                            len(blocked_events),
                            settings.SCAN_THEN_ALLOWED_MIN_BLOCKED_EVENTS,
                            base_confidence=0.8,
                            max_confidence=0.95,
                        ),
                        first_seen=first_seen,
                        last_seen=last_seen,
                        event_ids=event_ids,
                        primary_entity=src_ip,
                        target_entities=targets,
                        metrics=metrics,
                        evidence=evidence,
                        mitre_techniques=list(self.metadata.mitre_techniques),
                        tags=["network", "scan", "sequence", "allowed_after_block"],
                    )
                )
        return signals
