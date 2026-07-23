from datetime import datetime
from typing import List, Sequence, Tuple, Dict, Any
from collections import defaultdict, deque
from agent.schema import CanonicalLogEvent
from agent.detection.models import DetectionSignal, SeverityType, generate_signal_id
from agent.detection.detectors.base import BaseDetectionRule, DetectionContext
from agent.detection.evidence import select_representative_evidence
from agent.detection.correlation import sliding_window_scan
from agent.detection.scoring import calculate_signal_confidence
from agent.detection.contracts import DetectionRuleMetadata, DetectionSignalVariant
from agent.detection.detectors.exposure_helpers import (
    is_explicit_wan_zone,
    sensitive_service_for_port,
)
from agent.detection.detectors.scan_helpers import (
    find_fixed_source_port_groups,
    is_tcp_syn,
)

# Deterministic ATT&CK mapping for service enumeration. Technique and tactic
# are always separate values; TA0007 must never appear in a techniques list.
FIXED_SOURCE_PORT_TECHNIQUE = "T1046"
FIXED_SOURCE_PORT_TACTIC = "TA0007"

#: Bound on ports rendered into the scalar metrics strings.
MAX_METRIC_PORTS = 15

class VerticalScanRule(BaseDetectionRule):
    metadata = DetectionRuleMetadata(
        rule_id="network_scan_vertical",
        # 1.1.0: the rule now emits a second declared signal identity, the
        # fixed-source-port variant, so its emitted contract changed.
        version="1.1.0",
        name="Vertical Port Scan",
        family="network_scanning",
        priority=100,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip"),
        signal_type="vertical_scan",
        signal_variants=(
            DetectionSignalVariant(
                rule_id="network_scan_vertical",
                rule_name="Vertical Port Scan",
                signal_type="vertical_scan",
            ),
            DetectionSignalVariant(
                rule_id="network_scan_vertical",
                rule_name="Vertical Port Scan",
                signal_type="fixed_source_port_scan",
            ),
        ),
        default_severity="medium",
        mitre_techniques=("T1046",),
        window_setting="VERTICAL_SCAN_WINDOW_SECONDS",
        minimum_events_setting="VERTICAL_SCAN_MIN_EVENTS",
    )

    def evaluate(self, events: Sequence[CanonicalLogEvent], context: DetectionContext) -> List[DetectionSignal]:
        settings = context.settings
        
        # Group by (src_ip, dst_ip, protocol)
        groups = defaultdict(list)
        for e in events:
            if not e.src_ip or not e.dst_ip:
                continue
            protocol = getattr(e, 'protocol', None)
            if not protocol:
                protocol = "UNKNOWN"
            groups[(e.src_ip, e.dst_ip, protocol)].append(e)

        signals = []
        for (src_ip, dst_ip, protocol), evs in groups.items():
            if len(evs) < settings.VERTICAL_SCAN_MIN_EVENTS:
                continue
                
            def check_window(window: deque) -> Tuple[bool, Dict[str, Any]]:
                if len(window) < settings.VERTICAL_SCAN_MIN_EVENTS:
                    return False, {}
                    
                distinct_ports = set(e.dst_port for e in window if e.dst_port)
                if len(distinct_ports) < settings.VERTICAL_SCAN_MIN_DISTINCT_PORTS:
                    return False, {}
                    
                blocks = sum(1 for e in window if str(e.action).lower() in ["block", "deny", "drop"])
                block_ratio = blocks / len(window)
                if block_ratio < settings.VERTICAL_SCAN_MIN_BLOCK_RATIO:
                    return False, {}
                    
                if str(protocol).upper() == "TCP":
                    syn_count = sum(1 for e in window if is_tcp_syn(e))
                    if syn_count / len(window) < settings.VERTICAL_SCAN_MIN_SYN_RATIO:
                        return False, {}
                        
                return True, {
                    "distinct_ports": len(distinct_ports),
                    "block_ratio": block_ratio,
                    "event_count": len(window),
                    "target": dst_ip,
                    "protocol": protocol
                }

            matches = sliding_window_scan(evs, settings.VERTICAL_SCAN_WINDOW_SECONDS, check_window)
            
            for match_events, match_context in matches:
                event_ids = [e.event_id for e in match_events]
                first_seen = match_events[0].timestamp or datetime.now()
                last_seen = match_events[-1].timestamp or datetime.now()
                
                sig_id = generate_signal_id(self.rule_id, self.version, src_ip, f"target_{dst_ip}_{protocol}", first_seen, event_ids)
                
                evidence = select_representative_evidence(
                    match_events, 
                    max_evidence=3, 
                    reason=f"Vertical scan detected targeting {dst_ip}", 
                    source_rule=self.rule_id,
                    correlation_context=match_context
                )
                
                confidence = calculate_signal_confidence(
                    match_context["event_count"], 
                    settings.VERTICAL_SCAN_MIN_EVENTS,
                    base_confidence=0.6,
                    max_confidence=0.9
                )
                
                signal = DetectionSignal(
                    signal_id=sig_id,
                    rule_id=self.rule_id,
                    rule_version=self.version,
                    rule_name=self.name,
                    signal_type="vertical_scan",
                    signal_family=self.family,
                    severity="high" if match_context["distinct_ports"] > settings.VERTICAL_SCAN_MIN_DISTINCT_PORTS * 2 else "medium",
                    confidence=confidence,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    event_ids=event_ids,
                    primary_entity=src_ip,
                    target_entities=[dst_ip],
                    metrics=match_context,
                    evidence=evidence,
                    mitre_techniques=["T1046"],
                    tags=["network", "scan", "vertical"]
                )
                signals.append(signal)

        signals.extend(self._evaluate_fixed_source_port(events, context))
        return signals

    def _evaluate_fixed_source_port(
        self,
        events: Sequence[CanonicalLogEvent],
        context: DetectionContext,
    ) -> List[DetectionSignal]:
        """Emit the fixed-source-port variant of this rule.

        A constant, service-looking source port across a short burst of TCP
        SYNs to several destination ports is service enumeration disguised as
        return traffic. It is reported as a signal variant of the existing
        vertical scan rule so the registered rule count does not change.

        Severity follows the documented scan policy: fully blocked activity
        stays low/medium, allowed activity against ordinary ports is medium,
        and allowed activity reaching a sensitive or critical-management
        service is high. A firewall pass proves policy exposure, never
        compromise.
        """
        settings = context.settings
        if not getattr(settings, "FIXED_SOURCE_PORT_SCAN_ENABLED", False):
            return []

        groups = find_fixed_source_port_groups(
            events,
            source_ports=settings.FIXED_SOURCE_PORT_SCAN_PORTS,
            min_events=settings.FIXED_SOURCE_PORT_SCAN_MIN_EVENTS,
            min_distinct_destination_ports=(
                settings.FIXED_SOURCE_PORT_SCAN_MIN_DISTINCT_PORTS
            ),
            window_seconds=settings.FIXED_SOURCE_PORT_SCAN_WINDOW_SECONDS,
            is_external_inbound=lambda event: is_explicit_wan_zone(event.inbound_zone),
        )

        signals: List[DetectionSignal] = []
        for group in groups:
            event_ids = [event.event_id for event in group.events]
            sensitive_ports = sorted(
                port
                for port in group.destination_ports
                if sensitive_service_for_port(port) is not None
            )
            severity: SeverityType
            if group.allowed_event_count == 0:
                severity = "low" if group.event_count < 10 else "medium"
            elif sensitive_ports:
                severity = "high"
            else:
                severity = "medium"

            # DetectionSignal.metrics holds scalars only, so bounded port
            # lists are rendered as compact comma-separated strings.
            metrics: Dict[str, Any] = {
                "variant": "fixed_source_port_scan",
                "fixed_source_port": group.source_port,
                "event_count": group.event_count,
                "allowed_event_count": group.allowed_event_count,
                "blocked_event_count": group.blocked_event_count,
                "distinct_destination_ports": len(group.destination_ports),
                "distinct_destination_ips": len(group.destination_ips),
                "destination_ports": ",".join(
                    str(port) for port in group.destination_ports[:MAX_METRIC_PORTS]
                ),
                "sensitive_destination_ports": ",".join(
                    str(port) for port in sensitive_ports[:MAX_METRIC_PORTS]
                ),
                # ATT&CK technique and tactic are kept in separate fields; the
                # tactic never enters a techniques collection.
                "mitre_tactic": FIXED_SOURCE_PORT_TACTIC,
            }

            sig_id = generate_signal_id(
                self.rule_id,
                self.version,
                group.source_ip,
                f"fixed_source_port_{group.source_port}",
                group.first_seen,
                event_ids,
            )
            evidence = select_representative_evidence(
                list(group.events),
                max_evidence=3,
                reason=(
                    f"Fixed source port {group.source_port} enumeration across "
                    f"{len(group.destination_ports)} destination port(s)"
                ),
                source_rule=self.rule_id,
                correlation_context=metrics,
            )
            confidence = calculate_signal_confidence(
                group.event_count,
                settings.FIXED_SOURCE_PORT_SCAN_MIN_EVENTS,
                base_confidence=0.6,
                max_confidence=0.9,
            )
            signals.append(
                DetectionSignal(
                    signal_id=sig_id,
                    rule_id=self.rule_id,
                    rule_version=self.version,
                    rule_name=self.name,
                    signal_type="fixed_source_port_scan",
                    signal_family=self.family,
                    severity=severity,
                    confidence=confidence,
                    first_seen=group.first_seen,
                    last_seen=group.last_seen,
                    event_ids=event_ids,
                    primary_entity=group.source_ip,
                    target_entities=list(group.destination_ips),
                    metrics=metrics,
                    evidence=evidence,
                    mitre_techniques=[FIXED_SOURCE_PORT_TECHNIQUE],
                    tags=["network", "scan", "fixed_source_port"],
                )
            )
        return signals
