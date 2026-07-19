from datetime import datetime
from typing import List, Sequence, Tuple, Dict, Any
from collections import defaultdict, deque
from agent.schema import CanonicalLogEvent
from agent.detection.models import DetectionSignal, generate_signal_id
from agent.detection.detectors.base import BaseDetectionRule, DetectionContext
from agent.detection.evidence import select_representative_evidence
from agent.detection.correlation import sliding_window_scan
from agent.detection.scoring import calculate_signal_confidence
from agent.detection.contracts import DetectionRuleMetadata

class VerticalScanRule(BaseDetectionRule):
    metadata = DetectionRuleMetadata(
        rule_id="network_scan_vertical",
        version="1.0.0",
        name="Vertical Port Scan",
        family="network_scanning",
        priority=100,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip"),
        signal_type="vertical_scan",
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
                    syn_count = sum(1 for e in window if getattr(e, "tcp_flags", None) == "SYN")
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

        return signals
