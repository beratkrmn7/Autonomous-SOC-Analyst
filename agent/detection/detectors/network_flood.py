from datetime import datetime
from typing import List, Sequence, Tuple, Dict, Any
from collections import defaultdict, deque
from agent.schema import CanonicalLogEvent
from agent.detection.models import DetectionSignal, generate_signal_id
from agent.detection.detectors.base import BaseDetectionRule, DetectionContext
from agent.detection.evidence import select_representative_evidence
from agent.detection.correlation import sliding_window_scan
from agent.detection.scoring import calculate_signal_confidence

class NetworkFloodRule(BaseDetectionRule):
    rule_id = "network_flood_dos"
    version = "1.0.0"
    name = "Network Flood (DoS) Attempt"
    family = "network_dos"
    priority = 100

    def evaluate(self, events: Sequence[CanonicalLogEvent], context: DetectionContext) -> List[DetectionSignal]:
        settings = context.settings
        
        # We group by (src_ip, dst_ip) for flood to target
        groups = defaultdict(list)
        for e in events:
            if not e.src_ip or not e.dst_ip:
                continue
            groups[(e.src_ip, e.dst_ip)].append(e)

        signals = []
        for (src_ip, dst_ip), evs in groups.items():
            if len(evs) < settings.NETWORK_FLOOD_MIN_EVENTS:
                continue
                
            def check_window(window: deque) -> Tuple[bool, Dict[str, Any]]:
                if len(window) < settings.NETWORK_FLOOD_MIN_EVENTS:
                    return False, {}
                    
                blocks = sum(1 for e in window if str(e.action).lower() in ["block", "deny", "drop"])
                block_ratio = blocks / len(window)
                if block_ratio < settings.NETWORK_FLOOD_MIN_BLOCK_RATIO:
                    return False, {}
                    
                distinct_ports = set(e.dst_port for e in window if e.dst_port is not None)
                
                return True, {
                    "block_ratio": block_ratio,
                    "event_count": len(window),
                    "distinct_ports": len(distinct_ports),
                    "eps": len(window) / max(1, settings.NETWORK_FLOOD_WINDOW_SECONDS)
                }

            matches = sliding_window_scan(evs, settings.NETWORK_FLOOD_WINDOW_SECONDS, check_window)
            
            for match_events, match_context in matches:
                event_ids = [e.event_id for e in match_events]
                first_seen = match_events[0].timestamp or datetime.now()
                last_seen = match_events[-1].timestamp or datetime.now()
                
                sig_id = generate_signal_id(self.rule_id, self.version, src_ip, f"target_{dst_ip}", first_seen, event_ids)
                
                evidence = select_representative_evidence(
                    match_events, 
                    max_evidence=3, 
                    reason=f"High volume blocked traffic targeting {dst_ip}", 
                    source_rule=self.rule_id,
                    correlation_context=match_context
                )
                
                confidence = calculate_signal_confidence(
                    match_context["event_count"], 
                    settings.NETWORK_FLOOD_MIN_EVENTS,
                    base_confidence=0.7,
                    max_confidence=0.9
                )
                
                signal = DetectionSignal(
                    signal_id=sig_id,
                    rule_id=self.rule_id,
                    rule_version=self.version,
                    rule_name=self.name,
                    signal_type="network_flood",
                    signal_family=self.family,
                    severity="high",
                    confidence=confidence,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    event_ids=event_ids,
                    primary_entity=src_ip,
                    target_entities=[dst_ip],
                    metrics=match_context,
                    evidence=evidence,
                    mitre_techniques=["T1498"], # Network Denial of Service
                    tags=["network", "dos", "flood"]
                )
                signals.append(signal)

        return signals
