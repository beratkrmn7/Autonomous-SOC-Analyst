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

class NetworkFloodRule(BaseDetectionRule):
    metadata = DetectionRuleMetadata(
        rule_id="network_flood_dos",
        version="1.0.0",
        name="Network Flood (DoS) Attempt",
        family="network_dos",
        priority=100,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip"),
        signal_type="network_flood",
        default_severity="high",
        mitre_techniques=("T1498",),
        window_setting="NETWORK_FLOOD_WINDOW_SECONDS",
        minimum_events_setting="NETWORK_FLOOD_MIN_EVENTS",
    )

    def evaluate(self, events: Sequence[CanonicalLogEvent], context: DetectionContext) -> List[DetectionSignal]:
        settings = context.settings
        
        # We group by (src_ip, dst_ip, dst_port, protocol) for flood to target
        groups = defaultdict(list)
        for e in events:
            if not e.src_ip or not e.dst_ip:
                continue
            protocol = getattr(e, 'protocol', "UNKNOWN") or "UNKNOWN"
            dst_port = e.dst_port if e.dst_port is not None else 0
            groups[(e.src_ip, e.dst_ip, dst_port, protocol)].append(e)

        signals = []
        for (src_ip, dst_ip, dst_port, protocol), evs in groups.items():
            if len(evs) < settings.NETWORK_FLOOD_MIN_EVENTS:
                continue
                
            def check_window(window: deque) -> Tuple[bool, Dict[str, Any]]:
                if len(window) < settings.NETWORK_FLOOD_MIN_EVENTS:
                    return False, {}
                    
                blocks = sum(1 for e in window if str(e.action).lower() in ["block", "deny", "drop"])
                block_ratio = blocks / len(window)
                if block_ratio < settings.NETWORK_FLOOD_MIN_BLOCK_RATIO:
                    return False, {}
                    
                first_ts = window[0].timestamp
                last_ts = window[-1].timestamp
                observed_duration = 1.0
                if first_ts and last_ts:
                    observed_duration = max(1.0, (last_ts - first_ts).total_seconds())
                    
                eps = len(window) / observed_duration
                
                return True, {
                    "block_ratio": block_ratio,
                    "event_count": len(window),
                    "eps": eps,
                    "observed_window_seconds": observed_duration,
                    "destination_port": dst_port,
                    "protocol": protocol
                }

            matches = sliding_window_scan(evs, settings.NETWORK_FLOOD_WINDOW_SECONDS, check_window)
            
            for match_events, match_context in matches:
                event_ids = [e.event_id for e in match_events]
                first_seen = match_events[0].timestamp or datetime.now()
                last_seen = match_events[-1].timestamp or datetime.now()
                
                sig_id = generate_signal_id(self.rule_id, self.version, src_ip, f"target_{dst_ip}_{dst_port}_{protocol}", first_seen, event_ids)
                
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
