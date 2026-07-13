from datetime import datetime
from typing import List, Sequence, Tuple, Dict, Any
from collections import defaultdict, deque
from agent.schema import CanonicalLogEvent
from agent.detection.models import DetectionSignal, generate_signal_id
from agent.detection.detectors.base import BaseDetectionRule, DetectionContext
from agent.detection.evidence import select_representative_evidence
from agent.detection.correlation import sliding_window_scan
from agent.detection.scoring import calculate_signal_confidence

class SPIAnomalyRule(BaseDetectionRule):
    rule_id = "spi_anomaly_burst"
    version = "1.0.0"
    name = "SPI Anomaly Burst"
    family = "network_anomaly"
    priority = 100

    def evaluate(self, events: Sequence[CanonicalLogEvent], context: DetectionContext) -> List[DetectionSignal]:
        settings = context.settings
        
        # SPI events are strictly defined by their action_reason or explicit markers
        groups = defaultdict(list)
        for e in events:
            if not e.src_ip:
                continue
            is_spi = False
            # Check canonical action_reason
            if e.action_reason and "spi" in str(e.action_reason).lower():
                is_spi = True
            # Check event_outcome or action for spi related blocks
            elif e.event_outcome and "spi" in str(e.event_outcome).lower():
                is_spi = True
            elif e.action and "spi" in str(e.action).lower():
                is_spi = True
            # Check metadata or fallback to safe_message_excerpt checking
            elif e.parser_metadata and e.parser_metadata.get("spi_anomaly", False):
                is_spi = True
            elif settings.SPI_ANOMALY_FALLBACK_RAW_MATCH and e.safe_message_excerpt and "blocked by spi" in str(e.safe_message_excerpt).lower():
                is_spi = True
                
            if is_spi:
                groups[e.src_ip].append(e)

        signals = []
        for src_ip, evs in groups.items():
            if len(evs) < settings.SPI_ANOMALY_MIN_EVENTS:
                continue
                
            def check_window(window: deque) -> Tuple[bool, Dict[str, Any]]:
                if len(window) < settings.SPI_ANOMALY_MIN_EVENTS:
                    return False, {}
                    
                distinct_targets = set(e.dst_ip for e in window if e.dst_ip)
                if len(distinct_targets) < settings.SPI_ANOMALY_MIN_DISTINCT_TARGETS:
                    return False, {}
                    
                return True, {
                    "distinct_targets": len(distinct_targets),
                    "event_count": len(window),
                }

            matches = sliding_window_scan(evs, settings.SPI_ANOMALY_WINDOW_SECONDS, check_window)
            
            for match_events, match_context in matches:
                event_ids = [e.event_id for e in match_events]
                first_seen = match_events[0].timestamp or datetime.now()
                last_seen = match_events[-1].timestamp or datetime.now()
                
                sig_id = generate_signal_id(self.rule_id, self.version, src_ip, "spi_burst", first_seen, event_ids)
                
                evidence = select_representative_evidence(
                    match_events, 
                    max_evidence=3, 
                    reason="Repeated SPI anomaly blocks", 
                    source_rule=self.rule_id,
                    correlation_context=match_context
                )
                
                confidence = calculate_signal_confidence(
                    match_context["event_count"], 
                    settings.SPI_ANOMALY_MIN_EVENTS,
                    base_confidence=0.5,
                    max_confidence=0.85
                )

                targets = list(set(e.dst_ip for e in match_events if e.dst_ip))
                
                signal = DetectionSignal(
                    signal_id=sig_id,
                    rule_id=self.rule_id,
                    rule_version=self.version,
                    rule_name=self.name,
                    signal_type="spi_anomaly",
                    signal_family=self.family,
                    severity="medium",
                    confidence=confidence,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    event_ids=event_ids,
                    primary_entity=src_ip,
                    target_entities=targets,
                    metrics=match_context,
                    evidence=evidence,
                    mitre_techniques=[], # No mapping unless specific behavior
                    tags=["network", "anomaly", "spi"]
                )
                signals.append(signal)

        return signals
