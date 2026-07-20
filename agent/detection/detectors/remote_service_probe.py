from datetime import datetime
from typing import List, Sequence, Tuple, Dict, Any
from collections import defaultdict, deque
from agent.schema import CanonicalLogEvent
from agent.detection.models import DetectionSignal, generate_signal_id
from agent.detection.detectors.base import BaseDetectionRule, DetectionContext
from agent.detection.evidence import select_representative_evidence
from agent.detection.correlation import sliding_window_scan
from agent.detection.scoring import calculate_signal_confidence
from agent.detection.contracts import DetectionRuleMetadata, DetectionSignalVariant
from agent.detection.detectors.scan_helpers import is_tcp_syn

class RemoteServiceProbeRule(BaseDetectionRule):
    metadata = DetectionRuleMetadata(
        rule_id="remote_service_probe",
        version="1.0.0",
        name="Remote Service Probe (RDP/SSH)",
        family="service_probing",
        priority=50,
        supported_event_types=(),
        required_fields=("src_ip", "dst_port", "protocol"),
        signal_type="remote_service_probe",
        signal_variants=(
            DetectionSignalVariant(
                rule_id="rdp_probe",
                rule_name="RDP Probe",
                signal_type="rdp_probe",
            ),
            DetectionSignalVariant(
                rule_id="ssh_probe",
                rule_name="SSH Probe",
                signal_type="ssh_probe",
            ),
        ),
        default_severity="high",
        mitre_techniques=("T1046",),
        window_setting="REMOTE_SERVICE_WINDOW_SECONDS",
        minimum_events_setting="REMOTE_SERVICE_MIN_EVENTS",
    )

    def evaluate(self, events: Sequence[CanonicalLogEvent], context: DetectionContext) -> List[DetectionSignal]:
        settings = context.settings
        
        rdp_ports = set(settings.RDP_PORTS)
        ssh_ports = set(settings.SSH_PORTS)
        target_ports = rdp_ports.union(ssh_ports)
        
        # We group by (src_ip, service_type)
        groups = defaultdict(list)
        for e in events:
            if not e.src_ip or e.dst_port not in target_ports:
                continue
            protocol = getattr(e, 'protocol', None)
            if not protocol or str(protocol).upper() != "TCP":
                continue
                
            svc_type = "rdp" if e.dst_port in rdp_ports else "ssh"
            groups[(e.src_ip, svc_type)].append(e)

        signals = []
        for (src_ip, svc_type), evs in groups.items():
            if len(evs) < settings.REMOTE_SERVICE_MIN_EVENTS:
                continue
                
            def check_window(window: deque) -> Tuple[bool, Dict[str, Any]]:
                if len(window) < settings.REMOTE_SERVICE_MIN_EVENTS:
                    return False, {}
                    
                distinct_targets = set(e.dst_ip for e in window if e.dst_ip)
                if len(distinct_targets) < settings.REMOTE_SERVICE_MIN_DISTINCT_TARGETS:
                    return False, {}
                    
                blocks = sum(1 for e in window if str(e.action).lower() in ["block", "deny", "drop"])
                block_ratio = blocks / len(window)
                if block_ratio < settings.REMOTE_SERVICE_MIN_BLOCK_RATIO:
                    return False, {}
                    
                syn_count = sum(1 for e in window if is_tcp_syn(e))
                if syn_count / len(window) < settings.REMOTE_SERVICE_MIN_SYN_RATIO:
                    return False, {}
                    
                # Note: We do NOT map T1110 (Brute Force) here because we lack authentication failure logs.
                # We map T1046 (Network Service Scanning) and tag it with the specific service.
                return True, {
                    "distinct_targets": len(distinct_targets),
                    "block_ratio": block_ratio,
                    "syn_ratio": syn_count / len(window),
                    "event_count": len(window),
                    "service": svc_type
                }

            matches = sliding_window_scan(evs, settings.REMOTE_SERVICE_WINDOW_SECONDS, check_window)
            
            for match_events, match_context in matches:
                event_ids = [e.event_id for e in match_events]
                first_seen = match_events[0].timestamp or datetime.now()
                last_seen = match_events[-1].timestamp or datetime.now()
                
                sig_id = generate_signal_id(self.rule_id, self.version, src_ip, f"service_{svc_type}", first_seen, event_ids)
                
                evidence = select_representative_evidence(
                    match_events, 
                    max_evidence=3, 
                    reason=f"Suspicious {svc_type.upper()} probing detected", 
                    source_rule=self.rule_id,
                    correlation_context=match_context
                )
                
                confidence = calculate_signal_confidence(
                    match_context["event_count"], 
                    settings.REMOTE_SERVICE_MIN_EVENTS,
                    base_confidence=0.7,
                    max_confidence=0.95
                )

                targets = list(set(e.dst_ip for e in match_events if e.dst_ip))
                
                signal = DetectionSignal(
                    signal_id=sig_id,
                    rule_id=f"{svc_type}_probe",
                    rule_version=self.version,
                    rule_name=f"{svc_type.upper()} Probe",
                    signal_type=f"{svc_type}_probe",
                    signal_family=self.family,
                    severity="high",
                    confidence=confidence,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    event_ids=event_ids,
                    primary_entity=src_ip,
                    target_entities=targets,
                    metrics=match_context,
                    evidence=evidence,
                    mitre_techniques=["T1046"], # Conservative mapping
                    tags=["network", "probe", svc_type]
                )
                signals.append(signal)

        return signals
