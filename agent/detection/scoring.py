from typing import cast, Literal, List
import ipaddress
from agent.detection.models import DetectionSignal
from agent.detection.config import DetectionSettings

def is_internal_ip(ip_str: str, internal_networks: List[str]) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in internal_networks:
            if ip in ipaddress.ip_network(net):
                return True
        return False
    except ValueError:
        return False

def calculate_signal_confidence(
    event_count: int,
    threshold_count: int,
    base_confidence: float = 0.5,
    max_confidence: float = 0.95
) -> float:
    """
    Deterministic confidence calculation.
    Increases confidence as the event count exceeds the threshold.
    """
    if threshold_count <= 0:
        return base_confidence
    ratio = event_count / threshold_count
    if ratio < 1.0:
        return base_confidence * ratio
    
    # Asymptotically approach max_confidence
    extra = ratio - 1.0
    boost = (1.0 - (1.0 / (1.0 + extra * 0.5))) * (max_confidence - base_confidence)
    return min(base_confidence + boost, max_confidence)


def calculate_incident_severity(
    signals: List[DetectionSignal],
    primary_entity: str,
    settings: DetectionSettings
) -> Literal['informational', 'low', 'medium', 'high', 'critical']:
    """
    Calculate incident severity based on the signals and entity context.
    """
    if not signals:
        return "informational"
        
    highest_severity_val = 0
    severity_map = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    reverse_map = {0: "informational", 1: "low", 2: "medium", 3: "high", 4: "critical"}
    
    total_events = sum(len(s.event_ids) for s in signals)
    distinct_targets = len(set(t for s in signals for t in s.target_entities))
    
    for s in signals:
        val = severity_map.get(s.severity, 0)
        if val > highest_severity_val:
            highest_severity_val = val
            
    # Boost if high event count or target count
    if total_events > 500 or distinct_targets > 50:
        highest_severity_val = min(4, highest_severity_val + 1)
        
    # Example: If internal target is heavily attacked, could bump severity, but for now deterministically rely on rule severity + volume
    
    return cast(Literal['informational', 'low', 'medium', 'high', 'critical'], reverse_map.get(highest_severity_val, "medium"))

def calculate_incident_confidence(signals: List[DetectionSignal]) -> float:
    if not signals:
        return 0.0
    # Average confidence of top 3 signals or max confidence
    confs = sorted([s.confidence for s in signals], reverse=True)
    top_confs = confs[:3]
    return sum(top_confs) / len(top_confs)
