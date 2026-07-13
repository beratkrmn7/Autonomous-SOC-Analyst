from typing import Dict, Any, List, Optional
from agent.schema import CanonicalLogEvent
from agent.detection.models import DetectionEvidence

def create_evidence_from_event(
    event: CanonicalLogEvent, 
    reason: str, 
    source_rule: str,
    correlation_context: Optional[Dict[str, Any]] = None
) -> DetectionEvidence:
    """
    Safely creates DetectionEvidence from a CanonicalLogEvent.
    Extracts relevant structural fields for validation without mutating original data.
    """
    if not event.event_id:
        raise ValueError("Cannot create evidence for event without event_id")

    original_fields: Dict[str, Any] = {}
    if event.src_ip:
        original_fields["src_ip"] = event.src_ip
    if event.dst_ip:
        original_fields["dst_ip"] = event.dst_ip
    if event.dst_port is not None:
        original_fields["dst_port"] = event.dst_port
    if event.action:
        original_fields["action"] = event.action
    if event.timestamp:
        original_fields["timestamp"] = event.timestamp.isoformat()
    if event.protocol:
        original_fields["protocol"] = event.protocol
    if event.action_reason:
        original_fields["action_reason"] = event.action_reason

    quote = str(event.safe_message_excerpt) if event.safe_message_excerpt else ""

    return DetectionEvidence(
        event_id=event.event_id,
        quote=quote,
        reason=reason,
        source=source_rule,
        original_fields=original_fields,
        correlation_context=correlation_context or {}
    )

def select_representative_evidence(
    events: List[CanonicalLogEvent], 
    max_evidence: int, 
    reason: str, 
    source_rule: str,
    correlation_context: Optional[Dict[str, Any]] = None
) -> List[DetectionEvidence]:
    """
    Selects a representative subset of events as evidence to avoid unbounded growth.
    Usually picks the first few events.
    """
    selected = events[:max_evidence]
    return [create_evidence_from_event(e, reason, source_rule, correlation_context) for e in selected]
