from typing import List, Dict, Any
from agent.triage.models import TriageInput, SafeEventView, EvidenceCandidate, TriageIncidentContext
from agent.config import get_settings
from agent.schema import CanonicalLogEvent
import hashlib

def generate_evidence_id(incident_id: str, event_id: str, source: str, quote: str, reason: str) -> str:
    hash_input = f"{incident_id}|{event_id}|{source}|{quote}|{reason}"
    return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()[:12]

def truncate_str(s: str, max_len: int = 500) -> str:
    if not s:
        return ""
    if len(s) > max_len:
        return s[:max_len] + "... [TRUNCATED]"
    return s

def _build_safe_event(event: CanonicalLogEvent, max_preview_chars: int = 1000) -> SafeEventView:
    return SafeEventView(
        event_id=event.event_id,
        timestamp=event.timestamp.isoformat() if event.timestamp else "",
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        src_port=event.src_port,
        dst_port=event.dst_port,
        protocol=event.protocol,
        action=event.action,
        action_reason=event.action_reason,
        event_type=event.event_type,
        event_category=event.event_category,
        event_outcome=event.event_outcome,
        tcp_flags=event.tcp_flags,
        parser_name=event.parser_name or "unknown",
        source_name=event.source_name or "unknown",
        sanitized_message_excerpt=truncate_str(event.safe_message_excerpt, max_preview_chars) if event.safe_message_excerpt else None
    )

def build_triage_input(
    context: TriageIncidentContext,
    detected_signals: List[Dict[str, Any]],
    candidate_evidence: List[Dict[str, Any]]
) -> TriageInput:
    
    settings = get_settings()
    max_preview_chars = settings.max_event_preview_chars
    max_context_events = settings.max_context_events
    max_candidate_evidence = settings.max_candidate_evidence
    
    # Sort events deterministically by timestamp then event_id
    sorted_events = sorted(context.events, key=lambda e: (e.timestamp or "", e.event_id))
    safe_events = [_build_safe_event(e, max_preview_chars) for e in sorted_events]
    
    sorted_context = sorted(context.context_events, key=lambda e: (e.timestamp or "", e.event_id))
    safe_context = [_build_safe_event(e, max_preview_chars) for e in sorted_context]
    
    signal_summaries = []
    for sig in detected_signals:
        signal_summaries.append(f"[{sig.get('rule_name', 'unknown')}] {sig.get('description', '')} - Severity: {sig.get('severity', 'none')} Confidence: {sig.get('confidence_score', 0.0)}")
    signal_summaries.sort()
    
    ev_candidates = []
    for ev in candidate_evidence:
        quote = ev.get('quote', '')
        reason = ev.get('reason', '')
        source = ev.get('source', '')
        event_id = ev.get('event_id', '')
        ev_id = generate_evidence_id(context.incident.incident_id, event_id, source, quote, reason)
        
        ev_candidates.append(EvidenceCandidate(
            evidence_id=ev_id,
            event_id=event_id,
            quote=quote,
            reason=reason,
            source=source,
            canonical_fields=ev.get('original_fields', {}),
            vendor_original_fields=ev.get('source_line', {}),
            correlation_context=ev.get('correlation_context', {})
        ))
        
    ev_candidates.sort(key=lambda c: c.evidence_id)
    ev_candidates = ev_candidates[:max_candidate_evidence]
    
    limited_events = (safe_events + safe_context)[:max_context_events]
    
    mitre_set = set()
    for sig in detected_signals:
        mitre_techs = sig.get('mitre_techniques')
        if mitre_techs and isinstance(mitre_techs, list) and len(mitre_techs) > 0:
            mitre_set.add(mitre_techs[0])
    
    p_warns = set()
    dq_warns = set()
    for e in context.events + context.context_events:
        for w in getattr(e, 'parse_warnings', []):
            p_warns.add(w)
        for w in getattr(e, 'data_quality_warnings', []):
            dq_warns.add(w)
            
    return TriageInput(
        incident_id=context.incident.incident_id,
        incident_type=context.incident.incident_type,
        incident_family=context.incident.incident_family,
        title=context.incident.title,
        deterministic_severity=context.incident.severity,
        deterministic_confidence=context.incident.confidence,
        first_seen=context.incident.first_seen.isoformat() if context.incident.first_seen else "",
        last_seen=context.incident.last_seen.isoformat() if context.incident.last_seen else "",
        primary_entity=context.incident.primary_entity,
        target_entities=context.incident.target_entities,
        signal_summaries=signal_summaries,
        candidate_evidence=ev_candidates,
        limited_context_events=limited_events,
        allowed_mitre_candidates=sorted(list(mitre_set)),
        parser_warnings=sorted(list(p_warns)),
        data_quality_warnings=sorted(list(dq_warns))
    )
