from typing import List, Dict, Any, Optional
from agent.triage.models import (
    TriageInput,
    SafeEventView,
    EvidenceCandidate,
    TriageIncidentContext,
    TriageSignalView,
)
from agent.config import get_settings
from agent.schema import CanonicalLogEvent
from agent.triage.guardrails import derive_incident_facts
from agent.triage.network_context import derive_flow_direction
import hashlib

# Phase 6E.3 bounds for the provider-facing safe view. These cap what a
# single incident can ever push into the prompt regardless of how many raw
# events/signals the deterministic engine matched; full, untruncated
# event/signal IDs always remain in DetectionResult and persistence. The
# current 36-rule registry never produces an incident anywhere near these
# limits, so normal incidents are never truncated.
MAX_SIGNAL_VIEWS = 50
MAX_MATCHED_EVENT_IDS_PER_SIGNAL = 50
MAX_MITRE_PER_SIGNAL = 20
MAX_SHORT_FIELD_CHARS = 200

def generate_evidence_id(incident_id: str, event_id: str, source: str, quote: str, reason: str) -> str:
    hash_input = f"{incident_id}|{event_id}|{source}|{quote}|{reason}"
    return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()[:12]

def truncate_str(s: str, max_len: int = 500) -> str:
    if not s:
        return ""
    if len(s) > max_len:
        return s[:max_len] + "... [TRUNCATED]"
    return s


def _bounded_optional_str(value: Optional[str], max_len: int = MAX_SHORT_FIELD_CHARS) -> Optional[str]:
    """Like truncate_str, but preserves None instead of coercing it to ''."""
    if value is None:
        return None
    return truncate_str(value, max_len)


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
        sanitized_message_excerpt=truncate_str(event.safe_message_excerpt, max_preview_chars) if event.safe_message_excerpt else None,
        bytes=event.bytes,
        packets=event.packets,
        duration_ms=event.duration_ms,
        inbound_interface=_bounded_optional_str(event.inbound_interface),
        outbound_interface=_bounded_optional_str(event.outbound_interface),
        inbound_zone=_bounded_optional_str(event.inbound_zone),
        outbound_zone=_bounded_optional_str(event.outbound_zone),
        nat_type=_bounded_optional_str(event.nat_type),
        translated_src_ip=event.translated_src_ip,
        translated_dst_ip=event.translated_dst_ip,
        translated_src_port=event.translated_src_port,
        translated_dst_port=event.translated_dst_port,
        flow_direction=derive_flow_direction(event),
    )


def _build_signal_views(
    detected_signals: List[Dict[str, Any]],
    incident_event_ids: set,
) -> List[TriageSignalView]:
    """Bounded, deterministic, duplicate-free typed metadata for every
    attached signal (Phase 6E.2 may attach several rule families to one
    correlated incident, including supporting/absorbed signals).

    Deterministic sorted truncation everywhere: matched_event_ids and
    mitre_techniques are sorted (deduped) before being capped, and the
    final view list is sorted by signal_id before being capped, so
    truncation never depends on input order.
    """
    views: dict[str, TriageSignalView] = {}
    for sig in detected_signals:
        signal_id = sig.get("signal_id")
        if not signal_id or signal_id in views:
            continue
        matched_event_ids = sorted(
            {
                eid
                for eid in sig.get("matched_event_ids", []) or []
                if eid in incident_event_ids
            }
        )[:MAX_MATCHED_EVENT_IDS_PER_SIGNAL]
        mitre = sig.get("mitre_techniques") or []
        mitre_sorted = (
            sorted(set(mitre))[:MAX_MITRE_PER_SIGNAL] if isinstance(mitre, list) else []
        )
        views[signal_id] = TriageSignalView(
            signal_id=signal_id,
            rule_id=truncate_str(str(sig.get("rule_id", "unknown")), MAX_SHORT_FIELD_CHARS),
            rule_name=truncate_str(str(sig.get("rule_name", "unknown")), MAX_SHORT_FIELD_CHARS),
            signal_type=truncate_str(str(sig.get("signal_type", "unknown")), MAX_SHORT_FIELD_CHARS),
            signal_family=truncate_str(str(sig.get("signal_family", "unknown")), MAX_SHORT_FIELD_CHARS),
            severity=str(sig.get("severity", "none")),
            confidence=float(sig.get("confidence_score", 0.0) or 0.0),
            matched_event_ids=matched_event_ids,
            mitre_techniques=mitre_sorted,
        )
    return sorted(views.values(), key=lambda view: view.signal_id)[:MAX_SIGNAL_VIEWS]

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

    incident_event_ids = set(context.incident.event_ids)
    signal_views = _build_signal_views(detected_signals, incident_event_ids)

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
            
    deterministic_metrics = dict(context.incident.metrics)
    facts = derive_incident_facts(context, signal_views)
    deterministic_metrics.update(facts.model_dump())

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
        deterministic_metrics=deterministic_metrics,
        signal_summaries=signal_summaries,
        signal_views=signal_views,
        candidate_evidence=ev_candidates,
        limited_context_events=limited_events,
        allowed_mitre_candidates=sorted(list(mitre_set)),
        parser_warnings=sorted(list(p_warns)),
        data_quality_warnings=sorted(list(dq_warns))
    )
