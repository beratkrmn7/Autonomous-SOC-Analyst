from typing import List, Dict, Any, Optional, Sequence
from agent.triage.models import (
    TriageInput,
    SafeEventView,
    EvidenceCandidate,
    TriageIncidentContext,
    TriageSignalView,
)
from agent.config import get_settings
from agent.schema import CanonicalLogEvent
from agent.triage.guardrails import (
    derive_incident_facts,
    EXPOSURE_POLICY_FAMILIES,
    SCAN_PROBE_FAMILIES,
    SEQUENCE_SIGNAL_TYPES,
)
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
# Provider-facing cap on target entities. The full target count is always
# preserved in deterministic_metrics and in relational persistence.
MAX_TARGET_ENTITIES = 50

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


# Signal type/family that Phase 6E.3 guardrails classify on. A bounded
# provider view must never drop a distinct one of these, or an exposure /
# sequence / scan-probe incident could be mis-classified for the model.
_SAFETY_CRITICAL_FAMILIES = SCAN_PROBE_FAMILIES | EXPOSURE_POLICY_FAMILIES


def _build_single_signal_view(
    sig: Dict[str, Any], incident_event_ids: set
) -> TriageSignalView:
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
    return TriageSignalView(
        signal_id=sig["signal_id"],
        rule_id=truncate_str(str(sig.get("rule_id", "unknown")), MAX_SHORT_FIELD_CHARS),
        rule_name=truncate_str(str(sig.get("rule_name", "unknown")), MAX_SHORT_FIELD_CHARS),
        signal_type=truncate_str(str(sig.get("signal_type", "unknown")), MAX_SHORT_FIELD_CHARS),
        signal_family=truncate_str(str(sig.get("signal_family", "unknown")), MAX_SHORT_FIELD_CHARS),
        severity=str(sig.get("severity", "none")),
        confidence=float(sig.get("confidence_score", 0.0) or 0.0),
        matched_event_ids=matched_event_ids,
        mitre_techniques=mitre_sorted,
    )


def _select_signal_views(
    detected_signals: List[Dict[str, Any]],
    incident_event_ids: set,
    *,
    preferred_signal_ids: set,
    primary_signal_id: Optional[str],
) -> List[TriageSignalView]:
    """Bounded, deterministic, duplicate-free typed signal metadata that
    preserves the material identity of the incident rather than just the
    lowest-sorted signal IDs.

    A canonical incident merged across jobs may carry thousands of historical
    signals whose IDs sort before the current job's. The stratified selection
    guarantees, within MAX_SIGNAL_VIEWS: the canonical primary signal, at least
    one current-job signal, and one representative for every distinct
    safety-critical family/sequence type the Phase 6E.3 guardrails classify on -
    then fills deterministically by signal_id. The complete attached rule-ID set
    still reaches deterministic routing through signal_map; this bound is
    provider-facing only.
    """
    by_id: dict[str, Dict[str, Any]] = {}
    for sig in detected_signals:
        sid = sig.get("signal_id")
        if sid and sid not in by_id:
            by_id[sid] = sig

    order: List[str] = []
    seen: set[str] = set()

    def add(sid: Optional[str]) -> None:
        if sid and sid in by_id and sid not in seen:
            seen.add(sid)
            order.append(sid)

    # 1. canonical primary signal
    add(primary_signal_id)
    # 2. at least one current-job signal (deterministic lowest ID)
    current_ids = sorted(sid for sid in by_id if sid in preferred_signal_ids)
    if current_ids:
        add(current_ids[0])
    # 3. one representative per distinct safety-critical family / sequence type
    for family in sorted(_SAFETY_CRITICAL_FAMILIES):
        reps = sorted(
            sid for sid, s in by_id.items() if s.get("signal_family") == family
        )
        if reps:
            add(reps[0])
    for stype in sorted(SEQUENCE_SIGNAL_TYPES):
        reps = sorted(sid for sid, s in by_id.items() if s.get("signal_type") == stype)
        if reps:
            add(reps[0])
    # 4. deterministic fill by signal_id
    for sid in sorted(by_id):
        if len(order) >= MAX_SIGNAL_VIEWS:
            break
        add(sid)

    selected = order[:MAX_SIGNAL_VIEWS]
    views = [_build_single_signal_view(by_id[sid], incident_event_ids) for sid in selected]
    return sorted(views, key=lambda view: view.signal_id)


def _build_signal_views(
    detected_signals: List[Dict[str, Any]],
    incident_event_ids: set,
) -> List[TriageSignalView]:
    """Backward-compatible unbounded-preference selection (every attached
    signal, deduped, sorted by signal_id, capped at MAX_SIGNAL_VIEWS). Kept for
    existing callers/tests that do not supply current-job provenance."""
    return _select_signal_views(
        detected_signals, incident_event_ids,
        preferred_signal_ids=set(), primary_signal_id=None,
    )


def _select_events(
    sorted_events: List[CanonicalLogEvent],
    sorted_context: List[CanonicalLogEvent],
    *,
    preferred_event_ids: set,
    max_context_events: int,
) -> List[CanonicalLogEvent]:
    """Deterministically select a bounded event set that keeps at least one
    current-job incident event and at least one historical event visible,
    instead of only the oldest events. Views are built for the selection only."""
    pool = sorted_events + sorted_context  # incident events, then context
    reserved: set[str] = set()
    current_incident = [e for e in sorted_events if e.event_id in preferred_event_ids]
    if current_incident:
        reserved.add(current_incident[0].event_id)
    historical = [e for e in pool if e.event_id not in preferred_event_ids]
    if historical and len(reserved) < max_context_events:
        reserved.add(historical[0].event_id)

    chosen: set[str] = set(reserved)
    for event in pool:
        if len(chosen) >= max_context_events:
            break
        chosen.add(event.event_id)
    # Preserve deterministic pool order; duplicate-free because event IDs are
    # unique and incident/context sets are disjoint.
    return [e for e in pool if e.event_id in chosen][:max_context_events]


def _select_evidence(
    ev_candidates: List[EvidenceCandidate],
    *,
    preferred_event_ids: set,
    max_candidate_evidence: int,
) -> List[EvidenceCandidate]:
    """Stratified, deterministic bounded evidence: keep at least one current-job
    evidence item and at least one historical item when both exist, then fill
    deterministically by evidence_id. `ev_candidates` is already sorted."""
    reserved: set[str] = set()
    current = [c for c in ev_candidates if c.event_id in preferred_event_ids]
    if current:
        reserved.add(current[0].evidence_id)
    historical = [c for c in ev_candidates if c.event_id not in preferred_event_ids]
    if historical and len(reserved) < max_candidate_evidence:
        reserved.add(historical[0].evidence_id)

    chosen: set[str] = set(reserved)
    for candidate in ev_candidates:
        if len(chosen) >= max_candidate_evidence:
            break
        chosen.add(candidate.evidence_id)
    return [c for c in ev_candidates if c.evidence_id in chosen][:max_candidate_evidence]

def build_triage_input(
    context: TriageIncidentContext,
    detected_signals: List[Dict[str, Any]],
    candidate_evidence: List[Dict[str, Any]],
    *,
    preferred_signal_ids: Optional[Sequence[str]] = None,
    preferred_event_ids: Optional[Sequence[str]] = None,
    primary_signal_id: Optional[str] = None,
) -> TriageInput:

    settings = get_settings()
    max_preview_chars = settings.max_event_preview_chars
    max_context_events = settings.max_context_events
    max_candidate_evidence = settings.max_candidate_evidence

    preferred_signals = set(preferred_signal_ids or ())
    preferred_events = set(preferred_event_ids or ())

    # Deterministically SELECT the bounded event set BEFORE building any
    # SafeEventView, keeping at least one current-job incident event and one
    # historical event visible rather than only the oldest events.
    sorted_events = sorted(context.events, key=lambda e: (e.timestamp or "", e.event_id))
    sorted_context = sorted(context.context_events, key=lambda e: (e.timestamp or "", e.event_id))
    selected_events = _select_events(
        sorted_events, sorted_context,
        preferred_event_ids=preferred_events,
        max_context_events=max_context_events,
    )
    limited_events = [_build_safe_event(e, max_preview_chars) for e in selected_events]

    incident_event_ids = set(context.incident.event_ids)
    signal_views = _select_signal_views(
        detected_signals, incident_event_ids,
        preferred_signal_ids=preferred_signals,
        primary_signal_id=primary_signal_id,
    )

    # Signal summaries are derived from the already-bounded, deduplicated,
    # sorted, and truncated signal_views (<= MAX_SIGNAL_VIEWS) rather than from
    # every attached raw signal, so a campaign with thousands of historical
    # signals can never push thousands of summary lines into the prompt. The
    # complete attached rule-ID set still reaches deterministic routing through
    # DetectionResult/signal_map - this bound is provider-facing only.
    signal_summaries = sorted(
        {
            f"[{sv.rule_name}] {sv.signal_type} ({sv.signal_family}) - "
            f"Severity: {sv.severity} Confidence: {sv.confidence}"
            for sv in signal_views
        }
    )

    all_ev_candidates = []
    for ev in candidate_evidence:
        quote = ev.get('quote', '')
        reason = ev.get('reason', '')
        source = ev.get('source', '')
        event_id = ev.get('event_id', '')
        ev_id = generate_evidence_id(context.incident.incident_id, event_id, source, quote, reason)

        all_ev_candidates.append(EvidenceCandidate(
            evidence_id=ev_id,
            event_id=event_id,
            quote=quote,
            reason=reason,
            source=source,
            canonical_fields=ev.get('original_fields', {}),
            vendor_original_fields=ev.get('source_line', {}),
            correlation_context=ev.get('correlation_context', {})
        ))

    all_ev_candidates.sort(key=lambda c: c.evidence_id)
    ev_candidates = _select_evidence(
        all_ev_candidates,
        preferred_event_ids=preferred_events,
        max_candidate_evidence=max_candidate_evidence,
    )

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
            
    # Provider-facing target entities are deterministically bounded, but the
    # full target count is preserved in deterministic_metrics (and the complete
    # list always remains in the persisted Incident row).
    full_targets = list(context.incident.target_entities or [])
    bounded_targets = sorted(set(full_targets))[:MAX_TARGET_ENTITIES]

    deterministic_metrics = dict(context.incident.metrics)
    facts = derive_incident_facts(context, signal_views)
    deterministic_metrics.update(facts.model_dump())
    deterministic_metrics["target_entity_count"] = len(full_targets)

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
        target_entities=bounded_targets,
        deterministic_metrics=deterministic_metrics,
        signal_summaries=signal_summaries,
        signal_views=signal_views,
        candidate_evidence=ev_candidates,
        limited_context_events=limited_events,
        allowed_mitre_candidates=sorted(list(mitre_set)),
        parser_warnings=sorted(list(p_warns)),
        data_quality_warnings=sorted(list(dq_warns))
    )
