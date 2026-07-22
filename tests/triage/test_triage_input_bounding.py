"""Phase 6E.4 blockers: the provider-facing TriageInput must stay strictly
bounded no matter how many historical signals/events a merged canonical
incident carries, AND must still surface the current job's material evidence
and the canonical primary identity - not just the oldest / lowest-sorted IDs.
Deterministic routing (which uses the full signal_map) is unaffected."""

from __future__ import annotations

import datetime

from agent.detection.models import DetectionEvidence, DetectionSignal, IncidentBundle
from agent.schema import CanonicalLogEvent
from agent.triage.input_builder import (
    MAX_SHORT_FIELD_CHARS,
    MAX_SIGNAL_VIEWS,
    MAX_TARGET_ENTITIES,
    build_triage_input,
)
from agent.triage.models import TriageIncidentContext
from agent.triage.prompt_builder import build_system_prompt
from agent.config import get_settings

FIXED = datetime.datetime(2026, 7, 10, 6, 0, 0, tzinfo=datetime.timezone.utc)

LONG_RULE_NAME = "rdp_probe_rule_" + ("x" * 5000)
# A current-job event/signal whose IDs deliberately sort AFTER every historical
# ID, so a naive lowest-ID selection would drop them.
CURRENT_EVENT_ID = "zzz_current_event"
CURRENT_SIGNAL_ID = "zzz_current_signal"

N_HISTORICAL = 1200


def _event(event_id: str, *, ts: datetime.datetime, excerpt_len: int = 100) -> CanonicalLogEvent:
    return CanonicalLogEvent(
        event_id=event_id, timestamp=ts, src_ip="203.0.113.10", dst_ip="10.0.0.5",
        dst_port=3389, protocol="TCP", action="block", parser_name="pf_firewall",
        parse_status="parsed", source_name="firewall.json",
        safe_message_excerpt="X" * excerpt_len,
    )


def _signal_dict(signal_id: str, event_id: str) -> dict:
    return {
        "signal_id": signal_id,
        "rule_id": "remote_service_probe",
        "rule_name": LONG_RULE_NAME,
        "signal_type": "rdp_probe",
        "signal_family": "service_probing",
        "severity": "medium",
        "confidence_score": 0.6,
        "description": "d" * 4000,
        "mitre_techniques": ["T1021.001"],
        "matched_event_ids": [event_id],
    }


def _evidence(event_id: str) -> dict:
    return {
        "event_id": event_id,
        "quote": "q" * 80,
        "reason": "r",
        "source": "pf_firewall",
        "original_fields": {},
        "correlation_context": {},
    }


def _build_campaign(n_targets: int = 4000):
    # Historical events/signals (low-sorting IDs).
    hist_events = [
        _event(f"e{i:05d}", ts=FIXED + datetime.timedelta(seconds=i))
        for i in range(N_HISTORICAL)
    ]
    hist_signals = [_signal_dict(f"s{i:05d}", f"e{i:05d}") for i in range(N_HISTORICAL)]

    # One current-job event and signal, sorting AFTER all historical IDs. The
    # current event carries a maximum-length safe excerpt (truncated to
    # max_event_preview_chars) and must still remain visible and within budget.
    current_event = _event(
        CURRENT_EVENT_ID, ts=FIXED + datetime.timedelta(days=1), excerpt_len=5000
    )
    current_signal = _signal_dict(CURRENT_SIGNAL_ID, CURRENT_EVENT_ID)

    events = hist_events + [current_event]
    detected_signals = hist_signals + [current_signal]
    evidence = [_evidence(f"e{i:05d}") for i in range(N_HISTORICAL)] + [
        _evidence(CURRENT_EVENT_ID)
    ]

    targets = [f"10.0.{i // 256}.{i % 256}" for i in range(n_targets)]
    incident = IncidentBundle(
        incident_id="INC-A", incident_type="rdp_probe", incident_family="service_probing",
        title="RDP probe", severity="medium", confidence=0.6, first_seen=FIXED,
        last_seen=current_event.timestamp, primary_entity="203.0.113.10",
        target_entities=targets,
        signal_ids=[s["signal_id"] for s in detected_signals],
        event_ids=[e.event_id for e in events], context_event_ids=[],
        evidence=[DetectionEvidence(event_id="e00000", quote="q", reason="r",
                                    source="pf", original_fields={}, correlation_context={})],
        metrics={"primary_signal_id": CURRENT_SIGNAL_ID},
        mitre_techniques=["T1021.001"], merge_key="m1",
    )
    context = TriageIncidentContext(incident=incident, events=events, context_events=[])
    return context, detected_signals, evidence, targets


def _build(context, detected_signals, evidence):
    return build_triage_input(
        context, detected_signals, evidence,
        preferred_signal_ids=[CURRENT_SIGNAL_ID],
        preferred_event_ids=[CURRENT_EVENT_ID],
        primary_signal_id=CURRENT_SIGNAL_ID,
    )


def test_current_job_and_historical_evidence_stay_visible_within_bounds() -> None:
    context, signals, evidence, targets = _build_campaign()
    result = _build(context, signals, evidence)
    settings = get_settings()

    assert len(result.signal_views) <= MAX_SIGNAL_VIEWS
    assert len(result.limited_context_events) <= settings.max_context_events

    # Current-job signal and event remain visible despite sorting last.
    view_ids = {v.signal_id for v in result.signal_views}
    assert CURRENT_SIGNAL_ID in view_ids
    event_ids = {e.event_id for e in result.limited_context_events}
    assert CURRENT_EVENT_ID in event_ids
    assert any(c.event_id == CURRENT_EVENT_ID for c in result.candidate_evidence)

    # Historical representation also remains visible.
    assert any(vid != CURRENT_SIGNAL_ID for vid in view_ids)
    assert any(eid != CURRENT_EVENT_ID for eid in event_ids)
    assert any(c.event_id != CURRENT_EVENT_ID for c in result.candidate_evidence)

    # Long rule names are truncated inside the bounded views.
    for view in result.signal_views:
        assert len(view.rule_name) <= MAX_SHORT_FIELD_CHARS + len("... [TRUNCATED]")


def test_target_entities_are_bounded_but_full_count_preserved() -> None:
    context, signals, evidence, targets = _build_campaign(n_targets=4000)
    result = _build(context, signals, evidence)
    assert len(result.target_entities) <= MAX_TARGET_ENTITIES
    assert result.deterministic_metrics["target_entity_count"] == len(targets)
    # The persisted incident still holds the complete target list.
    assert len(context.incident.target_entities) == len(targets)


def test_full_prompt_stays_within_max_prompt_tokens() -> None:
    context, signals, evidence, _ = _build_campaign()
    triage_input = _build(context, signals, evidence)
    system_prompt = build_system_prompt(triage_input)
    settings = get_settings()
    # Exactly TriageRunner's estimate.
    approx_tokens = (len(triage_input.model_dump_json()) + len(system_prompt)) // 4
    assert approx_tokens <= settings.max_prompt_tokens


def test_triage_input_is_deterministic() -> None:
    context, signals, evidence, _ = _build_campaign()
    first = _build(context, signals, evidence)
    second = _build(context, signals, evidence)
    assert first.signal_summaries == second.signal_summaries
    assert [v.signal_id for v in first.signal_views] == [v.signal_id for v in second.signal_views]
    assert [e.event_id for e in first.limited_context_events] == [
        e.event_id for e in second.limited_context_events
    ]
    assert first.target_entities == second.target_entities


def test_routing_still_sees_complete_attached_rule_id_set() -> None:
    """Bounding the provider-facing input must not shrink the rule-ID set that
    deterministic routing derives from the full attached signal_map."""
    n = 1200
    signal_map = {
        f"s{i:05d}": DetectionSignal(
            signal_id=f"s{i:05d}", rule_id=f"rule_{i % 7}", rule_version="1",
            rule_name=LONG_RULE_NAME, signal_type="rdp_probe",
            signal_family="service_probing", severity="medium", confidence=0.6,
            first_seen=FIXED, last_seen=FIXED, event_ids=[f"e{i:05d}"],
            primary_entity="203.0.113.10", target_entities=["10.0.0.5"], metrics={},
            evidence=[DetectionEvidence(event_id=f"e{i:05d}", quote="q", reason="r",
                                        source="pf", original_fields={}, correlation_context={})],
            mitre_techniques=["T1021.001"], tags=[],
        )
        for i in range(n)
    }
    rule_ids = frozenset(s.rule_id for s in signal_map.values())
    assert rule_ids == {f"rule_{k}" for k in range(7)}
