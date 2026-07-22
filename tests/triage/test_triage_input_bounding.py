"""Phase 6E.4 blocker: the provider-facing TriageInput must stay strictly
bounded no matter how many historical signals/events a merged canonical
incident carries. Routing (which uses the full signal_map) is unaffected."""

from __future__ import annotations

import datetime
import json

from agent.detection.models import DetectionEvidence, DetectionSignal, IncidentBundle
from agent.schema import CanonicalLogEvent
from agent.triage.input_builder import (
    MAX_SHORT_FIELD_CHARS,
    MAX_SIGNAL_VIEWS,
    build_triage_input,
)
from agent.triage.models import TriageIncidentContext
from agent.config import get_settings

FIXED = datetime.datetime(2026, 7, 10, 6, 0, 0, tzinfo=datetime.timezone.utc)

LONG_RULE_NAME = "rdp_probe_rule_" + ("x" * 5000)


def _event(i: int) -> CanonicalLogEvent:
    return CanonicalLogEvent(
        event_id=f"e{i:05d}",
        timestamp=FIXED + datetime.timedelta(seconds=i),
        src_ip="203.0.113.10",
        dst_ip="10.0.0.5",
        dst_port=3389,
        protocol="TCP",
        action="block",
        parser_name="pf_firewall",
        parse_status="parsed",
        source_name="firewall.json",
        safe_message_excerpt=f"BLOCK TCP e{i:05d}",
    )


def _signal_dict(i: int, *, dup: bool = False) -> dict:
    # `dup` produces byte-identical content under a distinct signal_id to prove
    # summary de-duplication; long rule names prove field truncation.
    return {
        "signal_id": f"s{i:05d}",
        "rule_id": "remote_service_probe" if not dup else "remote_service_probe",
        "rule_name": LONG_RULE_NAME,
        "signal_type": "rdp_probe",
        "signal_family": "service_probing",
        "severity": "medium",
        "confidence_score": 0.6,
        "description": "d" * 4000,
        "mitre_techniques": ["T1021.001"],
        "matched_event_ids": [f"e{i:05d}"],
    }


def _context(n_events: int, n_signals: int) -> tuple[TriageIncidentContext, list[dict]]:
    events = [_event(i) for i in range(n_events)]
    incident = IncidentBundle(
        incident_id="INC-A",
        incident_type="rdp_probe",
        incident_family="service_probing",
        title="RDP probe",
        severity="medium",
        confidence=0.6,
        first_seen=FIXED,
        last_seen=events[-1].timestamp,
        primary_entity="203.0.113.10",
        target_entities=["10.0.0.5"],
        signal_ids=[f"s{i:05d}" for i in range(n_signals)],
        event_ids=[e.event_id for e in events],
        context_event_ids=[],
        evidence=[
            DetectionEvidence(
                event_id="e00000", quote="q", reason="r", source="pf_firewall",
                original_fields={}, correlation_context={},
            )
        ],
        metrics={},
        mitre_techniques=["T1021.001"],
        merge_key="m1",
    )
    context = TriageIncidentContext(incident=incident, events=events, context_events=[])
    detected_signals = [_signal_dict(i, dup=(i % 2 == 0)) for i in range(n_signals)]
    return context, detected_signals


def test_triage_input_stays_bounded_with_thousands_of_signals_and_events() -> None:
    context, detected_signals = _context(n_events=1500, n_signals=1200)
    result = build_triage_input(context, detected_signals, candidate_evidence=[])

    settings = get_settings()
    assert len(result.signal_views) <= MAX_SIGNAL_VIEWS
    assert len(result.signal_summaries) <= MAX_SIGNAL_VIEWS
    assert len(result.limited_context_events) <= settings.max_context_events

    # Long rule names are truncated inside the bounded views.
    for view in result.signal_views:
        assert len(view.rule_name) <= MAX_SHORT_FIELD_CHARS + len("... [TRUNCATED]")

    # Serialized provider-facing input stays far within the token budget
    # (~4 chars/token is a conservative lower bound).
    serialized = json.dumps(
        {
            "signal_summaries": result.signal_summaries,
            "signal_views": [v.model_dump() for v in result.signal_views],
            "limited_context_events": [e.model_dump() for e in result.limited_context_events],
            "candidate_evidence": [c.model_dump() for c in result.candidate_evidence],
        }
    )
    assert len(serialized) < settings.max_prompt_tokens * 4


def test_triage_input_is_deterministic() -> None:
    context, detected_signals = _context(n_events=1500, n_signals=1200)
    first = build_triage_input(context, detected_signals, candidate_evidence=[])
    second = build_triage_input(context, detected_signals, candidate_evidence=[])
    assert first.signal_summaries == second.signal_summaries
    assert [v.signal_id for v in first.signal_views] == [
        v.signal_id for v in second.signal_views
    ]
    assert [e.event_id for e in first.limited_context_events] == [
        e.event_id for e in second.limited_context_events
    ]


def test_routing_still_sees_complete_attached_rule_id_set() -> None:
    """Bounding the provider-facing input must not shrink the rule-ID set that
    deterministic routing derives from the full attached signal_map."""
    n = 1200
    signal_map = {
        f"s{i:05d}": DetectionSignal(
            signal_id=f"s{i:05d}",
            rule_id=f"rule_{i % 7}",
            rule_version="1",
            rule_name=LONG_RULE_NAME,
            signal_type="rdp_probe",
            signal_family="service_probing",
            severity="medium",
            confidence=0.6,
            first_seen=FIXED,
            last_seen=FIXED,
            event_ids=[f"e{i:05d}"],
            primary_entity="203.0.113.10",
            target_entities=["10.0.0.5"],
            metrics={},
            evidence=[
                DetectionEvidence(
                    event_id=f"e{i:05d}", quote="q", reason="r", source="pf",
                    original_fields={}, correlation_context={},
                )
            ],
            mitre_techniques=["T1021.001"],
            tags=[],
        )
        for i in range(n)
    }
    signal_ids = list(signal_map.keys())
    rule_ids = frozenset(
        signal_map[sid].rule_id for sid in signal_ids if sid in signal_map
    )
    # All 7 distinct rule families remain visible to routing.
    assert rule_ids == {f"rule_{k}" for k in range(7)}
