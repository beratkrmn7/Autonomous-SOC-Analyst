"""Phase 6E.3 focused tests: deterministic report wording, family-aware
recommendations, and separated confidence presentation."""

from __future__ import annotations

import datetime

from agent.detection.models import IncidentBundle
from agent.nodes import action_recommendation_node, evidence_validation_node, reporter_node
from agent.schema import CanonicalLogEvent
from agent.triage.input_builder import build_triage_input
from agent.triage.models import TriageIncidentContext


FIXED = datetime.datetime(2026, 7, 10, 6, 0, 0, tzinfo=datetime.timezone.utc)

_COMPROMISE_PHRASES = (
    "successfully accessed",
    "fully compromised",
    "exploit succeeded",
    "authentication bypass",
    "credentials were stolen",
    "attacker gained access",
)


def _exposure_incident() -> tuple[IncidentBundle, list[CanonicalLogEvent]]:
    events = [
        CanonicalLogEvent(
            event_id="exposure-1",
            timestamp=FIXED,
            src_ip="8.8.8.8",
            dst_ip="203.0.113.50",
            translated_dst_ip="10.0.0.60",
            dst_port=6379,
            protocol="TCP",
            action="allow",
            tcp_flags="SYN,ACK",
            inbound_zone="wan",
            outbound_zone="lan",
            nat_type="dnat",
            packets=1,
            bytes=64,
            parser_name="pf_firewall",
            parse_status="parsed",
            source_name="firewall.json",
            safe_message_excerpt="ALLOW TCP 8.8.8.8 -> 10.0.0.60:6379 flags=SA",
        )
    ]
    incident = IncidentBundle(
        incident_id="INC-EXPOSURE",
        incident_type="dnat_sensitive_service_exposure",
        incident_family="firewall_exposure",
        title="Detected DNAT sensitive service exposure",
        severity="high",
        confidence=0.85,
        first_seen=events[0].timestamp,
        last_seen=events[0].timestamp,
        primary_entity="10.0.0.60",
        target_entities=["8.8.8.8"],
        signal_ids=["SIG-EXPOSURE"],
        event_ids=[events[0].event_id],
        context_event_ids=[],
        evidence=[],
        metrics={},
        mitre_techniques=[],
        merge_key="firewall_exposure_1",
    )
    return incident, events


def _sequence_incident() -> tuple[IncidentBundle, list[CanonicalLogEvent]]:
    blocked = [
        CanonicalLogEvent(
            event_id=f"blocked-{i}",
            timestamp=FIXED + datetime.timedelta(seconds=i),
            src_ip="198.51.100.20",
            dst_ip="10.0.0.30",
            dst_port=22,
            protocol="TCP",
            action="block",
            tcp_flags="SYN",
            parser_name="pf_firewall",
            parse_status="parsed",
            source_name="firewall.json",
            safe_message_excerpt=f"BLOCK TCP 198.51.100.20 -> 10.0.0.30:22 flags=S #{i}",
        )
        for i in range(3)
    ]
    allowed = CanonicalLogEvent(
        event_id="allowed-1",
        timestamp=FIXED + datetime.timedelta(seconds=10),
        src_ip="198.51.100.20",
        dst_ip="10.0.0.30",
        dst_port=22,
        protocol="TCP",
        action="allow",
        tcp_flags="SYN,ACK",
        parser_name="pf_firewall",
        parse_status="parsed",
        source_name="firewall.json",
        safe_message_excerpt="ALLOW TCP 198.51.100.20 -> 10.0.0.30:22 flags=SA",
    )
    events = [*blocked, allowed]
    incident = IncidentBundle(
        incident_id="INC-SEQUENCE",
        incident_type="scan_followed_by_allowed_connection",
        incident_family="network_intrusion_candidate",
        title="Detected scan followed by allowed connection",
        severity="high",
        confidence=0.8,
        first_seen=events[0].timestamp,
        last_seen=events[-1].timestamp,
        primary_entity="198.51.100.20",
        target_entities=["10.0.0.30"],
        signal_ids=["SIG-SEQUENCE"],
        event_ids=[e.event_id for e in events],
        context_event_ids=[],
        evidence=[],
        metrics={},
        mitre_techniques=["T1046"],
        merge_key="sequence_1",
    )
    return incident, events


def _run_pipeline(
    incident: IncidentBundle,
    events: list[CanonicalLogEvent],
    *,
    verdict: str,
    severity: str,
    confidence: float,
    summary: str,
    claims: list[dict] | None = None,
    return_state: bool = False,
):
    context = TriageIncidentContext(incident=incident, events=events)
    evidence = {
        "event_id": events[0].event_id,
        "quote": events[0].safe_message_excerpt,
        "reason": "evidence",
        "source": "pf_firewall",
        "original_fields": {},
        "correlation_context": {},
    }
    triage_input = build_triage_input(context, [], [evidence])
    evidence_id = triage_input.candidate_evidence[0].evidence_id
    resolved_claims = []
    for claim in claims or []:
        resolved = dict(claim)
        resolved["supporting_evidence_ids"] = [evidence_id]
        resolved["supporting_event_ids"] = [events[0].event_id]
        resolved_claims.append(resolved)

    state = {
        "incident_id": incident.incident_id,
        "incident": context.model_dump(mode="json"),
        "triage_submission": {
            "triage_verdict": verdict,
            "incident_type": incident.incident_type,
            "severity": severity,
            "confidence_score": confidence,
            "summary": summary,
            "selected_evidence_ids": [evidence_id],
            "claims": resolved_claims,
        },
        "triage_verdict": verdict,
        "incident_type": incident.incident_type,
        "severity": severity,
        "confidence_score": confidence,
        "safe_triage_input": triage_input.model_dump(mode="json"),
        "review_reason": "none",
    }

    state.update(evidence_validation_node(state))
    state.update(action_recommendation_node(state))
    report = reporter_node(state)["final_report"]
    if return_state:
        return report, state
    return report


# --- 17 & 18: exposure report never asserts compromise ----------------------


def test_firewall_exposure_report_contains_no_compromise_claims() -> None:
    incident, events = _exposure_incident()
    fake_summary = (
        "The attacker successfully accessed the Redis service and the "
        "database was fully compromised via a successful authentication bypass."
    )
    report = _run_pipeline(
        incident,
        events,
        verdict="confirmed_incident",
        severity="critical",
        confidence=0.95,
        summary=fake_summary,
    )

    # The untrusted model summary (an affirmative compromise claim) must not
    # survive into the report at all - only the deterministic, hedged
    # wording ("does not prove ... compromise") is allowed to mention these
    # terms.
    assert fake_summary not in report
    lowered = report.lower()
    for phrase in _COMPROMISE_PHRASES:
        assert phrase not in lowered

    assert "SUSPICIOUS_ACTIVITY" in report  # capped from confirmed_incident


# --- Merge-blocker fix 2: ClaimType.OTHER cannot bypass the firewall-only
# claim guardrail --------------------------------------------------------


def test_claim_type_other_compromise_statement_is_rejected_and_never_reported() -> None:
    incident, events = _exposure_incident()
    compromise_statement = "The host was compromised and the attacker gained access."

    report, state = _run_pipeline(
        incident,
        events,
        verdict="suspicious_activity",
        severity="high",
        confidence=0.7,
        summary="summary",
        claims=[
            {
                "claim_id": "claim-1",
                "claim_type": "other",
                "statement": compromise_statement,
            }
        ],
        return_state=True,
    )

    assert state["validated_claims"] == []
    rejected_reasons = {c["reason"] for c in state["rejected_claims"]}
    assert "firewall_only_evidence_insufficient" in rejected_reasons
    assert compromise_statement not in report
    assert "No high-impact claims accepted." in report


def test_legacy_non_firewall_claim_type_other_is_still_accepted() -> None:
    """Legacy (non-firewall-only) incidents must keep accepting a
    well-supported ClaimType.OTHER claim - only firewall-only exposure/
    sequence incidents reject it."""
    from agent.triage.claims import validate_claims
    from agent.triage.enums import ClaimType
    from agent.triage.models import EvidenceValidationResult, TriageClaim

    claim = TriageClaim(
        claim_id="claim-1",
        claim_type=ClaimType.OTHER,
        statement="The traffic pattern matches a known benign backup job.",
        supporting_event_ids=["event-1"],
        supporting_evidence_ids=["evidence-1"],
    )
    evidence = [
        EvidenceValidationResult(
            evidence_id="evidence-1", event_id="event-1", status="validated"
        )
    ]

    accepted, rejected = validate_claims(
        [claim], evidence, firewall_only_evidence=False
    )

    assert rejected == []
    assert len(accepted) == 1
    assert accepted[0].claim_id == "claim-1"


def test_firewall_exposure_report_uses_deterministic_summary_over_fake_provider_summary() -> None:
    incident, events = _exposure_incident()
    report = _run_pipeline(
        incident,
        events,
        verdict="suspicious_activity",
        severity="high",
        confidence=0.7,
        summary="Fake summary: the host was fully compromised by the attacker.",
    )

    assert "Fake summary" not in report
    assert "fully compromised" not in report.lower()
    assert "policy exposure" in report.lower()


# --- 19: blocked-then-allowed sequence wording -------------------------------


def test_blocked_then_allowed_sequence_report_states_success_not_proven() -> None:
    incident, events = _sequence_incident()
    report = _run_pipeline(
        incident,
        events,
        verdict="suspicious_activity",
        severity="high",
        confidence=0.75,
        summary="Model summary claiming the SSH session succeeded.",
    )

    lowered = report.lower()
    assert "allowed firewall event" in lowered
    assert "application-level success" in lowered
    assert "not prove" in lowered or "does not prove" in lowered


# --- 20 & 21: exposure recommended actions ----------------------------------


def test_exposure_recommendations_focus_on_firewall_and_service_logs() -> None:
    incident, events = _exposure_incident()
    context = TriageIncidentContext(incident=incident, events=events)
    evidence = {
        "event_id": events[0].event_id,
        "quote": events[0].safe_message_excerpt,
        "reason": "evidence",
        "source": "pf_firewall",
        "original_fields": {},
        "correlation_context": {},
    }
    triage_input = build_triage_input(context, [], [evidence])
    evidence_id = triage_input.candidate_evidence[0].evidence_id
    state = {
        "incident_id": incident.incident_id,
        "incident": context.model_dump(mode="json"),
        "triage_submission": {
            "triage_verdict": "suspicious_activity",
            "incident_type": incident.incident_type,
            "severity": "high",
            "confidence_score": 0.8,
            "summary": "summary",
            "selected_evidence_ids": [evidence_id],
            "claims": [],
        },
        "triage_verdict": "suspicious_activity",
        "incident_type": incident.incident_type,
        "severity": "high",
        "confidence_score": 0.8,
        "safe_triage_input": triage_input.model_dump(mode="json"),
        "review_reason": "none",
    }
    state.update(evidence_validation_node(state))

    actions = action_recommendation_node(state)["recommended_actions"]
    joined = " ".join(actions).lower()

    assert any("firewall" in a.lower() or "nat" in a.lower() for a in actions)
    assert any("service" in a.lower() or "authentication" in a.lower() for a in actions)
    assert "isolat" not in joined
    assert "password reset" not in joined
    assert "reset the password" not in joined


# --- 22: separated confidence presentation ----------------------------------


def test_report_displays_detection_and_triage_confidence_separately() -> None:
    incident, events = _exposure_incident()
    report = _run_pipeline(
        incident,
        events,
        verdict="suspicious_activity",
        severity="high",
        confidence=0.6789,
        summary="summary",
    )

    assert "Detection confidence score:" in report
    assert "Triage confidence score:" in report
    assert "0.85" in report  # deterministic detection confidence, unrounded input
    assert "0.68" in report  # rounded triage confidence (0.6789 -> 0.68)
