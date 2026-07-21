"""Phase 6E.4A focused tests: pure incident merge mechanics (required tests
16-19, plus the explicit fail-conservative-scoring requirement)."""

from __future__ import annotations

import datetime

from agent.correlation.merge import merge_incident_bundles
from agent.detection.config import DetectionSettings
from agent.detection.models import DetectionEvidence, DetectionSignal, IncidentBundle


FIXED = datetime.datetime(2026, 7, 10, 6, 0, 0, tzinfo=datetime.timezone.utc)
LATER = FIXED + datetime.timedelta(minutes=10)

SETTINGS = DetectionSettings()


def _evidence(event_id: str) -> DetectionEvidence:
    return DetectionEvidence(
        event_id=event_id, quote="q", reason="r", source="pf_firewall",
        original_fields={}, correlation_context={},
    )


def _signal(
    signal_id: str,
    *,
    signal_type: str,
    signal_family: str,
    severity: str = "medium",
    confidence: float = 0.6,
    primary_entity: str = "203.0.113.10",
    event_ids: list[str],
    rule_id: str = "rule",
    rule_name: str = "Rule",
    mitre: list[str] | None = None,
    first_seen: datetime.datetime = FIXED,
) -> DetectionSignal:
    return DetectionSignal(
        signal_id=signal_id,
        rule_id=rule_id,
        rule_version="1",
        rule_name=rule_name,
        signal_type=signal_type,
        signal_family=signal_family,
        severity=severity,
        confidence=confidence,
        first_seen=first_seen,
        last_seen=first_seen,
        event_ids=event_ids,
        primary_entity=primary_entity,
        target_entities=["10.0.0.5"],
        metrics={},
        evidence=[_evidence(event_ids[0])],
        mitre_techniques=mitre or [],
        tags=[],
    )


def _bundle(
    incident_id: str,
    *,
    incident_type: str,
    incident_family: str,
    signal_ids: list[str],
    event_ids: list[str],
    context_event_ids: list[str] | None = None,
    primary_signal_id: str,
    severity: str = "medium",
    confidence: float = 0.6,
    target_entities: list[str] | None = None,
    mitre: list[str] | None = None,
    ts: datetime.datetime = FIXED,
    primary_entity: str = "203.0.113.10",
    evidence: list[DetectionEvidence] | None = None,
) -> IncidentBundle:
    return IncidentBundle(
        incident_id=incident_id,
        incident_type=incident_type,
        incident_family=incident_family,
        title=f"Detected {incident_type} from {primary_entity}",
        severity=severity,
        confidence=confidence,
        first_seen=ts,
        last_seen=ts,
        primary_entity=primary_entity,
        target_entities=target_entities or ["10.0.0.5"],
        signal_ids=signal_ids,
        event_ids=event_ids,
        context_event_ids=context_event_ids or [],
        evidence=evidence if evidence is not None else [_evidence(event_ids[0])],
        metrics={"primary_signal_id": primary_signal_id},
        mitre_techniques=mitre or [],
        merge_key=f"mk-{incident_id}",
    )


# --- 16: existing horizontal_scan plus incoming rdp_probe promotes identity
# to rdp_probe while preserving the canonical incident ID


def test_promotion_preserves_canonical_id_and_promotes_identity() -> None:
    sig_h = _signal(
        "SIG-H", signal_type="horizontal_scan", signal_family="network_scanning",
        severity="medium", confidence=0.6, event_ids=["e1", "e2"],
        rule_id="network_scan_horizontal", rule_name="Horizontal Scan",
        mitre=["T1046"],
    )
    sig_r = _signal(
        "SIG-R", signal_type="rdp_probe", signal_family="service_probing",
        severity="high", confidence=0.85, event_ids=["e3"],
        rule_id="remote_service_probe", rule_name="RDP Probe",
        mitre=["T1021.001"], first_seen=LATER,
    )
    canonical = _bundle(
        "INC-CANON", incident_type="horizontal_scan", incident_family="network_scanning",
        signal_ids=["SIG-H"], event_ids=["e1", "e2"], primary_signal_id="SIG-H",
        mitre=["T1046"],
    )
    incoming = _bundle(
        "INC-INCOMING", incident_type="rdp_probe", incident_family="service_probing",
        signal_ids=["SIG-R"], event_ids=["e3"], primary_signal_id="SIG-R",
        severity="high", confidence=0.85, mitre=["T1021.001"], ts=LATER,
    )

    outcome = merge_incident_bundles(
        canonical=canonical, incoming=incoming, available_signals=[sig_h, sig_r],
        settings=SETTINGS, max_context_events=50,
    )

    assert outcome.incident.incident_id == "INC-CANON"
    assert outcome.incident.incident_type == "rdp_probe"
    assert outcome.incident.incident_family == "service_probing"
    assert outcome.identity_promoted is True
    assert "primary_identity_promoted" in outcome.material_changes


# --- 17: all signal IDs remain attached after promotion


def test_all_signal_ids_remain_attached_after_promotion() -> None:
    sig_h = _signal(
        "SIG-H", signal_type="horizontal_scan", signal_family="network_scanning",
        event_ids=["e1"],
    )
    sig_r = _signal(
        "SIG-R", signal_type="rdp_probe", signal_family="service_probing",
        severity="high", confidence=0.9, event_ids=["e2"],
    )
    canonical = _bundle(
        "INC-CANON", incident_type="horizontal_scan", incident_family="network_scanning",
        signal_ids=["SIG-H"], event_ids=["e1"], primary_signal_id="SIG-H",
    )
    incoming = _bundle(
        "INC-INCOMING", incident_type="rdp_probe", incident_family="service_probing",
        signal_ids=["SIG-R"], event_ids=["e2"], primary_signal_id="SIG-R",
    )

    outcome = merge_incident_bundles(
        canonical=canonical, incoming=incoming, available_signals=[sig_h, sig_r],
        settings=SETTINGS, max_context_events=50,
    )

    assert outcome.incident.signal_ids == ["SIG-H", "SIG-R"]
    assert set(outcome.incident.absorbed_signal_ids) == {"SIG-H"}
    assert outcome.primary_signal_id == "SIG-R"


# --- 18: event/context IDs remain disjoint and duplicate-free


def test_event_and_context_ids_remain_disjoint_and_duplicate_free() -> None:
    sig1 = _signal("SIG-1", signal_type="rdp_probe", signal_family="service_probing", event_ids=["e1"])
    sig2 = _signal("SIG-2", signal_type="rdp_probe", signal_family="service_probing", event_ids=["e2"])

    canonical = _bundle(
        "INC-CANON", incident_type="rdp_probe", incident_family="service_probing",
        signal_ids=["SIG-1"], event_ids=["e1"], context_event_ids=["e2", "ctx-1"],
        primary_signal_id="SIG-1",
    )
    # incoming promotes "e2" from context to real incident evidence.
    incoming = _bundle(
        "INC-INCOMING", incident_type="rdp_probe", incident_family="service_probing",
        signal_ids=["SIG-2"], event_ids=["e2"], primary_signal_id="SIG-2",
    )

    outcome = merge_incident_bundles(
        canonical=canonical, incoming=incoming, available_signals=[sig1, sig2],
        settings=SETTINGS, max_context_events=50,
    )

    merged = outcome.incident
    assert set(merged.event_ids) == {"e1", "e2"}
    assert "e2" not in merged.context_event_ids
    assert merged.context_event_ids == ["ctx-1"]
    assert len(merged.event_ids) == len(set(merged.event_ids))
    assert len(merged.context_event_ids) == len(set(merged.context_event_ids))
    assert not (set(merged.event_ids) & set(merged.context_event_ids))


# --- 19: severity/confidence use existing scoring helpers


def test_severity_and_confidence_use_existing_scoring_helpers() -> None:
    from agent.detection.scoring import calculate_incident_confidence, calculate_incident_severity

    sig1 = _signal(
        "SIG-1", signal_type="rdp_probe", signal_family="service_probing",
        severity="high", confidence=0.9, event_ids=["e1"],
    )
    sig2 = _signal(
        "SIG-2", signal_type="rdp_probe", signal_family="service_probing",
        severity="critical", confidence=0.95, event_ids=["e2"],
    )
    canonical = _bundle(
        "INC-CANON", incident_type="rdp_probe", incident_family="service_probing",
        signal_ids=["SIG-1"], event_ids=["e1"], primary_signal_id="SIG-1",
        severity="high", confidence=0.9,
    )
    incoming = _bundle(
        "INC-INCOMING", incident_type="rdp_probe", incident_family="service_probing",
        signal_ids=["SIG-2"], event_ids=["e2"], primary_signal_id="SIG-2",
        severity="critical", confidence=0.95,
    )

    outcome = merge_incident_bundles(
        canonical=canonical, incoming=incoming, available_signals=[sig1, sig2],
        settings=SETTINGS, max_context_events=50,
    )

    expected_severity = calculate_incident_severity(
        [sig1, sig2], outcome.incident.primary_entity, SETTINGS
    )
    expected_confidence = calculate_incident_confidence([sig1, sig2])
    assert outcome.incident.severity == expected_severity
    assert outcome.incident.confidence == expected_confidence
    assert outcome.scoring_recalculated is True


def test_incomplete_signal_rows_preserve_canonical_severity_and_confidence() -> None:
    """If historical signal rows are unavailable/incomplete, fail
    conservatively and preserve the existing canonical severity/confidence
    rather than inventing a value from a partial signal set."""
    sig1 = _signal(
        "SIG-1", signal_type="rdp_probe", signal_family="service_probing",
        severity="high", confidence=0.9, event_ids=["e1"],
    )
    canonical = _bundle(
        "INC-CANON", incident_type="rdp_probe", incident_family="service_probing",
        signal_ids=["SIG-1"], event_ids=["e1"], primary_signal_id="SIG-1",
        severity="high", confidence=0.9,
    )
    incoming = _bundle(
        "INC-INCOMING", incident_type="rdp_probe", incident_family="service_probing",
        signal_ids=["SIG-2"], event_ids=["e2"], primary_signal_id="SIG-2",
        severity="critical", confidence=0.99,
    )

    # SIG-2 is missing from available_signals - simulating an incomplete
    # historical signal set.
    outcome = merge_incident_bundles(
        canonical=canonical, incoming=incoming, available_signals=[sig1],
        settings=SETTINGS, max_context_events=50,
    )

    assert outcome.scoring_recalculated is False
    assert outcome.identity_promoted is False
    assert outcome.incident.severity == "high"
    assert outcome.incident.confidence == 0.9
    assert outcome.incident.incident_type == "rdp_probe"
    # Mechanical fields still merge even though scoring/identity are frozen.
    assert set(outcome.incident.event_ids) == {"e1", "e2"}
    assert set(outcome.incident.signal_ids) == {"SIG-1", "SIG-2"}


def test_evidence_stays_bounded_to_existing_incident_evidence_maximum() -> None:
    from agent.detection.incident_correlation import MAX_INCIDENT_EVIDENCE

    many_event_ids = [f"e{i}" for i in range(MAX_INCIDENT_EVIDENCE + 5)]
    canonical_evidence = [_evidence(eid) for eid in many_event_ids[: MAX_INCIDENT_EVIDENCE]]
    incoming_evidence = [_evidence(eid) for eid in many_event_ids[MAX_INCIDENT_EVIDENCE:]]

    sig1 = _signal("SIG-1", signal_type="rdp_probe", signal_family="service_probing", event_ids=many_event_ids[:1])
    sig2 = _signal("SIG-2", signal_type="rdp_probe", signal_family="service_probing", event_ids=many_event_ids[1:])

    canonical = _bundle(
        "INC-CANON", incident_type="rdp_probe", incident_family="service_probing",
        signal_ids=["SIG-1"], event_ids=many_event_ids[:MAX_INCIDENT_EVIDENCE],
        primary_signal_id="SIG-1", evidence=canonical_evidence,
    )
    incoming = _bundle(
        "INC-INCOMING", incident_type="rdp_probe", incident_family="service_probing",
        signal_ids=["SIG-2"], event_ids=many_event_ids[MAX_INCIDENT_EVIDENCE:],
        primary_signal_id="SIG-2", evidence=incoming_evidence,
    )

    outcome = merge_incident_bundles(
        canonical=canonical, incoming=incoming, available_signals=[sig1, sig2],
        settings=SETTINGS, max_context_events=50,
    )

    assert len(outcome.incident.evidence) <= MAX_INCIDENT_EVIDENCE


def test_merge_is_deterministic_regardless_of_call_repetition() -> None:
    sig1 = _signal("SIG-1", signal_type="rdp_probe", signal_family="service_probing", event_ids=["e1"])
    sig2 = _signal("SIG-2", signal_type="rdp_probe", signal_family="service_probing", event_ids=["e2"])
    canonical = _bundle(
        "INC-CANON", incident_type="rdp_probe", incident_family="service_probing",
        signal_ids=["SIG-1"], event_ids=["e1"], primary_signal_id="SIG-1",
    )
    incoming = _bundle(
        "INC-INCOMING", incident_type="rdp_probe", incident_family="service_probing",
        signal_ids=["SIG-2"], event_ids=["e2"], primary_signal_id="SIG-2",
    )

    outcome1 = merge_incident_bundles(
        canonical=canonical, incoming=incoming, available_signals=[sig1, sig2],
        settings=SETTINGS, max_context_events=50,
    )
    outcome2 = merge_incident_bundles(
        canonical=canonical, incoming=incoming, available_signals=[sig2, sig1],
        settings=SETTINGS, max_context_events=50,
    )

    assert outcome1.incident == outcome2.incident
