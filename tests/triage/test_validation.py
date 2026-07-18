from datetime import datetime, timezone

from agent.triage.validation import validate_evidence
from agent.triage.claims import validate_claims
from agent.triage.models import TriageSubmission, TriageInput, SafeEventView, EvidenceCandidate, TriageClaim
from agent.triage.enums import TriageVerdict, TriageSeverity, RejectionReason, ClaimType

def test_validate_evidence_success():
    event_time = datetime(2024, 1, 1, tzinfo=timezone.utc)
    submission = TriageSubmission(
        triage_verdict=TriageVerdict.CONFIRMED_INCIDENT,
        incident_type="test",
        severity=TriageSeverity.HIGH,
        confidence_score=0.9,
        summary="Test",
        selected_evidence_ids=["ev_1"],
        claims=[]
    )
    
    triage_input = TriageInput(
        incident_id="INC-1",
        incident_type="test",
        incident_family="test",
        title="test",
        deterministic_severity="high",
        deterministic_confidence=1.0,
        first_seen="2024",
        last_seen="2024",
        primary_entity="ip",
        candidate_evidence=[
            EvidenceCandidate(
                evidence_id="ev_1",
                event_id="EVT-1",
                quote="error occurred",
                reason="test",
                source="test_parser",
                canonical_fields={"timestamp": event_time.isoformat()},
                vendor_original_fields={"src_ip": "1.2.3.4"}
            )
        ],
        limited_context_events=[
            SafeEventView(
                event_id="EVT-1",
                timestamp="2024",
                parser_name="test_parser",
                source_name="test_source",
                sanitized_message_excerpt="An error occurred here",
                src_ip="1.2.3.4"
            )
        ]
    )
    
    from agent.schema import CanonicalLogEvent
    from agent.detection.models import IncidentBundle
    from agent.triage.models import TriageIncidentContext
    trusted_events = [CanonicalLogEvent(event_id="EVT-1", timestamp=event_time, observed_at=datetime.now(timezone.utc), parse_status="success", parser_name="test_parser", source_name="test_source", safe_message_excerpt="An error occurred here", parser_metadata={"src_ip": "1.2.3.4"})]
    bundle = IncidentBundle(incident_id="INC-1", incident_type="test", incident_family="test", title="test", severity="low", confidence=1.0, primary_entity="ip", target_entities=[], signal_ids=[], evidence=[], metrics={}, mitre_techniques=[], merge_key="mock", event_ids=[], context_event_ids=[], first_seen=datetime.now(timezone.utc), last_seen=datetime.now(timezone.utc))
    context = TriageIncidentContext(incident=bundle, events=trusted_events)
    results = validate_evidence(submission, triage_input, context)
    assert len(results) == 1
    assert results[0].status == "validated"

def test_validate_evidence_quote_mismatch():
    submission = TriageSubmission(
        triage_verdict=TriageVerdict.CONFIRMED_INCIDENT,
        incident_type="test",
        severity=TriageSeverity.HIGH,
        confidence_score=0.9,
        summary="Test",
        selected_evidence_ids=["ev_1"],
        claims=[]
    )
    
    triage_input = TriageInput(
        incident_id="INC-1",
        incident_type="test",
        incident_family="test",
        title="test",
        deterministic_severity="high",
        deterministic_confidence=1.0,
        first_seen="2024",
        last_seen="2024",
        primary_entity="ip",
        candidate_evidence=[
            EvidenceCandidate(
                evidence_id="ev_1",
                event_id="EVT-1",
                quote="hallucinated quote",
                reason="test",
                source="test_parser",
                canonical_fields={},
                vendor_original_fields={"src_ip": "1.2.3.4"}
            )
        ],
        limited_context_events=[
            SafeEventView(
                event_id="EVT-1",
                timestamp="2024",
                parser_name="test_parser",
                source_name="test_source",
                sanitized_message_excerpt="An error occurred here",
                src_ip="1.2.3.4"
            )
        ]
    )
    
    from agent.schema import CanonicalLogEvent
    from agent.detection.models import IncidentBundle
    from agent.triage.models import TriageIncidentContext
    from datetime import datetime, timezone
    trusted_events = [CanonicalLogEvent(event_id="EVT-1", timestamp=None, observed_at=datetime.now(timezone.utc), parse_status="success", parser_name="test_parser", source_name="test_source", safe_message_excerpt="An error occurred here")]
    bundle = IncidentBundle(incident_id="INC-1", incident_type="test", incident_family="test", title="test", severity="low", confidence=1.0, primary_entity="ip", target_entities=[], signal_ids=[], evidence=[], metrics={}, mitre_techniques=[], merge_key="mock", event_ids=[], context_event_ids=[], first_seen=datetime.now(timezone.utc), last_seen=datetime.now(timezone.utc))
    context = TriageIncidentContext(incident=bundle, events=trusted_events)
    results = validate_evidence(submission, triage_input, context)
    assert len(results) == 1
    assert results[0].status == "rejected"
    assert results[0].rejection_reason == RejectionReason.EVIDENCE_REJECTED

def test_validate_evidence_fields_mismatch():
    submission = TriageSubmission(
        triage_verdict=TriageVerdict.CONFIRMED_INCIDENT,
        incident_type="test",
        severity=TriageSeverity.HIGH,
        confidence_score=0.9,
        summary="Test",
        selected_evidence_ids=["ev_1"],
        claims=[]
    )
    
    triage_input = TriageInput(
        incident_id="INC-1",
        incident_type="test",
        incident_family="test",
        title="test",
        deterministic_severity="high",
        deterministic_confidence=1.0,
        first_seen="2024",
        last_seen="2024",
        primary_entity="ip",
        candidate_evidence=[
            EvidenceCandidate(
                evidence_id="ev_1",
                event_id="EVT-1",
                quote="error",
                reason="test",
                source="test_parser",
                canonical_fields={},
                vendor_original_fields={"src_ip": "9.9.9.9"} # Mismatch
            )
        ],
        limited_context_events=[
            SafeEventView(
                event_id="EVT-1",
                timestamp="2024",
                parser_name="test_parser",
                source_name="test_source",
                sanitized_message_excerpt="An error occurred here",
                src_ip="1.2.3.4"
            )
        ]
    )
    
    from agent.schema import CanonicalLogEvent
    from agent.detection.models import IncidentBundle
    from agent.triage.models import TriageIncidentContext
    from datetime import datetime, timezone
    trusted_events = [CanonicalLogEvent(event_id="EVT-1", timestamp=None, observed_at=datetime.now(timezone.utc), parse_status="success", parser_name="test_parser", source_name="test_source", safe_message_excerpt="An error occurred here")]
    bundle = IncidentBundle(incident_id="INC-1", incident_type="test", incident_family="test", title="test", severity="low", confidence=1.0, primary_entity="ip", target_entities=[], signal_ids=[], evidence=[], metrics={}, mitre_techniques=[], merge_key="mock", event_ids=[], context_event_ids=[], first_seen=datetime.now(timezone.utc), last_seen=datetime.now(timezone.utc))
    context = TriageIncidentContext(incident=bundle, events=trusted_events)
    results = validate_evidence(submission, triage_input, context)
    assert len(results) == 1
    assert results[0].status == "rejected"
    assert results[0].rejection_reason == RejectionReason.EVIDENCE_REJECTED

def test_validate_claims():
    from agent.triage.models import EvidenceValidationResult
    claims = [
        TriageClaim(
            claim_id="cl_1",
            claim_type=ClaimType.OTHER,
            statement="Test",
            supporting_evidence_ids=["ev_1"],
            supporting_event_ids=["EVT-1"]
        ),
        TriageClaim(
            claim_id="cl_2",
            claim_type=ClaimType.OTHER,
            statement="Test",
            supporting_evidence_ids=["ev_2"], # Hallucinated or rejected
            supporting_event_ids=["EVT-1"]
        )
    ]
    
    validated_evidence = [
        EvidenceValidationResult(evidence_id="ev_1", event_id="EVT-1", status="validated"),
        EvidenceValidationResult(evidence_id="ev_2", event_id="EVT-1", status="rejected", rejection_reason=RejectionReason.EVIDENCE_REJECTED)
    ]
    
    accepted, rejected = validate_claims(claims, validated_evidence)
    assert len(accepted) == 1
    assert accepted[0].claim_id == "cl_1"
    assert len(rejected) == 1
    assert rejected[0]["claim_id"] == "cl_2"
    assert rejected[0]["reason"] == RejectionReason.EVIDENCE_REJECTED.value

def test_provenance_multiple_evidence_same_event():
    from agent.schema import CanonicalLogEvent
    from agent.detection.models import IncidentBundle, DetectionEvidence
    from agent.triage.models import TriageIncidentContext
    from datetime import datetime, timezone
    
    trusted_events = [CanonicalLogEvent(event_id="EVT-1", timestamp=None, observed_at=datetime.now(timezone.utc), parse_status="success", parser_name="test_parser", source_name="test_source", safe_message_excerpt="An error occurred here")]
    
    # 2 pieces of evidence for the same event
    ev1 = DetectionEvidence(event_id="EVT-1", quote="error", reason="test", source="rule_1", original_fields={}, correlation_context={})
    ev2 = DetectionEvidence(event_id="EVT-1", quote="occurred", reason="test2", source="rule_2", original_fields={}, correlation_context={})
    
    bundle = IncidentBundle(incident_id="INC-1", incident_type="test", incident_family="test", title="test", severity="low", confidence=1.0, primary_entity="ip", target_entities=[], signal_ids=[], evidence=[ev1, ev2], metrics={}, mitre_techniques=[], merge_key="mock", event_ids=[], context_event_ids=[], first_seen=datetime.now(timezone.utc), last_seen=datetime.now(timezone.utc))
    context = TriageIncidentContext(incident=bundle, events=trusted_events)
    
    triage_input = TriageInput(
        incident_id="INC-1", incident_type="test", incident_family="test", title="test",
        deterministic_severity="high", deterministic_confidence=1.0, first_seen="2024", last_seen="2024", primary_entity="ip",
        candidate_evidence=[
            EvidenceCandidate(evidence_id="ev_1", event_id="EVT-1", quote="error", reason="test", source="rule_1", canonical_fields={}, vendor_original_fields={}),
            EvidenceCandidate(evidence_id="ev_2", event_id="EVT-1", quote="occurred", reason="test2", source="rule_2", canonical_fields={}, vendor_original_fields={})
        ]
    )
    
    submission = TriageSubmission(
        triage_verdict=TriageVerdict.CONFIRMED_INCIDENT, incident_type="test", severity=TriageSeverity.HIGH,
        confidence_score=0.9, summary="Test", selected_evidence_ids=["ev_1", "ev_2"], claims=[]
    )
    
    results = validate_evidence(submission, triage_input, context)
    assert len(results) == 2
    assert all(r.status == "validated" for r in results)

def test_correlation_context_allowlist():
    from agent.schema import CanonicalLogEvent
    from agent.detection.models import IncidentBundle
    from agent.triage.models import TriageIncidentContext
    from datetime import datetime, timezone
    
    trusted_events = [CanonicalLogEvent(event_id="EVT-1", timestamp=None, observed_at=datetime.now(timezone.utc), parse_status="success", parser_name="test_parser", source_name="test_source", safe_message_excerpt="An error occurred here")]
    bundle = IncidentBundle(incident_id="INC-1", incident_type="test", incident_family="test", title="test", severity="low", confidence=1.0, primary_entity="1.1.1.1", target_entities=["2.2.2.2"], signal_ids=[], evidence=[], metrics={}, mitre_techniques=[], merge_key="mock", event_ids=[], context_event_ids=[], first_seen=datetime.now(timezone.utc), last_seen=datetime.now(timezone.utc))
    context = TriageIncidentContext(incident=bundle, events=trusted_events)
    
    triage_input = TriageInput(
        incident_id="INC-1", incident_type="test", incident_family="test", title="test",
        deterministic_severity="high", deterministic_confidence=1.0, first_seen="2024", last_seen="2024", primary_entity="1.1.1.1", target_entities=["2.2.2.2"],
        candidate_evidence=[
            EvidenceCandidate(
                evidence_id="ev_1", event_id="EVT-1", quote="error", reason="test", source="test_parser", canonical_fields={}, vendor_original_fields={},
                correlation_context={
                    "target_entity": "2.2.2.2", 
                    "destination_port": 443, 
                    "protocol": "tcp"
                }
            )
        ]
    )
    
    submission = TriageSubmission(
        triage_verdict=TriageVerdict.CONFIRMED_INCIDENT, incident_type="test", severity=TriageSeverity.HIGH,
        confidence_score=0.9, summary="Test", selected_evidence_ids=["ev_1"], claims=[]
    )
    
    results = validate_evidence(submission, triage_input, context)
    assert len(results) == 1
    assert results[0].status == "validated"
