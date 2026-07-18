from typing import List, Dict, Any, Optional
from agent.triage.models import TriageSubmission, EvidenceValidationResult, TriageClaim
from agent.triage.enums import TriageVerdict

def generate_report(
    submission: TriageSubmission,
    validated_evidence: List[EvidenceValidationResult],
    accepted_claims: List[TriageClaim],
    incident_metadata: Dict[str, Any],
    review_reason: str,
    recommended_actions: Optional[List[str]] = None,
    deterministic_facts: Optional[Dict[str, Any]] = None,
) -> str:
    
    valid_ev_ids = [e.evidence_id for e in validated_evidence if e.status == "validated"]
    rejected_ev = [e for e in validated_evidence if e.status == "rejected"]
    
    report = []
    report.append(f"# Triage Report: {incident_metadata.get('title', 'Unknown Incident')}")
    report.append(f"**Verdict:** {submission.triage_verdict.value.upper()}")
    report.append(f"**Severity:** {submission.severity.value.upper()}")
    report.append(f"**Confidence:** {submission.confidence_score}")
    
    if submission.triage_verdict == TriageVerdict.NEEDS_REVIEW:
        report.append(f"**Review Reason:** {review_reason}")
        
    report.append("\n## Triage Summary")
    report.append(submission.summary)

    if deterministic_facts:
        ports = ", ".join(
            str(port) for port in deterministic_facts["destination_ports"]
        ) or "unknown"
        protocols = ", ".join(deterministic_facts["protocols"]) or "unknown"
        report.append("\n## Deterministic Incident Facts")
        report.append(f"- Source: {deterministic_facts['primary_entity']}")
        report.append(f"- Event count: {deterministic_facts['event_count']}")
        report.append(
            "- Distinct target count: "
            f"{deterministic_facts['distinct_target_count']}"
        )
        report.append(f"- Protocols: {protocols}")
        report.append(f"- Destination ports: {ports}")
        report.append(
            "- All attempts blocked: "
            f"{'yes' if deterministic_facts['all_attempts_blocked'] else 'no'}"
        )
        report.append(
            f"- SYN-only TCP traffic: {'yes' if deterministic_facts['syn_only'] else 'no'}"
        )
    
    report.append("\n## Validated Evidence")
    if valid_ev_ids:
        for ev_id in valid_ev_ids:
            report.append(f"- Evidence ID: {ev_id}")
    else:
        report.append("No validated evidence.")
        
    if rejected_ev:
        report.append("\n## Rejected Evidence Summary")
        for ev in rejected_ev:
            report.append(f"- ID: {ev.evidence_id} | Reason: {ev.rejection_reason.value if ev.rejection_reason else 'unknown'}")
            
    report.append("\n## Accepted Claims")
    if accepted_claims:
        for claim in accepted_claims:
            report.append(f"- {claim.claim_type.value}: {claim.statement}")
    else:
        report.append("No high-impact claims accepted.")
        
    report.append("\n## Recommended Analyst Actions")
    if recommended_actions:
        for action in recommended_actions:
            report.append(f"- {action}")
    elif submission.triage_verdict == TriageVerdict.FALSE_POSITIVE:
        report.append("- No immediate action required. Verify benign nature.")
    elif submission.triage_verdict == TriageVerdict.CONFIRMED_INCIDENT:
        report.append("- Isolate affected hosts if applicable.")
        report.append("- Review related authentication logs.")
    else:
        report.append("- Review evidence and verify claims manually.")
        
    return "\n".join(report)
