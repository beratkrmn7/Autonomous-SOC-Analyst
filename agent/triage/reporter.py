from typing import List, Dict, Any, Optional
from agent.triage.models import TriageSubmission, EvidenceValidationResult, TriageClaim
from agent.triage.enums import TriageVerdict
from agent.triage.guardrails import (
    FirewallExposureFacts,
    IncidentFacts,
    ScanProbeFacts,
    SequenceFacts,
)


def _format_confidence(value: Optional[float]) -> str:
    if value is None:
        return "unavailable"
    return f"{value:.2f}"


def _render_scan_probe_facts(facts: ScanProbeFacts) -> List[str]:
    ports = ", ".join(str(port) for port in facts.destination_ports) or "unknown"
    protocols = ", ".join(facts.protocols) or "unknown"
    return [
        "\n## Deterministic Incident Facts",
        f"- Source: {facts.primary_entity}",
        f"- Event count: {facts.event_count}",
        f"- Distinct target count: {facts.distinct_target_count}",
        f"- Protocols: {protocols}",
        f"- Destination ports: {ports}",
        f"- All attempts blocked: {'yes' if facts.all_attempts_blocked else 'no'}",
        f"- SYN-only TCP traffic: {'yes' if facts.syn_only else 'no'}",
    ]


def _render_exposure_facts(facts: FirewallExposureFacts) -> List[str]:
    original_ports = (
        ", ".join(str(port) for port in facts.original_destination_ports) or "none"
    )
    effective_ports = (
        ", ".join(str(port) for port in facts.effective_destination_ports) or "none"
    )
    zones = (
        ", ".join(facts.inbound_zones) + " -> " + ", ".join(facts.outbound_zones)
        if facts.inbound_zones or facts.outbound_zones
        else "unknown"
    )
    lines = [
        "\n## Deterministic Firewall Exposure Facts",
        f"- Exposure type: {facts.incident_type}",
        f"- Service: {facts.service or 'unclassified'}",
        f"- Source IPs: {', '.join(facts.source_ips) or 'unknown'}"
        f" (external: {', '.join(facts.external_source_ips) or 'none'})",
        f"- Original destination IPs: {', '.join(facts.original_destination_ips) or 'unknown'}",
        f"- Original destination ports: {original_ports}",
        f"- Effective destination IPs: {', '.join(facts.effective_destination_ips) or 'unknown'}",
        f"- Effective destination ports: {effective_ports}",
        f"- Incident primary entity: {facts.incident_primary_entity}",
        f"- Zones (inbound -> outbound): {zones}",
        f"- NAT observed: {'yes' if facts.nat_event_count else 'no'}",
        f"- Allowed events: {facts.allowed_event_count} | Blocked events: {facts.blocked_event_count}",
    ]
    if facts.total_packets or facts.total_bytes or facts.max_duration_ms:
        lines.append(
            "- Packets/Bytes/Max duration(ms): "
            f"{facts.total_packets}/{facts.total_bytes}/{facts.max_duration_ms}"
        )
    lines.extend(
        [
            f"- Policy exposure observed: {'yes' if facts.policy_allow_observed else 'no'}",
            f"- Transport activity observed: {'yes' if facts.transport_activity_observed else 'no'}",
            "- Application success proven: "
            f"{'yes' if facts.application_success_proven else 'no/unknown'}",
            f"- Compromise proven: {'yes' if facts.compromise_proven else 'no'}",
        ]
    )
    return lines


def _render_sequence_facts(facts: SequenceFacts) -> List[str]:
    return [
        "\n## Deterministic Sequence Facts",
        f"- Sequence type(s): {', '.join(facts.sequence_signal_types) or facts.incident_type}",
        f"- Source: {facts.primary_entity}",
        f"- Blocked events: {facts.blocked_event_count} | Allowed events: {facts.allowed_event_count}",
        "- Application success proven: "
        f"{'yes' if facts.application_success_proven else 'no/unknown'}",
        f"- Compromise proven: {'yes' if facts.compromise_proven else 'no'}",
    ]


def _render_deterministic_facts(facts: Optional[IncidentFacts]) -> List[str]:
    if facts is None:
        return []
    if isinstance(facts, ScanProbeFacts):
        return _render_scan_probe_facts(facts)
    if isinstance(facts, FirewallExposureFacts):
        return _render_exposure_facts(facts)
    if isinstance(facts, SequenceFacts):
        return _render_sequence_facts(facts)
    return []


def generate_report(
    submission: TriageSubmission,
    validated_evidence: List[EvidenceValidationResult],
    accepted_claims: List[TriageClaim],
    incident_metadata: Dict[str, Any],
    review_reason: str,
    recommended_actions: Optional[List[str]] = None,
    deterministic_facts: Optional[IncidentFacts] = None,
    deterministic_confidence: Optional[float] = None,
) -> str:

    valid_ev_ids = [e.evidence_id for e in validated_evidence if e.status == "validated"]
    rejected_ev = [e for e in validated_evidence if e.status == "rejected"]

    report = []
    report.append(f"# Triage Report: {incident_metadata.get('title', 'Unknown Incident')}")
    report.append(f"**Verdict:** {submission.triage_verdict.value.upper()}")
    report.append(f"**Severity:** {submission.severity.value.upper()}")
    report.append(
        f"**Detection confidence score:** {_format_confidence(deterministic_confidence)}"
    )
    report.append(
        f"**Triage confidence score:** {_format_confidence(submission.confidence_score)}"
    )
    from agent.triage.provenance import format_event_provenance

    event_count = int(incident_metadata.get("event_count", 0) or 0)
    incident_metrics = incident_metadata.get("incident_metrics", {})
    provenance = format_event_provenance(event_count, incident_metrics)
    if provenance != str(event_count):
        report.append(f"**Events:** {provenance}")

    if submission.triage_verdict == TriageVerdict.NEEDS_REVIEW:
        report.append(f"**Review Reason:** {review_reason}")

    report.append("\n## Triage Summary")
    report.append(submission.summary)

    report.extend(_render_deterministic_facts(deterministic_facts))

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
