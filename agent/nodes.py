import json
import re
import datetime
import logging
from typing import Any
from dotenv import load_dotenv

from agent.config import get_settings
from agent.errors import ConfigurationError
from agent.application.cancellation import JobCancellationRequested
from agent.triage.runner import TriageRunner
from agent.triage.provider_factory import build_provider
from agent.triage.provider import TriageProvider
from agent.triage.cache import InMemoryTriageCache
from agent.triage.validation import validate_evidence
from agent.triage.claims import validate_claims
from agent.triage.enums import ReviewReason
from agent.triage.reporter import generate_report


from agent.models import IncidentState
from agent.tools import (
    detect_sqli_patterns,
    detect_xss_patterns,
    detect_suspicious_commands,
    detect_bruteforce_pattern,
    detect_failed_then_success_login,
    detect_malware_hash_alert,
    detect_lateral_movement_pattern,
    detect_backup_false_positive,
    detect_benign_web_traffic,
    detect_normal_admin_login
)

load_dotenv()
logger = logging.getLogger(__name__)

_triage_cache = InMemoryTriageCache()

# Shared severity ranking for the exposure/policy severity-escalation cap
# (Phase 6E.3). "none" ranks below informational so a needs_review
# submission's forced severity=none never counts as an escalation.
_SEVERITY_RANK = {"none": -1, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

def get_triage_runner() -> TriageRunner:
    settings = get_settings()
    if not settings.llm_enabled:
        raise ConfigurationError("LLM is disabled via settings (LLM_ENABLED=false).")

    provider: TriageProvider = build_provider(settings)
    return TriageRunner(provider=provider, cache=_triage_cache)

def automated_detection_node(state: IncidentState) -> dict:
    """
    Deterministically runs detection rules based on event types and populates signals and evidence.
    """
    logger.info(f"--- PRE-ANALYSIS: Running automated detections for {state['incident_id']} ---")
    canonical_events_dict = state.get("canonical_events", [])
    
    detected_signals = list(state.get("detected_signals", []))
    candidate_evidence = list(state.get("candidate_evidence", []))

    if not state.get("detection_engine_executed"):
        # 1. Run new Professional Detection Engine
        from agent.schema import CanonicalLogEvent
        from agent.detection.engine import DetectionEngine
    
        # Convert dicts back to models for engine
        events = []
        for cd in canonical_events_dict:
            try:
                events.append(CanonicalLogEvent(**cd))
            except Exception:
                pass
            
        engine = DetectionEngine()
        det_result = engine.analyze(events)
    
        # Map new deterministic signals to graph state
        for sig in det_result.signals:
            if getattr(sig, 'suppressed', False):
                continue
            detected_signals.append({
                "detector_name": sig.rule_name,
                "status": "alert",
                "message": f"{sig.rule_name} detected targeting {len(sig.target_entities)} entities. Severity: {sig.severity}, Confidence: {sig.confidence}",
                "matched_event_ids": sig.event_ids
            })
            for ev in sig.evidence:
                candidate_evidence.append(ev.model_dump())

    # 2. Run existing legacy heuristics for other categories
    event_types = set([log.get("event_type") for log in canonical_events_dict])
    automated_results = []
    
    if "SSH_AUTH" in event_types:
        automated_results.append(detect_bruteforce_pattern(canonical_events_dict))
        automated_results.append(detect_failed_then_success_login(canonical_events_dict))
        
    if "HTTP_GET" in event_types or "HTTP_POST" in event_types:
        automated_results.append(detect_sqli_patterns(canonical_events_dict))
        automated_results.append(detect_xss_patterns(canonical_events_dict))
        automated_results.append(detect_benign_web_traffic(canonical_events_dict))
        automated_results.append(detect_normal_admin_login(canonical_events_dict))
        
    if "EDR_ALERT" in event_types:
        automated_results.append(detect_malware_hash_alert(canonical_events_dict))
        
    if "SMB_ACCESS" in event_types or "SERVICE_CREATE" in event_types:
        automated_results.append(detect_lateral_movement_pattern(canonical_events_dict))
        
    if "PROCESS_CREATE" in event_types or "BASH_CMD" in event_types:
        automated_results.append(detect_suspicious_commands(canonical_events_dict))
        
    # Always check for backup agent
    automated_results.append(detect_backup_false_positive(canonical_events_dict))
    
    # Note: detect_dns_tunneling_pattern, detect_port_scan_pattern, and detect_network_flood 
    # were replaced/disabled in Phase 3. The automated_detection_node only runs non-network legacy rules.
    
    # Filter out empty/clean results to save context
    meaningful_results = [res for res in automated_results if res.get("status") != "clean"]
    
    timestamp = datetime.datetime.now().isoformat()
    
    for res in meaningful_results:
        detected_signals.append({
            "detector_name": res.get("detector_name", "unknown"),
            "status": res.get("status", "alert"),
            "message": res.get("message", ""),
            "matched_event_ids": res.get("matched_event_ids", [])
        })
        ev_list = res.get("candidate_evidence")
        if ev_list:
            candidate_evidence.extend(ev_list)
            
    logger.debug(f"DEBUG: detected_signals = {json.dumps(detected_signals, indent=2)}")

    # Also log it to tool_results for generic history display
    formatted_tool_results = []
    for dsig in detected_signals:
         formatted_tool_results.append({
            "tool_name": dsig["detector_name"],
            "timestamp": timestamp,
            "result_summary": dsig["message"],
            "matched_event_ids": dsig["matched_event_ids"]
        })

    return {
        "tool_results": formatted_tool_results, 
        "detected_signals": detected_signals,
        "candidate_evidence": candidate_evidence,
        "iteration_count": 0
    }

def entity_extraction_node(state: IncidentState) -> dict:
    """
    Deterministically extracts unique entities from raw logs using RegEx to save LLM tokens.
    """
    logger.info(f"--- ENTITY EXTRACTION: Extracting entities for {state['incident_id']} ---")
    canonical_events = state.get("canonical_events", [])
    
    entities: dict[str, set] = {
        "ips": set(),
        "users": set(),
        "hashes": set(),
        "domains": set(),
        "endpoints": set(),
        "processes": set(),
        "ports": set(),
        "commands": set()
    }
    
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    hash_pattern = re.compile(r'\b[A-Fa-f0-9]{32,64}\b')
    domain_pattern = re.compile(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
    process_pattern = re.compile(r'\b[a-zA-Z0-9_]+\.exe\b')
    port_pattern = re.compile(r'(?:port |:)(\d{2,5})\b')
    
    for log in canonical_events:
        log_str = json.dumps(log)
        
        for ip in ip_pattern.findall(log_str):
            entities["ips"].add(ip)
        for h in hash_pattern.findall(log_str):
            entities["hashes"].add(h)
        for dom in domain_pattern.findall(log_str):
            entities["domains"].add(dom)
        for proc in process_pattern.findall(log_str):
            entities["processes"].add(proc)
        for port in port_pattern.findall(log_str):
            entities["ports"].add(port)
            
        if log.get("user"):
            entities["users"].add(log["user"])
        if log.get("username"):
            entities["users"].add(log["username"])
        
        endpoint_match = re.search(r' (/[a-zA-Z0-9_/?=-]*) HTTP', log_str)
        if endpoint_match:
            entities["endpoints"].add(endpoint_match.group(1))
            
        cmd_match = re.search(r'CMD=(.*?)(?:\"|\}|$)', log_str)
        if cmd_match:
            entities["commands"].add(cmd_match.group(1))
        
        ps_match = re.search(r'(powershell.*)', log_str, re.IGNORECASE)
        if ps_match:
            entities["commands"].add(ps_match.group(1))
        
    return {
        "entities": {k: list(v) for k, v in entities.items()}
    }

def triage_node(state: IncidentState) -> dict:
    """
    Analyzes raw logs. Uses the secure bounded TriageRunner.
    """
    logger.info(f"--- TRIAGE AGENT: Running secure agentic triage for {state['incident_id']} ---")
    
    from agent.triage.models import TriageIncidentContext
    
    incident_dict = state.get("incident")
    if not incident_dict:
        # Fallback if no incident bundle is provided
        return {
            "triage_verdict": "needs_review",
            "incident_type": "other",
            "severity": "none",
            "confidence_score": 0.0,
            "evidence": [],
            "review_reason": ReviewReason.INVALID_LLM_OUTPUT.value,
            "errors": ["invalid_incident_state"]
        }
        
    try:
        context = TriageIncidentContext(**incident_dict)
    except Exception as e:
        logger.error(f"State validation failed for incident: {e}")
        return {
            "triage_verdict": "needs_review",
            "incident_type": "other",
            "severity": "none",
            "confidence_score": 0.0,
            "evidence": [],
            "review_reason": ReviewReason.INVALID_LLM_OUTPUT.value,
            "errors": ["invalid_incident_state"]
        }

    cancellation_check = state.get("cancellation_check")
    if cancellation_check:
        cancellation_check()

    try:
        runner = get_triage_runner()
        result = runner.run(state, context)
        if cancellation_check:
            cancellation_check()
        
        triage_dict = {
            "iteration_count": result.metrics.iteration_count,
            "search_call_count": result.metrics.search_call_count,
            "tool_call_count": result.metrics.tool_call_count,
            "triage_metrics": result.metrics.model_dump(),
            "review_reason": result.review_reason.value,
            # LangGraph persists returned state updates, not mutations made to
            # the node's input mapping. Evidence validation needs this exact
            # bounded input to validate model-selected evidence IDs.
            "safe_triage_input": state.get("safe_triage_input", {}),
        }
        if state.get("cache_key"):
            triage_dict["cache_key"] = state["cache_key"]
        
        if result.submission:
            from agent.triage.identity import lock_deterministic_identity
            lock_deterministic_identity(result.submission, context)
            triage_dict.update({
                "triage_submission": result.submission.model_dump(),
                "triage_verdict": result.submission.triage_verdict.value,
                "incident_type": result.submission.incident_type,
                "severity": result.submission.severity.value,
                "confidence_score": result.submission.confidence_score,
                "evidence": [], # Handled later
            })
        else:
            # No submission at all (invalid output / provider unavailable):
            # the deterministic incident still owns its identity.
            triage_dict.update({
                "triage_verdict": "needs_review",
                "incident_type": context.incident.incident_type,
                "severity": "none",
                "confidence_score": 0.0,
                "evidence": []
            })

        return triage_dict

    except JobCancellationRequested:
        raise
    except Exception as e:
        logger.error(f"--- TRIAGE AGENT: Fatal Error -> {e} ---")
        return {
            "triage_verdict": "needs_review",
            "incident_type": context.incident.incident_type,
            "severity": "none",
            "confidence_score": 0.0,
            "evidence": [],
            "review_reason": ReviewReason.PROVIDER_UNAVAILABLE.value,
            "errors": [str(e)]
        }



def evidence_validation_node(state: IncidentState) -> dict:
    """
    Deterministically validates evidence IDs and claims using Phase 4 architecture.
    """
    logger.info(f"--- VALIDATION NODE: Validating evidence for {state['incident_id']} ---")
    
    from agent.triage.models import TriageSubmission, TriageInput, TriageIncidentContext
    
    submission_dict = state.get("triage_submission")
    triage_input_dict = state.get("safe_triage_input")
    incident_dict = state.get("incident")
    
    if not submission_dict or not triage_input_dict or not incident_dict:
        return {
            "validated_evidence": [],
            "rejected_evidence": [],
            "claims": [],
            "triage_verdict": "needs_review",
            "severity": "none",
            "confidence_score": 0.0,
            "review_reason": ReviewReason.NO_VALIDATED_EVIDENCE.value
        }
        
    submission = TriageSubmission(**submission_dict)
    triage_input = TriageInput(**triage_input_dict)
    try:
        context = TriageIncidentContext(**incident_dict)
    except Exception as e:
        logger.error(f"Failed to parse TriageIncidentContext in validation node: {e}")
        return {
            "validated_evidence": [],
            "rejected_evidence": [],
            "claims": [],
            "triage_verdict": "needs_review",
            "severity": "none",
            "confidence_score": 0.0,
            "review_reason": ReviewReason.INVALID_LLM_OUTPUT.value
        }
    
    from agent.triage.guardrails import classify_incident
    classification = classify_incident(context, triage_input.signal_views)

    ev_results = validate_evidence(submission, triage_input, context)
    accepted_claims, rejected_claims = validate_claims(
        submission.claims,
        ev_results,
        firewall_only_evidence=classification.is_firewall_only,
    )


    # Check if needs_review fallback applies
    valid_ev = [e for e in ev_results if e.status == "validated"]
    verdict = submission.triage_verdict.value
    
    ret: dict[str, Any] = {
        "validated_evidence": [e.model_dump() for e in valid_ev],
        "rejected_evidence": [e.model_dump() for e in ev_results if e.status == "rejected"],
        "claims": [c.model_dump() for c in submission.claims],
        "validated_claims": [c.model_dump() for c in accepted_claims],
        "rejected_claims": rejected_claims
    }
    
    if not valid_ev and verdict in ["suspicious_activity", "confirmed_incident", "false_positive"]:
        logger.info("--- VALIDATION NODE: All evidence rejected. Forcing needs_review ---")
        ret.update({
            "triage_verdict": "needs_review",
            "severity": "none",
            "confidence_score": 0.0,
            "review_reason": ReviewReason.NO_VALIDATED_EVIDENCE.value
        })
    else:
        from agent.triage.guardrails import (
            FirewallExposureFacts,
            ScanProbeFacts,
            SequenceFacts,
            derive_incident_facts,
        )
        from agent.triage.identity import lock_deterministic_identity
        from agent.triage.enums import TriageSeverity, TriageVerdict

        # The deterministic incident always owns its identity, for every
        # family - not only network scan/probe incidents.
        original_incident_type = submission.incident_type
        lock_deterministic_identity(submission, context)
        ret["incident_type"] = context.incident.incident_type

        facts = derive_incident_facts(context, triage_input.signal_views)
        policy_adjustments: list[str] = []
        if original_incident_type != context.incident.incident_type:
            policy_adjustments.append("deterministic_incident_type_locked")

        if isinstance(facts, ScanProbeFacts) and facts.all_attempts_blocked:
            if submission.triage_verdict == TriageVerdict.CONFIRMED_INCIDENT:
                submission.triage_verdict = TriageVerdict.SUSPICIOUS_ACTIVITY
                ret["triage_verdict"] = TriageVerdict.SUSPICIOUS_ACTIVITY.value
                policy_adjustments.append("all_blocked_network_verdict_capped")

        if isinstance(facts, (FirewallExposureFacts, SequenceFacts)):
            # Firewall-only telemetry (exposure/policy or an allowed
            # sequence) can never prove a successful application session,
            # authentication, exploitation, or compromise by itself.
            if (
                submission.triage_verdict == TriageVerdict.CONFIRMED_INCIDENT
                and not facts.application_success_proven
                and not facts.compromise_proven
            ):
                submission.triage_verdict = TriageVerdict.SUSPICIOUS_ACTIVITY
                ret["triage_verdict"] = TriageVerdict.SUSPICIOUS_ACTIVITY.value
                policy_adjustments.append("firewall_only_confirmed_verdict_capped")
                policy_adjustments.append("application_success_not_proven")
                policy_adjustments.append("compromise_not_proven")

            # The provider must never escalate severity above the
            # deterministic detection severity using firewall-only evidence.
            deterministic_rank = _SEVERITY_RANK.get(context.incident.severity, 0)
            submission_rank = _SEVERITY_RANK.get(submission.severity.value, 0)
            if submission_rank > deterministic_rank:
                submission.severity = TriageSeverity(context.incident.severity)
                ret["severity"] = context.incident.severity
                policy_adjustments.append("exposure_severity_capped")

        if submission.triage_verdict == TriageVerdict.NEEDS_REVIEW:
            submission.severity = TriageSeverity.NONE
            submission.confidence_score = 0.0
            ret["severity"] = "none"
            ret["confidence_score"] = 0.0

        if policy_adjustments:
            ret["policy_adjustments"] = sorted(set(policy_adjustments))

        ret["triage_submission"] = submission.model_dump()

    return ret

def action_recommendation_node(state: IncidentState) -> dict:
    """
    Deterministically generates recommended actions and MITRE ATT&CK mapping based on the incident_type.
    """
    logger.info(f"--- ACTION NODE: Generating deterministic recommendations for {state['incident_id']} ---")
    
    verdict = state.get("triage_verdict")
    incident_type = state.get("incident_type")
    actions = []
    mitre_techniques = []

    facts = None
    incident_dict = state.get("incident")
    triage_input_dict = state.get("safe_triage_input")
    if incident_dict:
        try:
            from agent.triage.guardrails import derive_incident_facts
            from agent.triage.models import TriageIncidentContext, TriageInput

            context = TriageIncidentContext(**incident_dict)
            signal_views = []
            if triage_input_dict:
                try:
                    signal_views = TriageInput(**triage_input_dict).signal_views
                except Exception:
                    signal_views = []
            facts = derive_incident_facts(context, signal_views)
        except Exception:
            logger.warning("Unable to derive deterministic incident facts")
    if facts is not None:
        incident_type = facts.incident_type

    MITRE_MAP = {
        "bruteforce_failed": ["T1110 - Brute Force"],
        "bruteforce_success": ["T1110 - Brute Force", "T1078 - Valid Accounts"],
        "powershell": ["T1059.001 - PowerShell"],
        "dns_tunneling": ["T1071.004 - DNS"],
        "lateral_movement": ["T1021.002 - SMB/Windows Admin Shares"],
        "sql_injection": ["T1190 - Exploit Public-Facing Application"],
        "malware_hash": ["T1204 - User Execution", "T1059 - Command and Scripting Interpreter"],
        "port_scan": ["T1046 - Network Service Discovery"],
        "horizontal_scan": ["T1046 - Network Service Discovery"],
        "vertical_scan": ["T1046 - Network Service Discovery"],
        "rdp_probe": ["T1046 - Network Service Discovery"],
        "ssh_probe": ["T1046 - Network Service Discovery"],
        "xss": ["T1190 - Exploit Public-Facing Application"]
    }
    
    if incident_type in MITRE_MAP and verdict in ["suspicious_activity", "confirmed_incident"]:
        mitre_techniques.extend(MITRE_MAP[incident_type])
    
    if verdict == "needs_review":
        actions.append("SOC Analyst required: Manual review necessary due to validation failure, insufficient evidence, or automation constraints.")
    elif verdict == "false_positive":
        if incident_type == "backup_traffic":
            actions.append("Known backup agent activity. Verify schedule with IT operations.")
        elif incident_type == "normal_admin_login":
            actions.append("Normal administrative login detected. No action required.")
        elif incident_type == "benign_web_traffic":
            actions.append("Standard benign web traffic. No action required.")
        else:
            actions.append("No immediate action required.")
            actions.append("Consider tuning alert rules if this alert triggers frequently for normal traffic.")
    elif verdict in ["suspicious_activity", "confirmed_incident"]:
        from agent.triage.guardrails import FirewallExposureFacts, ScanProbeFacts, SequenceFacts

        if isinstance(facts, ScanProbeFacts) and facts.all_attempts_blocked:
            actions.extend([
                "Review firewall and network telemetry for continued probing from the source IP.",
                "Review relevant authentication logs for any separate successful activity.",
                "Consider temporarily blocking or rate-limiting the source IP at the network edge.",
            ])
        elif isinstance(facts, SequenceFacts):
            # Blocked-then-allowed sequence: investigate, do not auto-isolate.
            actions.extend([
                "Review service, application, and authentication logs for the allowed connection.",
                "Validate whether the allowed flow was expected and authorized.",
                "Check related sessions from the same source for suspicious activity.",
                "Review the firewall policy that permitted the connection.",
            ])
        elif isinstance(facts, FirewallExposureFacts):
            # Exposure/policy: focus on firewall/NAT policy and service
            # logs. Never recommend host isolation or a mandatory password
            # reset from firewall-only evidence alone.
            actions.extend([
                "Verify whether the firewall/NAT rule permitting this access is intended.",
                "Confirm the source falls within an approved/allowed range.",
                "Restrict public access or require a VPN/allowlist for this service if it is not intended to be public.",
                "Review service and authentication logs for any successful session.",
                "Review the configuration of the exposed service.",
                "Inspect related flow telemetry for the same source and destination.",
            ])
        elif incident_type == "sql_injection":
            actions.extend(["SOC Analyst should evaluate updating WAF rules to block signature.", "SOC Analyst should verify database integrity.", "SOC Analyst should perform endpoint validation."])
        elif incident_type == "bruteforce_success":
            actions.extend(["SOC Analyst should evaluate locking the compromised account.", "SOC Analyst should review session logs.", "SOC Analyst should evaluate forcing a password reset."])
        elif incident_type == "powershell":
            actions.extend(["SOC Analyst should evaluate isolating the target host.", "SOC Analyst should review process tree.", "SOC Analyst should evaluate initiating an EDR deep scan."])
        elif incident_type == "dns_tunneling":
            actions.extend(["SOC Analyst should review DNS logs.", "SOC Analyst should evaluate blocking malicious domains.", "SOC Analyst should investigate the source endpoint."])
        elif incident_type == "lateral_movement":
            actions.extend(["SOC Analyst should evaluate isolating the target host.", "SOC Analyst should review admin credentials.", "SOC Analyst should check SMB/PsExec logs."])
        else:
            actions.extend(["SOC Analyst should investigate the source IP.", "SOC Analyst should check authentication logs.", "SOC Analyst should consider temporary IP blocking."])
            
    return {"recommended_actions": actions, "mitre_techniques": mitre_techniques}



def build_why_it_matters(incident_type: str, verdict: str) -> str:
    if verdict == "needs_review":
        return "Automated triage could not validate enough evidence for a safe verdict. This incident should be reviewed by a SOC analyst before being dismissed or escalated."
    if verdict == "false_positive":
        if incident_type == "benign_web_traffic":
            return "The logs only show successful 200 OK web requests. No SQLi, XSS, failed authentication, or suspicious command indicators were found."
        elif incident_type == "backup_traffic":
            return "Large data transfer appears associated with known backup_agent.exe processes, matching expected backup activity."
        elif incident_type == "normal_admin_login":
            return "Login request originated from an internal IP and was followed by successful dashboard access without malicious payloads."
        else:
            return "Automated analysis did not find sufficient evidence of a real threat. Event matches normal or benign activity patterns."
            
    # For suspicious or confirmed_incident
    explanations = {
        "sql_injection": "SQL injection payloads (e.g., OR '1'='1', UNION SELECT) were sent to the endpoint, indicating an attempt to manipulate authentication or database queries.",
        "xss": "HTTP requests contain cross-site scripting (XSS) payloads (e.g., <script>, onerror=) aimed at executing malicious JavaScript in a user's browser.",
        "bruteforce_failed": "Multiple failed login attempts were observed from the same source IP in a short period. Without successful login evidence, this remains a suspicious brute force attempt.",
        "bruteforce_success": "Repeated failed SSH logins were followed by a successful login from the same source IP. This pattern suggests the brute force attempt may have succeeded.",
        "powershell": "PowerShell execution with -EncodedCommand or -ExecutionPolicy Bypass indicates an attempt to hide commands and evade security policies.",
        "dns_tunneling": "DNS queries contain abnormally long, random-looking subdomains, a technique often used in DNS tunneling for covert data exfiltration or C2 communication.",
        "malware_hash": "EDR logs indicate the execution or download of a file matching a known malicious hash and malware family.",
        "port_scan": "A single source IP attempted connections to multiple different destination ports or hosts in a short time, consistent with port scanning discovery activity. Note: All observed attempts were blocked, and the provided logs contain no evidence of a successful connection.",
        "lateral_movement": "A combination of SMB access and PsExec service creation was observed, which strongly aligns with lateral movement attempts between hosts."
    }
    
    return explanations.get(incident_type, "Suspicious indicators were detected in the logs that require further investigation.")

def build_key_evidence(evidence_list: list, max_items: int = 3) -> str:
    if not evidence_list:
        return "- No validated evidence available."
        
    lines = []
    for ev in evidence_list[:max_items]:
        event_id = ev.get("event_id", "Unknown")
        quote = ev.get("quote", "").strip().replace("\n", " ")
        if len(quote) > 80:
            quote = quote[:77] + "..."
        lines.append(f"- {event_id}: {quote}")
        
    return "\n".join(lines)

def build_recommended_actions(actions_list: list, max_items: int = 3) -> str:
    if not actions_list:
        return "- No immediate action required."
    
    lines = [f"- {action}" for action in actions_list[:max_items]]
    return "\n".join(lines)

def reporter_node(state: IncidentState) -> dict:
    """
    Generates a structured deterministic markdown summary via the phase 4 reporter.
    """
    logger.info(f"--- REPORTER AGENT: Generating deterministic report for {state['incident_id']} ---")
    
    from agent.triage.models import TriageSubmission, EvidenceValidationResult, TriageClaim
    
    submission_dict = state.get("triage_submission")
    if not submission_dict:
        # Build dummy
        from agent.triage.enums import TriageVerdict, TriageSeverity
        submission = TriageSubmission(
            triage_verdict=TriageVerdict.NEEDS_REVIEW,
            incident_type="other",
            severity=TriageSeverity.NONE,
            confidence_score=0.0,
            summary="No submission available. " + str(state.get("review_reason", ""))
        )
    else:
        submission = TriageSubmission(**submission_dict)
        
    # The validated graph state is authoritative over the original model
    # submission (for example, a blocked-network verdict cap).
    from agent.triage.enums import TriageVerdict, TriageSeverity

    state_verdict = state.get("triage_verdict")
    if state_verdict:
        submission.triage_verdict = TriageVerdict(state_verdict)
    if state.get("severity"):
        submission.severity = TriageSeverity(state["severity"])
    if state.get("confidence_score") is not None:
        submission.confidence_score = float(state["confidence_score"])
    if submission.triage_verdict == TriageVerdict.NEEDS_REVIEW:
        submission.severity = TriageSeverity.NONE
        submission.confidence_score = 0.0

    deterministic_facts = None
    deterministic_confidence = None
    context = None
    incident_dict = state.get("incident")
    if incident_dict:
        try:
            from agent.triage.guardrails import (
                FirewallExposureFacts,
                ScanProbeFacts,
                SequenceFacts,
                build_deterministic_summary,
                derive_incident_facts,
            )
            from agent.triage.identity import lock_deterministic_identity
            from agent.triage.models import TriageIncidentContext, TriageInput

            context = TriageIncidentContext(**incident_dict)
            deterministic_confidence = context.incident.confidence
            triage_input_dict = state.get("safe_triage_input")
            signal_views = []
            if triage_input_dict:
                try:
                    signal_views = TriageInput(**triage_input_dict).signal_views
                except Exception:
                    signal_views = []

            lock_deterministic_identity(submission, context)
            deterministic_facts = derive_incident_facts(context, signal_views)

            # For scan/probe, exposure/policy, and allowed-sequence
            # incidents, the report summary must be the deterministic
            # summary, never an untrusted model summary that may overstate
            # what firewall-only telemetry proves.
            if isinstance(deterministic_facts, (ScanProbeFacts, FirewallExposureFacts, SequenceFacts)):
                submission.summary = build_deterministic_summary(deterministic_facts)
        except Exception:
            logger.warning("Unable to render deterministic incident facts")

    valid_ev = [EvidenceValidationResult(**e) for e in state.get("validated_evidence", [])]
    rej_ev = [EvidenceValidationResult(**e) for e in state.get("rejected_evidence", [])]
    claims = [TriageClaim(**c) for c in state.get("validated_claims", [])]

    incident_metrics = {}
    if context is not None:
        incident_metrics = context.incident.metrics
    metadata = {
        "title": f"Incident {state['incident_id']} ({state.get('incident_type', 'unknown')})",
        "event_count": len(context.incident.event_ids) if context is not None else 0,
        "incident_metrics": incident_metrics,
    }

    report = generate_report(
        submission=submission,
        validated_evidence=valid_ev + rej_ev,
        accepted_claims=claims,
        incident_metadata=metadata,
        review_reason=state.get("review_reason", "none"),
        recommended_actions=state.get("recommended_actions", []),
        deterministic_facts=deterministic_facts,
        deterministic_confidence=deterministic_confidence,
    )

    return {"final_report": report}
