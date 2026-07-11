import json
import re
import datetime
from typing import Literal


from langchain_core.messages import SystemMessage, HumanMessage
from langchain_groq import ChatGroq

from agent.models import IncidentState, TriageResult
from agent.tools import (
    tools_list, 
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
from agent.config import get_settings
from agent.errors import ConfigurationError

from dotenv import load_dotenv
import logging

load_dotenv()
logger = logging.getLogger(__name__)


_llm_cache = None

def get_triage_llm():
    global _llm_cache
    if _llm_cache:
        return _llm_cache
    settings = get_settings()
    if not settings.llm_enabled:
        raise ConfigurationError("LLM is disabled via settings (LLM_ENABLED=false).")
    if not settings.groq_api_key:
        raise ConfigurationError("The triage provider is not configured (missing API key).")
    
    llm = ChatGroq(
        model=settings.llm_model, 
        temperature=0,
        api_key=settings.groq_api_key.get_secret_value(),
        max_retries=2
    )
    _llm_cache = llm.bind_tools(tools_list)
    return _llm_cache

def automated_detection_node(state: IncidentState) -> dict:
    """
    Deterministically runs detection rules based on event types and populates signals and evidence.
    """
    logger.info(f"--- PRE-ANALYSIS: Running automated detections for {state['incident_id']} ---")
    canonical_events_dict = state.get("canonical_events", [])
    
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
    
    detected_signals = list(state.get("detected_signals", []))
    candidate_evidence = list(state.get("candidate_evidence", []))
    
    # Map new deterministic signals to graph state
    for sig in det_result.signals:
        if sig.suppressed:
            continue
        detected_signals.append({
            "detector_name": sig.rule_name,
            "status": "alert",
            "message": f"{sig.rule_name} detected targeting {len(sig.target_entities)} entities. Severity: {sig.severity}, Confidence: {sig.confidence}",
            "matched_event_ids": sig.event_ids
        })
        for ev in sig.evidence:
            candidate_evidence.append(ev.model_dump())
            
    # Map incidents to graph state if needed (can be part of candidate evidence or just let Triage agent read signals)
    for inc in det_result.incidents:
        candidate_evidence.append({
            "event_id": f"INCIDENT-SUMMARY-{inc.incident_id}",
            "quote": inc.title,
            "reason": f"Correlated Incident {inc.incident_id} of type {inc.incident_type}",
            "source": "CorrelationEngine",
            "original_fields": {"severity": inc.severity, "confidence": inc.confidence, "metrics": inc.metrics},
            "correlation_context": {}
        })

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
    Analyzes raw logs. The LLM only has access to search_logs and submit_triage_result.
    It reads pre-computed automated signals and candidate evidence.
    """
    messages = state.get("messages", [])
    iter_count = state.get("iteration_count", 0)
    
    if not messages:
        logger.info(f"--- TRIAGE AGENT: Starting autonomous investigation for {state['incident_id']} ---")
        
        detected_signals = state.get("detected_signals", [])
        signals_text = json.dumps(detected_signals, indent=2) if detected_signals else "No automated signals detected."
        
        candidate_evidence = state.get("candidate_evidence", [])
        candidate_text = json.dumps(candidate_evidence, indent=2) if candidate_evidence else "No candidate evidence available."
        
        system_msg = SystemMessage(content=f"""You are an expert SOC Triage Analyst.

AUTOMATED ANALYSIS SIGNALS:
{signals_text}

CANDIDATE EVIDENCE:
{candidate_text}

Your goal:
1. Review the signals and evidence.
2. If you need more info, use your log search function.
3. When ready, use the submit function to conclude the triage.

When submitting:
- Classify `incident_type` as one of: sql_injection, xss, bruteforce_success, bruteforce_failed, lateral_movement, dns_tunneling, malware_hash, backup_traffic, benign_web_traffic, normal_admin_login, port_scan.
- If signals say "backup_agent.exe", use `backup_traffic`.
- Provide `evidence` by copying exact items from the CANDIDATE EVIDENCE.
- If you lack evidence, set triage_verdict to `needs_review`.
""")
        human_msg = HumanMessage(content=f"Please investigate incident: {state['incident_id']}.")
        messages = [system_msg, human_msg]
    
    import time
    max_retries = 3
    for attempt in range(max_retries):
        try:
            llm = get_triage_llm()
            response = llm.invoke(messages)
            if not hasattr(response, "tool_calls") or not response.tool_calls:
                logger.info(f"--- TRIAGE AGENT: Model output plain text (Attempt {attempt+1}/{max_retries}). Forcing tool call... ---")
                messages.append(response)
                messages.append(HumanMessage(content="You must use the submit_triage_result tool to provide your final verdict. Do not just write text."))
                continue
            break
        except ConfigurationError as ce:
            logger.error(f"--- TRIAGE AGENT: Configuration Error -> {ce} ---")
            from langchain_core.messages import AIMessage
            response = AIMessage(content="API failed.", tool_calls=[])
            break
        except Exception as e:
            err_str = str(e)
            logger.debug(f"DEBUG: Exception in invoke! type={type(e)}, str={err_str}")
            if "tool_use_failed" in err_str or "parse" in err_str.lower():
                logger.error(f"--- TRIAGE AGENT: Local Parser Error (Attempt {attempt+1}/{max_retries}). Retrying... ---")
                time.sleep(2)
            else:
                logger.error(f"--- TRIAGE AGENT: Ollama Error -> {err_str} ---")
                if attempt == max_retries - 1:
                    raise
                time.sleep(2)
    else:
        from langchain_core.messages import AIMessage
        logger.info("--- TRIAGE AGENT: Max retries exceeded. Forcing fallback. ---")
        response = AIMessage(content="API failed.", tool_calls=[])

    return {"messages": [response], "iteration_count": iter_count + 1}

def route_triage(state: IncidentState) -> Literal["tools", "process_result"]:
    logger.debug(f"DEBUG route_triage: iteration_count = {state.get('iteration_count', 0)}")
    if state.get("iteration_count", 0) >= 5:
        logger.info("--- TRIAGE AGENT: Iteration limit reached. Forcing process_result ---")
        return "process_result"
        
    last_message = state["messages"][-1]
    logger.debug(f"DEBUG route_triage: last_message type={type(last_message)}, tool_calls={getattr(last_message, 'tool_calls', None)}")
    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        has_submit = any(tool_call["name"] == "submit_triage_result" for tool_call in last_message.tool_calls)
        logger.debug(f"DEBUG route_triage: has_submit={has_submit}")
        if has_submit:
            return "process_result"
        return "tools"
    
    logger.debug("DEBUG route_triage: no tool calls found, returning process_result")
    return "process_result"

def process_result_node(state: IncidentState) -> dict:
    """
    Extracts the structured TriageResult from the submit tool call with Pydantic validation.
    Also handles mixed tool call errors.
    """
    last_message = state["messages"][-1]
    
    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        # Check for mixed tool call edge case
        has_submit = any(tool_call["name"] == "submit_triage_result" for tool_call in last_message.tool_calls)
        if has_submit and len(last_message.tool_calls) > 1:
            logger.error("--- TRIAGE AGENT: Error - Mixed tool calls detected (Submit + Others). Forcing needs_review ---")
            return {
                "triage_verdict": "needs_review", 
                "incident_type": "other",
                "severity": "none", 
                "confidence_score": 0.0, 
                "evidence": [],
                "errors": ["Mixed tool call: submit_triage_result cannot be called alongside other tools."]
            }
            
        for tool_call in last_message.tool_calls:
            if tool_call["name"] == "submit_triage_result":
                try:
                    validated_args = TriageResult.model_validate(tool_call["args"])
                    logger.info(f"--- TRIAGE AGENT: Verdict submitted -> {validated_args.triage_verdict} ({validated_args.incident_type}) ---")
                    
                    severity = validated_args.severity
                    if validated_args.triage_verdict in ["false_positive", "needs_review"]:
                        severity = "none"
                        
                    return {
                        "triage_verdict": validated_args.triage_verdict,
                        "incident_type": validated_args.incident_type,
                        "severity": severity,
                        "confidence_score": validated_args.confidence_score,
                        "evidence": [ev.model_dump() for ev in validated_args.evidence],
                    }
                except Exception as e:
                    logger.error(f"--- TRIAGE AGENT: Pydantic Validation Error -> {e} ---")
                    return {
                        "triage_verdict": "needs_review",
                        "incident_type": "other",
                        "severity": "none",
                        "confidence_score": 0.0,
                        "evidence": [],
                        "errors": [f"Validation error: {e}"]
                    }
            
    logger.error("--- TRIAGE AGENT: Error - No verdict submitted properly or max iterations hit! ---")
    return {
        "triage_verdict": "needs_review", 
        "incident_type": "other",
        "severity": "none", 
        "confidence_score": 0.0, 
        "evidence": [],
        "errors": ["Model failed to submit verdict properly or hit iteration limit."]
    }

def evidence_validation_node(state: IncidentState) -> dict:
    """
    Deterministically validates that the evidence event_ids exist AND the quote is exactly in the raw_message.
    Enforces evidence length and availability for false_positive as well.
    Also checks if original_fields match the actual log.
    """
    logger.info(f"--- VALIDATION NODE: Validating evidence for {state['incident_id']} ---")
    
    evidence_list = state.get("evidence", [])
    if not evidence_list:
        if state.get("triage_verdict") in ["suspicious", "confirmed_incident", "false_positive"]:
            logger.info(f"--- VALIDATION NODE: {state.get('triage_verdict')} verdict given without evidence. Forcing needs_review ---")
            return {"validated_evidence": [], "rejected_evidence": [], "triage_verdict": "needs_review"}
        return {"validated_evidence": [], "rejected_evidence": []}
        
    canonical_events = state.get("canonical_events", [])
    log_map = {log.get("event_id"): log for log in canonical_events}
    
    validated = []
    rejected = []
    
    for ev in evidence_list:
        event_id = ev.get("event_id")
        quote = ev.get("quote", "").strip()
        
        if not quote:
            logger.info(f"--- VALIDATION NODE: Empty quote for {event_id}. ---")
            rejected.append(ev)
            continue
            
        if event_id in log_map:
            log_obj = log_map[event_id]
            raw_msg = log_obj.get("raw_message", "")
            original_log = log_obj.get("original_log", {})
            
            target_str = raw_msg if raw_msg else json.dumps(original_log)
            
            # Condition A: Exact quote match (case-insensitive)
            quote_match = quote.lower() in target_str.lower()
            
            # Condition B: Original fields match
            fields_match = False
            ev_fields = ev.get("original_fields", {}) if isinstance(ev, dict) else getattr(ev, "original_fields", {})
            if ev_fields:
                fields_match = True
                for k, v in ev_fields.items():
                    if k not in original_log or str(original_log[k]) != str(v):
                        fields_match = False
                        break
                        
            if quote_match or fields_match:
                validated.append(ev)
            else:
                logger.info(f"--- VALIDATION NODE: Match failed for {event_id}. ---")
                ev_copy = dict(ev) if isinstance(ev, dict) else ev.model_dump()
                ev_copy["validation_error"] = "quote_and_fields_mismatch"
                rejected.append(ev_copy)
        else:
            logger.info(f"--- VALIDATION NODE: Unknown event_id {event_id} ---")
            ev_copy = dict(ev) if isinstance(ev, dict) else ev.model_dump()
            ev_copy["validation_error"] = "event_not_found"
            rejected.append(ev_copy)
            
    if rejected:
        logger.warning(f"--- VALIDATION NODE: Warning! Rejected {len(rejected)} hallucinated or invalid evidence items! ---")
        
    verdict = state.get("triage_verdict")
    if not validated and verdict in ["suspicious", "confirmed_incident", "false_positive"]:
        logger.info("--- VALIDATION NODE: All evidence rejected. Forcing needs_review ---")
        return {
            "validated_evidence": [],
            "rejected_evidence": rejected,
            "triage_verdict": "needs_review",
            "severity": "none",
            "confidence_score": 0.0,
            "recommended_actions": ["SOC Analyst required: Manual review necessary due to total validation failure."],
            "review_reason": "All generated evidence failed deterministic validation."
        }
        
    return {
        "validated_evidence": validated,
        "rejected_evidence": rejected
    }

def action_recommendation_node(state: IncidentState) -> dict:
    """
    Deterministically generates recommended actions and MITRE ATT&CK mapping based on the incident_type.
    """
    logger.info(f"--- ACTION NODE: Generating deterministic recommendations for {state['incident_id']} ---")
    
    verdict = state.get("triage_verdict")
    incident_type = state.get("incident_type")
    actions = []
    mitre_techniques = []
    
    MITRE_MAP = {
        "bruteforce_failed": ["T1110 - Brute Force"],
        "bruteforce_success": ["T1110 - Brute Force", "T1078 - Valid Accounts"],
        "powershell": ["T1059.001 - PowerShell"],
        "dns_tunneling": ["T1071.004 - DNS"],
        "lateral_movement": ["T1021.002 - SMB/Windows Admin Shares"],
        "sql_injection": ["T1190 - Exploit Public-Facing Application"],
        "malware_hash": ["T1204 - User Execution", "T1059 - Command and Scripting Interpreter"],
        "port_scan": ["T1046 - Network Service Discovery"],
        "xss": ["T1190 - Exploit Public-Facing Application"]
    }
    
    if incident_type in MITRE_MAP and verdict in ["suspicious", "confirmed_incident"]:
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
    elif verdict in ["suspicious", "confirmed_incident"]:
        if incident_type == "sql_injection":
            actions.extend(["Update WAF rules to block signature.", "Check database integrity.", "Endpoint validation."])
        elif incident_type == "bruteforce_success":
            actions.extend(["Lock compromised account.", "Review session logs.", "Force password reset."])
        elif incident_type == "powershell":
            actions.extend(["Isolate target host.", "Review process tree.", "Initiate EDR deep scan."])
        elif incident_type == "dns_tunneling":
            actions.extend(["Review DNS logs.", "Block malicious domains.", "Investigate source endpoint."])
        elif incident_type == "lateral_movement":
            actions.extend(["Isolate target host.", "Review admin credentials.", "Check SMB/PsExec logs."])
        else:
            actions.extend(["Investigate source IP.", "Check authentication logs.", "Consider temporary IP blocking."])
            
    return {"recommended_actions": actions, "mitre_techniques": mitre_techniques}

def route_after_process(state: IncidentState) -> Literal["evidence_validation_node"]:
    return "evidence_validation_node"

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
    Generates a structured deterministic markdown summary.
    """
    logger.info(f"--- REPORTER AGENT: Generating deterministic report for {state['incident_id']} ---")
    
    verdict = state.get("triage_verdict", "needs_review")
    incident_type = state.get("incident_type", "other")
    severity = state.get("severity", "none")
    confidence = state.get("confidence_score", 0.0)
    
    mitre = state.get("mitre_techniques", [])
    evidence = state.get("validated_evidence", [])
    actions = state.get("recommended_actions", [])
    
    summary_lines = [
        "## Triage Summary",
        f"- Verdict: {verdict}",
        f"- Incident Type: {incident_type}",
        f"- Severity: {severity}",
        f"- Confidence: {confidence}",
        ""
    ]
    
    why_it_matters = [
        "## Why It Matters",
        build_why_it_matters(incident_type, verdict),
        ""
    ]
    
    key_evidence = [
        "## Key Evidence",
        build_key_evidence(evidence),
        ""
    ]
    
    mitre_section = []
    if mitre and verdict not in ["false_positive", "needs_review"]:
        mitre_section.append("## MITRE ATT&CK")
        for tech in mitre:
            mitre_section.append(f"- {tech}")
        mitre_section.append("")
        
    rec_actions = [
        "## Recommended Actions",
        build_recommended_actions(actions)
    ]
    
    report_parts = summary_lines + why_it_matters + key_evidence + mitre_section + rec_actions
    final_report = "\n".join(report_parts).strip()
    
    return {"final_report": final_report}
