import json
import re
from typing import Annotated, Literal, List, Dict, Any
from langchain_core.tools import tool
from langgraph.prebuilt import InjectedState
from pydantic import BaseModel, Field
from models import EvidenceItem

def format_detection_result(title: str, matched_logs: list, is_benign: bool = False, custom_msg: str = "") -> dict:
    if not matched_logs:
        return {"status": "clean", "message": f"No {title} patterns detected."}
    
    status = "benign" if is_benign else "alert"
    prefix = "INFO:" if is_benign else "CRITICAL:"
    msg = custom_msg if custom_msg else f"{prefix} {title} pattern detected in {len(matched_logs)} logs."
    
    return {
        "status": status,
        "message": msg,
        "matched_event_ids": [log.get("event_id", "unknown") for log in matched_logs],
        "logs": matched_logs
    }

@tool
def search_logs(query: str, state: Annotated[dict, InjectedState]) -> dict:
    """
    Search the raw logs for a given string query.
    Use this to look for specific IP addresses, HTTP methods, SQL keywords, or authentication failures.
    Returns JSON containing matching logs.
    """
    incident_id = state.get("incident_id", "Unknown")
    print(f"\n[Tool Execution] Searching logs for '{query}' in incident {incident_id}...")
    
    raw_logs = state.get("raw_logs", [])
    if not raw_logs:
        return {"error": "No raw logs available to search."}
    
    results = []
    for log in raw_logs:
        if query.lower() in json.dumps(log).lower():
            results.append(log)
            
    if results:
        return {
            "message": f"Found {len(results)} logs matching '{query}'",
            "matched_event_ids": [log.get("event_id", "unknown") for log in results],
            "logs": results
        }
    return {"message": f"No logs found matching '{query}'"}

@tool
def count_events_by_type(state: Annotated[dict, InjectedState]) -> dict:
    """Counts how many events of each event_type exist in the raw logs."""
    raw_logs = state.get("raw_logs", [])
    counts = {}
    for log in raw_logs:
        etype = log.get("event_type", "unknown")
        counts[etype] = counts.get(etype, 0) + 1
    return {"event_type_counts": counts}

@tool
def detect_sqli_patterns(state: Annotated[dict, InjectedState]) -> dict:
    """Deterministically checks logs for common SQL Injection payloads."""
    sqli_patterns = [r"(?i)\bOR\b\s+['\"]?\d['\"]?\s*=\s*['\"]?\d", r"(?i)DROP\s+TABLE", r"(?i)UNION\s+SELECT"]
    matched_logs = [log for log in state.get("raw_logs", []) if any(re.search(p, json.dumps(log)) for p in sqli_patterns)]
    return format_detection_result("SQLi", matched_logs)

@tool
def detect_xss_patterns(state: Annotated[dict, InjectedState]) -> dict:
    """Deterministically checks logs for common XSS payloads."""
    xss_patterns = [r"(?i)<script>", r"(?i)onerror=", r"(?i)javascript:"]
    matched_logs = [log for log in state.get("raw_logs", []) if any(re.search(p, json.dumps(log)) for p in xss_patterns)]
    return format_detection_result("XSS", matched_logs)

@tool
def detect_suspicious_commands(state: Annotated[dict, InjectedState]) -> dict:
    """Deterministically checks logs for suspicious command line executions like Encoded PowerShell."""
    cmd_patterns = [r"(?i)powershell.*-EncodedCommand", r"(?i)powershell.*-ExecutionPolicy Bypass", r"(?i)whoami"]
    matched_logs = [log for log in state.get("raw_logs", []) if any(re.search(p, json.dumps(log)) for p in cmd_patterns)]
    return format_detection_result("Suspicious Command", matched_logs)

@tool
def detect_bruteforce_pattern(state: Annotated[dict, InjectedState]) -> dict:
    """Checks for rapid repeated failed logins (Brute Force) grouped by IP."""
    raw_logs = state.get("raw_logs", [])
    failed_logins = [log for log in raw_logs if "failed" in json.dumps(log).lower() or "401 unauthorized" in json.dumps(log).lower()]
    
    # Group by src_ip and dst_ip
    groups = {}
    for log in failed_logins:
        key = (log.get("src_ip"), log.get("dst_ip"))
        if key not in groups:
            groups[key] = []
        groups[key].append(log)
        
    matched = []
    for key, logs in groups.items():
        if len(logs) >= 3:
            matched.extend(logs)
            
    return format_detection_result("Brute Force", matched)

@tool
def detect_failed_then_success_login(state: Annotated[dict, InjectedState]) -> dict:
    """Checks if a user had multiple failed logins followed by a successful one."""
    raw_logs = state.get("raw_logs", [])
    failed = [log for log in raw_logs if "failed" in json.dumps(log).lower()]
    success = [log for log in raw_logs if "accepted" in json.dumps(log).lower() or "200 ok - user=" in json.dumps(log).lower()]
    if failed and success:
        return format_detection_result("Failed then Success Login", failed + success)
    return format_detection_result("Failed then Success Login", [])

@tool
def detect_port_scan_pattern(state: Annotated[dict, InjectedState]) -> dict:
    """Checks for rapid connections to multiple different ports from the same IP."""
    raw_logs = state.get("raw_logs", [])
    blocks = [log for log in raw_logs if "BLOCK TCP" in json.dumps(log).upper()]
    
    groups = {}
    for log in blocks:
        src = log.get("src_ip")
        if src not in groups:
            groups[src] = {"ports": set(), "logs": []}
        
        # Extract port using simple regex or split
        msg = log.get("raw_message", "")
        port_match = re.search(r'->\s*(?:[0-9]{1,3}\.){3}[0-9]{1,3}:(\d+)', msg)
        if port_match:
            groups[src]["ports"].add(port_match.group(1))
        groups[src]["logs"].append(log)
        
    matched = []
    for src, data in groups.items():
        if len(data["ports"]) >= 3:
            matched.extend(data["logs"])
            
    return format_detection_result("Port Scan", matched)

@tool
def detect_dns_tunneling_pattern(state: Annotated[dict, InjectedState]) -> dict:
    """Checks for suspiciously long subdomains in DNS queries indicating tunneling."""
    raw_logs = state.get("raw_logs", [])
    dns = [log for log in raw_logs if "DNS_QUERY" in log.get("event_type", "")]
    
    matched = []
    for log in dns:
        msg = log.get("raw_message", "")
        # Find domain looking string
        domain_match = re.search(r'Query:\s*([a-zA-Z0-9.-]+)', msg)
        if domain_match:
            domain = domain_match.group(1)
            parts = domain.split('.')
            if len(parts) >= 3 and len(parts[0]) > 20: # Long subdomain heuristic
                matched.append(log)
                
    # Also fallback to volume based if no long subdomains
    if not matched and len(dns) >= 3:
        matched.extend(dns)
        
    return format_detection_result("DNS Tunneling", matched)

@tool
def detect_malware_hash_alert(state: Annotated[dict, InjectedState]) -> dict:
    """Checks for EDR alerts containing malware signatures or hashes."""
    raw_logs = state.get("raw_logs", [])
    edr = [log for log in raw_logs if "EDR_ALERT" in log.get("event_type", "")]
    
    matched = []
    for log in edr:
        msg = log.get("raw_message", "")
        if re.search(r'[A-Fa-f0-9]{32,64}', msg) and "family:" in msg.lower():
            matched.append(log)
            
    return format_detection_result("Malware Hash EDR Alert", matched)

@tool
def detect_lateral_movement_pattern(state: Annotated[dict, InjectedState]) -> dict:
    """Checks for SMB PsExec or similar lateral movement indicators."""
    raw_logs = state.get("raw_logs", [])
    lm = [log for log in raw_logs if "PSEXESVC" in json.dumps(log).upper() or "IPC$" in json.dumps(log).upper()]
    return format_detection_result("Lateral Movement", lm)

@tool
def detect_backup_false_positive(state: Annotated[dict, InjectedState]) -> dict:
    """Checks if large data transfers match known backup agents."""
    raw_logs = state.get("raw_logs", [])
    backup = [log for log in raw_logs if "backup_agent.exe" in json.dumps(log).lower()]
    return format_detection_result("Backup Agent", backup, is_benign=True, custom_msg="Known backup agent activity detected.")

class SubmitTriageResultArgs(BaseModel):
    triage_verdict: Literal["false_positive", "suspicious", "confirmed_incident", "needs_review"] = Field(
        description="The final verdict on whether these logs represent a threat."
    )
    incident_type: Literal[
        "sql_injection", "bruteforce_success", "bruteforce_failed", "powershell", 
        "dns_tunneling", "lateral_movement", "port_scan", "malware_hash", "xss",
        "benign_web_traffic", "normal_admin_login", "backup_traffic", "other"
    ] = Field(
        description="The specific type of the incident if identified."
    )
    severity: Literal["low", "medium", "high", "critical", "none"] = Field(
        description="The severity of the incident. Use 'none' if it is a false positive."
    )
    confidence_score: float = Field(
        ge=0.0, le=1.0,
        description="A score between 0.0 and 1.0 indicating confidence in the verdict."
    )
    evidence: List[EvidenceItem] = Field(
        description="Structured evidence items linking directly to event_ids."
    )

@tool(args_schema=SubmitTriageResultArgs)
def submit_triage_result(
    triage_verdict: str,
    incident_type: str,
    severity: str,
    confidence_score: float,
    evidence: List[EvidenceItem]
) -> dict:
    """
    Submit the final triage result once you have gathered enough evidence.
    """
    return {"status": "success", "message": "Triage result submitted successfully."}

tools_list = [
    search_logs, 
    count_events_by_type, 
    detect_sqli_patterns, 
    detect_xss_patterns,
    detect_suspicious_commands,
    detect_bruteforce_pattern,
    detect_failed_then_success_login,
    detect_port_scan_pattern,
    detect_dns_tunneling_pattern,
    detect_malware_hash_alert,
    detect_lateral_movement_pattern,
    detect_backup_false_positive,
    submit_triage_result
]
