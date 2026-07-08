import json
import re
from datetime import datetime, timedelta
from typing import Annotated, Literal, List, Dict, Any
from langchain_core.tools import tool
from langgraph.prebuilt import InjectedState
from pydantic import BaseModel, Field

# We import EvidenceItem and TriageResult to keep schemas DRY
from models import EvidenceItem, TriageResult

def parse_time(ts_str: str) -> datetime:
    try:
        # ISO format like "2023-10-27T18:00:00Z"
        ts_str = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(ts_str)
    except:
        return datetime.min

def format_detection_result(detector_name: str, title: str, matched_logs: list, is_benign: bool = False, custom_msg: str = "") -> dict:
    if not matched_logs:
        return {"detector_name": detector_name, "status": "clean", "message": f"No {title} patterns detected."}
    
    status = "benign" if is_benign else "alert"
    prefix = "INFO:" if is_benign else "CRITICAL:"
    msg = custom_msg if custom_msg else f"{prefix} {title} pattern detected in {len(matched_logs)} logs."
    
    candidate_evidence = []
    for log in matched_logs:
        raw_msg = log.get("raw_message", "")
        if not raw_msg:
            # Fallback to a stringified subset of the JSON if raw_message is missing
            subset = {k: v for k, v in log.items() if k not in ["event_id", "timestamp"]}
            raw_msg = json.dumps(subset)
            
        candidate_evidence.append({
            "event_id": log.get("event_id", "unknown"),
            "quote": raw_msg,
            "reason": msg,
            "source": detector_name
        })
    
    return {
        "detector_name": detector_name,
        "status": status,
        "message": msg,
        "matched_event_ids": [log.get("event_id", "unknown") for log in matched_logs],
        "candidate_evidence": candidate_evidence,
        "logs": matched_logs
    }

# ======================================================================
# LLM Accessible Tools
# ======================================================================

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
            "query": query,
            "message": f"Found {len(results)} logs matching '{query}'",
            "matched_event_ids": [log.get("event_id", "unknown") for log in results],
            "logs": results
        }
    return {"query": query, "message": f"No logs found matching '{query}'"}

@tool(args_schema=TriageResult)
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

# ======================================================================
# Deterministic Pre-Analysis Tools (Not exposed to LLM directly)
# ======================================================================

def detect_sqli_patterns(raw_logs: list) -> dict:
    sqli_patterns = [r"(?i)\bOR\b\s+['\"]?\d['\"]?\s*=\s*['\"]?\d", r"(?i)DROP\s+TABLE", r"(?i)UNION\s+SELECT"]
    matched = [log for log in raw_logs if any(re.search(p, json.dumps(log)) for p in sqli_patterns)]
    return format_detection_result("detect_sqli_patterns", "SQLi", matched)

def detect_xss_patterns(raw_logs: list) -> dict:
    xss_patterns = [r"(?i)<script>", r"(?i)onerror=", r"(?i)javascript:"]
    matched = [log for log in raw_logs if any(re.search(p, json.dumps(log)) for p in xss_patterns)]
    return format_detection_result("detect_xss_patterns", "XSS", matched)

def detect_suspicious_commands(raw_logs: list) -> dict:
    cmd_patterns = [r"(?i)powershell.*-EncodedCommand", r"(?i)powershell.*-ExecutionPolicy Bypass", r"(?i)whoami", r"(?i)curl.*\|.*bash", r"(?i)wget.*-O"]
    matched = [log for log in raw_logs if any(re.search(p, json.dumps(log)) for p in cmd_patterns)]
    return format_detection_result("detect_suspicious_commands", "Suspicious Command", matched)

def detect_bruteforce_pattern(raw_logs: list) -> dict:
    failed_logins = [log for log in raw_logs if "failed" in json.dumps(log).lower() or "401 unauthorized" in json.dumps(log).lower()]
    
    # Sort chronologically
    failed_logins.sort(key=lambda x: parse_time(x.get("timestamp", "")))
    
    groups = {}
    for log in failed_logins:
        key = (log.get("src_ip"), log.get("dst_ip"))
        if key not in groups:
            groups[key] = []
        groups[key].append(log)
        
    matched = []
    # 5 minute window for >=3 attempts
    for key, logs in groups.items():
        if len(logs) >= 3:
            for i in range(len(logs) - 2):
                t1 = parse_time(logs[i].get("timestamp", ""))
                t3 = parse_time(logs[i+2].get("timestamp", ""))
                if t3 - t1 <= timedelta(minutes=5):
                    matched.extend(logs[i:i+3])
                    break
            
    # Deduplicate
    unique_matched = {m.get("event_id"): m for m in matched}.values()
    return format_detection_result("detect_bruteforce_pattern", "Brute Force", list(unique_matched))

def detect_failed_then_success_login(raw_logs: list) -> dict:
    failed = [log for log in raw_logs if "failed" in json.dumps(log).lower()]
    success = [log for log in raw_logs if "accepted" in json.dumps(log).lower() or "200 ok - user=" in json.dumps(log).lower()]
    if failed and success:
        return format_detection_result("detect_failed_then_success_login", "Failed then Success Login", failed + success)
    return format_detection_result("detect_failed_then_success_login", "Failed then Success Login", [])

def detect_port_scan_pattern(raw_logs: list) -> dict:
    blocks = [log for log in raw_logs if "BLOCK TCP" in json.dumps(log).upper()]
    blocks.sort(key=lambda x: parse_time(x.get("timestamp", "")))
    
    groups = {}
    for log in blocks:
        src = log.get("src_ip")
        if src not in groups:
            groups[src] = []
        groups[src].append(log)
        
    matched = []
    for src, logs in groups.items():
        # Check if >= 3 distinct ports hit within 5 minutes
        for i in range(len(logs)):
            ports_seen = set()
            window_logs = []
            t_start = parse_time(logs[i].get("timestamp", ""))
            
            for j in range(i, len(logs)):
                t_curr = parse_time(logs[j].get("timestamp", ""))
                if t_curr - t_start > timedelta(minutes=5):
                    break
                    
                msg = logs[j].get("raw_message", "")
                port_match = re.search(r'->\s*(?:[0-9]{1,3}\.){3}[0-9]{1,3}:(\d+)', msg)
                if port_match:
                    ports_seen.add(port_match.group(1))
                window_logs.append(logs[j])
                
            if len(ports_seen) >= 3:
                matched.extend(window_logs)
                break

    unique_matched = {m.get("event_id"): m for m in matched}.values()
    return format_detection_result("detect_port_scan_pattern", "Port Scan", list(unique_matched))

def detect_dns_tunneling_pattern(raw_logs: list) -> dict:
    dns = [log for log in raw_logs if "DNS_QUERY" in log.get("event_type", "")]
    matched = []
    
    for log in dns:
        msg = log.get("raw_message", "")
        domain_match = re.search(r'Query:\s*([a-zA-Z0-9.-]+)', msg)
        if domain_match:
            domain = domain_match.group(1)
            parts = domain.split('.')
            if len(parts) >= 3 and len(parts[0]) > 20: 
                matched.append(log)
                
    if not matched and len(dns) >= 3:
        matched.extend(dns)
        
    return format_detection_result("detect_dns_tunneling_pattern", "DNS Tunneling", matched)

def detect_malware_hash_alert(raw_logs: list) -> dict:
    edr = [log for log in raw_logs if "EDR_ALERT" in log.get("event_type", "")]
    matched = []
    for log in edr:
        msg = log.get("raw_message", "")
        if re.search(r'[A-Fa-f0-9]{32,64}', msg) and "family:" in msg.lower():
            matched.append(log)
    return format_detection_result("detect_malware_hash_alert", "Malware Hash EDR Alert", matched)

def detect_lateral_movement_pattern(raw_logs: list) -> dict:
    lm = [log for log in raw_logs if "PSEXESVC" in json.dumps(log).upper() or "IPC$" in json.dumps(log).upper()]
    return format_detection_result("detect_lateral_movement_pattern", "Lateral Movement", lm)

def detect_backup_false_positive(raw_logs: list) -> dict:
    backup = [log for log in raw_logs if "backup_agent.exe" in json.dumps(log).lower()]
    return format_detection_result("detect_backup_false_positive", "Backup Agent", backup, is_benign=True, custom_msg="Known backup agent activity detected.")

def detect_benign_web_traffic(raw_logs: list) -> dict:
    # Must only contain HTTP_GET, HTTP_POST
    event_types = set([log.get("event_type") for log in raw_logs])
    if not event_types.issubset({"HTTP_GET", "HTTP_POST"}):
        return format_detection_result("detect_benign_web_traffic", "Benign Web Traffic", [])
        
    # Must be 200 OK
    web_logs = [log for log in raw_logs if "200 ok" in json.dumps(log).lower() and ("index.html" in json.dumps(log).lower() or "images" in json.dumps(log).lower())]
    if web_logs:
        return format_detection_result("detect_benign_web_traffic", "Benign Web Traffic", web_logs, is_benign=True, custom_msg="Standard benign web traffic detected.")
    return format_detection_result("detect_benign_web_traffic", "Benign Web Traffic", [])

def detect_normal_admin_login(raw_logs: list) -> dict:
    # Look for successful admin logins (e.g. 200 OK - user=admin_real followed by dashboard access)
    admin_login = [log for log in raw_logs if "user=admin" in json.dumps(log).lower() and "200 ok" in json.dumps(log).lower()]
    dashboard_access = [log for log in raw_logs if "dashboard" in json.dumps(log).lower() and "200 ok" in json.dumps(log).lower()]
    
    if admin_login and dashboard_access:
        return format_detection_result("detect_normal_admin_login", "Normal Admin Login", admin_login + dashboard_access, is_benign=True, custom_msg="Normal administrative login detected.")
    return format_detection_result("detect_normal_admin_login", "Normal Admin Login", [])

# The only tools exposed to the LLM
tools_list = [
    search_logs, 
    submit_triage_result
]
