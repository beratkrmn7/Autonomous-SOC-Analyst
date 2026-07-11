import json
import re
import logging
import ipaddress
from datetime import datetime, timedelta
from typing import Annotated, List
from langchain_core.tools import tool
from langgraph.prebuilt import InjectedState
from agent.models import EvidenceItem, TriageResult

logger = logging.getLogger(__name__)

MAX_EVIDENCE_PER_DETECTOR = 5

def parse_time(ts_str: str) -> datetime:
    try:
        # ISO format like "2023-10-27T18:00:00Z"
        ts_str = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(ts_str)
    except Exception:
        return datetime.min

def format_detection_result(detector_name: str, title: str, matched_logs: list, is_benign: bool = False, custom_msg: str = "") -> dict:
    if not matched_logs:
        return {
            "detector_name": detector_name, 
            "status": "clean", 
            "message": f"No {title} patterns detected.",
            "matched_count": 0,
            "matched_event_ids": [],
            "candidate_evidence": [],
            "logs": []
        }
    
    status = "benign" if is_benign else "alert"
    prefix = "INFO:" if is_benign else "CRITICAL:"
    matched_count = len(matched_logs)
    msg = custom_msg if custom_msg else f"{prefix} {title} pattern detected in {matched_count} logs."
    
    candidate_evidence = []
    for log in matched_logs[:MAX_EVIDENCE_PER_DETECTOR]:
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
        "matched_count": matched_count,
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
    logger.info(f"\n[Tool Execution] Searching logs for '{query}' in incident {incident_id}...")
    
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
    
    groups: dict[tuple, List[dict]] = {}
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
    logins = [log for log in raw_logs if "failed" in json.dumps(log).lower() or "accepted" in json.dumps(log).lower() or "200 ok - user=" in json.dumps(log).lower()]
    logins.sort(key=lambda x: parse_time(x.get("timestamp", "")))
    
    groups: dict[tuple, List[dict]] = {}
    for log in logins:
        key = (log.get("src_ip"), log.get("dst_ip"))
        if key not in groups:
            groups[key] = []
        groups[key].append(log)
        
    matched = []
    for key, logs in groups.items():
        failed_logs = []
        for log in logs:
            msg = json.dumps(log).lower()
            if "failed" in msg:
                failed_logs.append(log)
            elif ("accepted" in msg or "200 ok - user=" in msg) and failed_logs:
                # Check time window
                t_success = parse_time(log.get("timestamp", ""))
                t_last_fail = parse_time(failed_logs[-1].get("timestamp", ""))
                if t_success - t_last_fail <= timedelta(minutes=5):
                    matched.extend(failed_logs)
                    matched.append(log)
                failed_logs = [] # Reset after success
            
    unique_matched = {m.get("event_id"): m for m in matched}.values()
    return format_detection_result("detect_failed_then_success_login", "Failed then Success Login", list(unique_matched))

def detect_port_scan_pattern(raw_logs: list) -> dict:
    # A true port scan usually involves many blocks from the same IP to different ports.
    blocks = [log for log in raw_logs if str(log.get("action", "")).lower() == "block" or "BLOCK" in str(log.get("raw_message", "")).upper()]
    blocks.sort(key=lambda x: parse_time(x.get("timestamp", "")))
    
    groups: dict[str, List[dict]] = {}
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
                    
                dst_port = logs[j].get("dst_port")
                if dst_port:
                    ports_seen.add(dst_port)
                else:
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

def detect_network_flood(raw_logs: list) -> dict:
    # A simple connection count is not enough to prove a network flood.
    # To avoid false positives (e.g. from busy DNS servers or web servers),
    # this detector requires more metrics.
    # For now, we return insufficient_data or no_alert unless we see massive
    # connection attempts with same src/dst in a very short window with mostly blocks.
    
    logs_sorted = sorted(raw_logs, key=lambda x: parse_time(x.get("timestamp", "")))
    groups: dict[tuple, List[dict]] = {}
    for log in logs_sorted:
        src = log.get("src_ip")
        dst = log.get("dst_ip")
        if not src or not dst:
            continue
        key = (src, dst)
        if key not in groups:
            groups[key] = []
        groups[key].append(log)
        
    matched = []
    metrics = {}
    for (src, dst), src_logs in groups.items():
        if len(src_logs) < 100: # Increased threshold drastically
            continue
            
        for i in range(len(src_logs)):
            window_logs = []
            t_start = parse_time(src_logs[i].get("timestamp", ""))
            blocks = 0
            
            for j in range(i, len(src_logs)):
                t_curr = parse_time(src_logs[j].get("timestamp", ""))
                if t_curr - t_start > timedelta(minutes=1): # Shorter time window
                    break
                window_logs.append(src_logs[j])
                if str(src_logs[j].get("action", "")).lower() in ["block", "deny", "drop"]:
                    blocks += 1
                
            if len(window_logs) >= 100 and blocks / len(window_logs) > 0.8:
                matched.extend(window_logs)
                metrics = {
                    "source_ip": src,
                    "destination_ip": dst,
                    "connection_count": len(window_logs),
                    "blocked_ratio": blocks / len(window_logs),
                    "time_window_seconds": 60
                }
                break
                
    if not matched:
        return {
            "detector_name": "detect_network_flood",
            "status": "not_applicable",
            "message": "Insufficient data to determine network flood, or traffic looks normal.",
            "matched_event_ids": [],
            "metrics": {},
            "candidate_evidence": []
        }
        
    unique_matched = {m.get("event_id"): m for m in matched}.values()
    result = format_detection_result("detect_network_flood", "Network Flood", list(unique_matched))
    result["metrics"] = metrics
    return result

def detect_dns_tunneling_pattern(raw_logs: list) -> dict:
    dns_logs = [log for log in raw_logs if log.get("event_type") == "DNS_QUERY"]
    matched = []
    for log in dns_logs:
        msg = log.get("raw_message", "")
        # A simple check for long, random-looking subdomains (ignoring legitimate ones like dns.google)
        if "dns.google" in msg:
            continue
        # Look for a subdomain longer than 30 chars
        match = re.search(r'([A-Za-z0-9_-]{30,})\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', msg)
        if match:
            matched.append(log)
            
    if not matched:
        return format_detection_result("detect_dns_tunneling_pattern", "DNS Tunneling", [], is_benign=True)
        
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
    event_types = set([log.get("event_type") for log in raw_logs])
    if not event_types.issubset({"HTTP_GET", "HTTP_POST", None}):
        return format_detection_result("detect_benign_web_traffic", "Benign Web Traffic", [])
        
    malicious_patterns = [r"(?i)\bOR\b\s+['\"]?\d['\"]?\s*=\s*['\"]?\d", r"(?i)DROP\s+TABLE", r"(?i)UNION\s+SELECT", r"(?i)<script>", r"(?i)onerror=", r"(?i)javascript:"]
    allowed_endpoints = [r"GET /$", r"GET /index\.html", r"GET /home", r"GET /dashboard", r"GET /favicon\.ico", r"GET /images/", r"GET /styles\.css", r"GET /api/profile"]
    
    web_logs = []
    for log in raw_logs:
        if log.get("event_type") not in ("HTTP_GET", "HTTP_POST"):
            continue
        msg = json.dumps(log)
        
        # Check malicious patterns
        if any(re.search(p, msg) for p in malicious_patterns):
            continue
            
        # Check status code (allow only 2xx)
        if "200 ok" not in msg.lower() and not re.search(r"HTTP/1.[01] 20[0-9]", msg):
            continue
            
        # If it has a bad status code, reject
        if re.search(r"HTTP/1.[01] (401|403|500|404)", msg):
            continue
            
        # Allow standard endpoints
        if any(re.search(p, msg) for p in allowed_endpoints):
            web_logs.append(log)
            
    if web_logs:
        return format_detection_result("detect_benign_web_traffic", "Benign Web Traffic", web_logs, is_benign=True, custom_msg="Standard benign web traffic detected.")
    return format_detection_result("detect_benign_web_traffic", "Benign Web Traffic", [])

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def detect_normal_admin_login(raw_logs: list) -> dict:
    malicious_patterns = [r"(?i)\bOR\b\s+['\"]?\d['\"]?\s*=\s*['\"]?\d", r"(?i)DROP\s+TABLE", r"(?i)UNION\s+SELECT", r"(?i)<script>", r"(?i)onerror="]
    
    admin_logins = []
    dash_accesses = []
    
    for log in raw_logs:
        msg = json.dumps(log).lower()
        if any(re.search(p, json.dumps(log)) for p in malicious_patterns):
            continue
            
        if "post /login" in msg and "user=admin" in msg and "200 ok" in msg:
            if is_private_ip(log.get("src_ip", "")):
                admin_logins.append(log)
        elif "get /dashboard" in msg and "200 ok" in msg:
            if is_private_ip(log.get("src_ip", "")):
                dash_accesses.append(log)
                
    matched = []
    for login in admin_logins:
        src_ip = login.get("src_ip")
        t_login = parse_time(login.get("timestamp", ""))
        
        for dash in dash_accesses:
            if dash.get("src_ip") == src_ip:
                t_dash = parse_time(dash.get("timestamp", ""))
                if timedelta(seconds=0) <= (t_dash - t_login) <= timedelta(minutes=10):
                    matched.extend([login, dash])
                    
    if matched:
        unique_matched = {m.get("event_id"): m for m in matched}.values()
        return format_detection_result("detect_normal_admin_login", "Normal Admin Login", list(unique_matched), is_benign=True, custom_msg="Normal administrative login detected.")
    return format_detection_result("detect_normal_admin_login", "Normal Admin Login", [])

# The only tools exposed to the LLM
tools_list = [
    search_logs, 
    submit_triage_result
]
