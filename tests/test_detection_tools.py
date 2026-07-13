from agent.tools import (
    detect_sqli_patterns, 
    detect_port_scan_pattern, 
    detect_backup_false_positive,
    detect_suspicious_commands, 
    detect_dns_tunneling_pattern, 
    detect_malware_hash_alert,
    detect_benign_web_traffic, 
    detect_normal_admin_login, 
    detect_failed_then_success_login,
    MAX_EVIDENCE_PER_DETECTOR
)

def test_detect_sqli_patterns():
    logs = [
        {"event_id": "1", "safe_message_excerpt": "GET /login HTTP/1.1"},
        {"event_id": "2", "safe_message_excerpt": "POST /login user=admin' OR '1'='1"}
    ]
    res = detect_sqli_patterns(logs)
    assert res["status"] == "alert"
    assert "2" in res["matched_event_ids"]
    assert len(res["candidate_evidence"]) == 1

def test_detect_port_scan_pattern():
    logs = [
        {"event_id": "1", "timestamp": "2023-10-27T10:00:00Z", "src_ip": "1.1.1.1", "safe_message_excerpt": "BLOCK TCP 1.1.1.1 -> 2.2.2.2:80"},
        {"event_id": "2", "timestamp": "2023-10-27T10:00:01Z", "src_ip": "1.1.1.1", "safe_message_excerpt": "BLOCK TCP 1.1.1.1 -> 2.2.2.2:443"},
        {"event_id": "3", "timestamp": "2023-10-27T10:00:02Z", "src_ip": "1.1.1.1", "safe_message_excerpt": "BLOCK TCP 1.1.1.1 -> 2.2.2.2:22"}
    ]
    res = detect_port_scan_pattern(logs)
    assert res["status"] == "alert"
    assert len(res["matched_event_ids"]) == 3

def test_detect_backup_false_positive():
    logs = [
        {"event_id": "1", "safe_message_excerpt": "Process start: backup_agent.exe"}
    ]
    res = detect_backup_false_positive(logs)
    assert res["status"] == "benign"
    assert "1" in res["matched_event_ids"]

def test_detect_suspicious_commands():
    logs = [
        {"event_id": "1", "safe_message_excerpt": "powershell -EncodedCommand JABz..."}
    ]
    res = detect_suspicious_commands(logs)
    assert res["status"] == "alert"
    assert "1" in res["matched_event_ids"]

def test_detect_dns_tunneling_pattern():
    logs = [
        {"event_id": "1", "event_type": "DNS_QUERY", "safe_message_excerpt": "Query: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0.evil.com"}
    ]
    res = detect_dns_tunneling_pattern(logs)
    assert res["status"] == "alert"
    assert "1" in res["matched_event_ids"]

def test_detect_malware_hash_alert():
    logs = [
        {"event_id": "1", "event_type": "EDR_ALERT", "safe_message_excerpt": "Alert! family: ransomware hash: 8d1122a30b42c448d39c941dfab40251"}
    ]
    res = detect_malware_hash_alert(logs)
    assert res["status"] == "alert"
    assert "1" in res["matched_event_ids"]

def test_detect_benign_web_traffic():
    logs = [
        {"event_id": "1", "event_type": "HTTP_GET", "safe_message_excerpt": "GET /index.html HTTP/1.1 200 OK"}
    ]
    res = detect_benign_web_traffic(logs)
    assert res["status"] == "benign"
    assert "1" in res["matched_event_ids"]

def test_detect_normal_admin_login_success():
    logs = [
        {"event_id": "1", "timestamp": "2023-10-27T10:00:00Z", "src_ip": "10.0.0.5", "safe_message_excerpt": "POST /login user=admin 200 OK"},
        {"event_id": "2", "timestamp": "2023-10-27T10:01:00Z", "src_ip": "10.0.0.5", "safe_message_excerpt": "GET /dashboard HTTP/1.1 200 OK"}
    ]
    res = detect_normal_admin_login(logs)
    assert res["status"] == "benign"
    assert "1" in res["matched_event_ids"]
    assert "2" in res["matched_event_ids"]

def test_detect_normal_admin_login_sqli():
    logs = [
        {"event_id": "1", "timestamp": "2023-10-27T10:00:00Z", "src_ip": "10.0.0.5", "safe_message_excerpt": "POST /login user=admin' OR '1'='1 200 OK"},
        {"event_id": "2", "timestamp": "2023-10-27T10:01:00Z", "src_ip": "10.0.0.5", "safe_message_excerpt": "GET /dashboard HTTP/1.1 200 OK"}
    ]
    res = detect_normal_admin_login(logs)
    assert res["status"] == "clean"
    assert len(res["matched_event_ids"]) == 0

def test_detect_failed_then_success_login():
    logs = [
        {"event_id": "1", "timestamp": "2023-10-27T10:00:00Z", "src_ip": "192.168.1.10", "dst_ip": "10.0.0.2", "safe_message_excerpt": "Login failed"},
        {"event_id": "2", "timestamp": "2023-10-27T10:02:00Z", "src_ip": "192.168.1.10", "dst_ip": "10.0.0.2", "safe_message_excerpt": "Login accepted"}
    ]
    res = detect_failed_then_success_login(logs)
    assert res["status"] == "alert"
    assert len(res["matched_event_ids"]) == 2

def test_detect_failed_then_success_login_unrelated():
    logs = [
        {"event_id": "1", "timestamp": "2023-10-27T10:00:00Z", "src_ip": "192.168.1.10", "dst_ip": "10.0.0.2", "safe_message_excerpt": "Login failed"},
        {"event_id": "2", "timestamp": "2023-10-27T10:02:00Z", "src_ip": "192.168.1.20", "dst_ip": "10.0.0.2", "safe_message_excerpt": "Login accepted"}
    ]
    res = detect_failed_then_success_login(logs)
    assert res["status"] == "clean"

def test_max_candidate_evidence():
    logs = [{"event_id": str(i), "safe_message_excerpt": f"GET /login HTTP/1.1 OR '1'='1 {i}"} for i in range(10)]
    res = detect_sqli_patterns(logs)
    assert res["status"] == "alert"
    assert res["matched_count"] == 10
    assert len(res["candidate_evidence"]) == MAX_EVIDENCE_PER_DETECTOR
