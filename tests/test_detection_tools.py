import pytest
from tools import detect_sqli_patterns, detect_port_scan_pattern, detect_backup_false_positive

def test_detect_sqli_patterns():
    logs = [
        {"event_id": "1", "raw_message": "GET /login HTTP/1.1"},
        {"event_id": "2", "raw_message": "POST /login user=admin' OR '1'='1"}
    ]
    res = detect_sqli_patterns(logs)
    assert res["status"] == "alert"
    assert "2" in res["matched_event_ids"]
    assert len(res["candidate_evidence"]) == 1

def test_detect_port_scan_pattern():
    logs = [
        {"event_id": "1", "timestamp": "2023-10-27T10:00:00Z", "src_ip": "1.1.1.1", "raw_message": "BLOCK TCP 1.1.1.1 -> 2.2.2.2:80"},
        {"event_id": "2", "timestamp": "2023-10-27T10:00:01Z", "src_ip": "1.1.1.1", "raw_message": "BLOCK TCP 1.1.1.1 -> 2.2.2.2:443"},
        {"event_id": "3", "timestamp": "2023-10-27T10:00:02Z", "src_ip": "1.1.1.1", "raw_message": "BLOCK TCP 1.1.1.1 -> 2.2.2.2:22"}
    ]
    res = detect_port_scan_pattern(logs)
    assert res["status"] == "alert"
    assert len(res["matched_event_ids"]) == 3

def test_detect_backup_false_positive():
    logs = [
        {"event_id": "1", "raw_message": "Process start: backup_agent.exe"}
    ]
    res = detect_backup_false_positive(logs)
    assert res["status"] == "benign"
    assert "1" in res["matched_event_ids"]
