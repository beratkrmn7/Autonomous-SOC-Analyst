from agent.ingestion.pipeline import IngestionPipeline

def test_mixed_formats(tmp_path):
    log_content = """{"incident_id": "INC-MIX", "parser_name": "mock", "timestamp": "2026-07-10T10:00:00Z", "src_ip": "192.168.1.5", "dst_ip": "10.0.0.5", "src_port": 12345, "dst_port": 80, "protocol": "TCP", "action": "block", "event_type": "FIREWALL", "safe_message_excerpt": "BLOCK TCP"}
<34>Oct 11 22:14:15 myhost su: failed login for root
CEF:0|SecurityVendor|Firewall|1.0|100|Block Traffic|5|src=192.168.1.1 dst=10.0.0.1 spt=50000 dpt=80 proto=TCP act=block msg=Blocked connection
{"start": "2026-07-10T11:00:00Z", "src": "198.51.100.1", "dst": "203.0.113.1", "sourcePort": 50000, "destinationPort": 22, "proto": "tcp", "deviceAction": "block", "tcpFlags": "S", "deviceInboundZone": "wan"}
{"client_ip": "1.1.1.1", "server_ip": "2.2.2.2", "sport": 1234, "dport": 80, "action": "deny"}
This is an unparseable malformed log line that should fail gracefully."""
    
    p = tmp_path / "mixed.log"
    p.write_text(log_content)
    
    pipe = IngestionPipeline()
    res = pipe.ingest_file(str(p))
    assert res.metrics.total_records == 6
    # 5 valid, 1 invalid
    assert res.metrics.parsed_records == 5
    assert res.metrics.failed_records + res.metrics.unsupported_records == 1
    assert "mock_json" in res.metrics.parser_counts
    assert "syslog" in res.metrics.parser_counts
    assert "cef" in res.metrics.parser_counts
