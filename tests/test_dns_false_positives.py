
from agent.tools import detect_dns_tunneling_pattern
def test_dns_fp():
    logs = [{"event_type": "DNS_QUERY", "destinationFqdns": ["dns.google"], "dst_port": 53, "safe_message_excerpt": "Query: dns.google"}]
    res = detect_dns_tunneling_pattern(logs)
    assert res["status"] in ["clean", "not_applicable"]
