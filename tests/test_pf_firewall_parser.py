# mypy: ignore-errors
from agent.parsers.pf_firewall import PfFirewallParser
from agent.parsers.base import ParseContext

def test_pf_firewall_parsing():
    raw = {"start": "2026-07-10T11:00:00Z", "src": "1.1.1.1", "deviceAction": "allow"}
    p = PfFirewallParser()
    ctx = ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z")
    evt = p.parse(raw, ctx, "E1")
    assert evt.action == "pass"
    assert evt.src_ip == "1.1.1.1"

def test_pf_firewall_optional_fields():
    # Should not fail if fields are missing
    raw = {"src": "1.1.1.1", "pf": "yes"}
    p = PfFirewallParser()
    ctx = ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z")
    match = p.match(raw, ctx)
    assert match.matched
    evt = p.parse(raw, ctx, "E1")
    assert evt.src_ip == "1.1.1.1"

def test_pf_firewall_fqdn_parsing_string():
    raw = {"sourceFqdns": "source.example.test", "destinationFqdns": "destination.example.test"}
    p = PfFirewallParser()
    ctx = ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z")
    evt = p.parse(raw, ctx, "E1")
    assert evt.source_fqdns == ["source.example.test"]
    assert evt.destination_fqdns == ["destination.example.test"]

def test_pf_firewall_fqdn_parsing_list():
    raw = {"sourceFqdns": ["s1.example.test", "s2.example.test"], "destinationFqdns": ["d1.example.test", "d2.example.test"]}
    p = PfFirewallParser()
    ctx = ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z")
    evt = p.parse(raw, ctx, "E1")
    assert evt.source_fqdns == ["s1.example.test", "s2.example.test"]
    assert evt.destination_fqdns == ["d1.example.test", "d2.example.test"]
