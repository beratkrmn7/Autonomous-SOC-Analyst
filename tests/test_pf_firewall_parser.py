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


def test_pf_firewall_preserves_spi_action_metadata_and_excerpt():
    raw = {
        "deviceAction": "blocked by spi",
        "deviceActionReason": "unexpected tcp flags",
        "deviceInboundRuleSet": "SPI",
        "src": "10.4.252.70",
        "dst": "157.240.9.142",
        "sourcePort": 37930,
        "destinationPort": 443,
        "proto": "tcp",
        "tcpFlags": "AR",
        "start": "2026-07-10T09:51:40.022179+03:00",
    }

    event = PfFirewallParser().parse(
        raw,
        ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z"),
        "E-SPI",
    )

    assert event.action == "block"
    assert event.action_reason == "unexpected tcp flags"
    assert event.parser_metadata == {
        "original_device_action": "blocked by spi",
        "spi_anomaly": True,
        "tcp_flags_present": True,
        "original_tcp_flags": "AR",
        "tcp_flag_tokens": ["RST", "ACK"],
        "tcp_flags_explicit_none": False,
    }
    assert "reason=unexpected tcp flags" in event.safe_message_excerpt
    assert "spi=true" in event.safe_message_excerpt


def test_pf_firewall_normal_block_is_not_spi():
    raw = {
        "deviceAction": "block",
        "deviceActionReason": "match",
        "src": "20.102.115.195",
        "dst": "193.255.132.187",
        "sourcePort": 37684,
        "destinationPort": 1723,
        "proto": "tcp",
        "tcpFlags": "S",
        "start": "2026-07-10T09:53:35.251159+03:00",
    }

    event = PfFirewallParser().parse(
        raw,
        ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z"),
        "E-BLOCK",
    )

    assert event.action == "block"
    assert event.parser_metadata == {
        "original_device_action": "block",
        "spi_anomaly": False,
        "tcp_flags_present": True,
        "original_tcp_flags": "S",
        "tcp_flag_tokens": ["SYN"],
        "tcp_flags_explicit_none": False,
    }
    assert "spi=true" not in event.safe_message_excerpt


def test_pf_firewall_existing_field_mapping_remains_intact():
    raw = {
        "deviceAction": "block",
        "src": "192.0.2.10",
        "dst": "198.51.100.20",
        "sourcePort": "42424",
        "destinationPort": "8443",
        "proto": "tcp",
        "tcpFlags": "S",
        "sourceFqdns": ["source.example.test"],
        "destinationFqdns": "destination.example.test",
        "sourceUserName": "analyst",
        "sourceTranslationType": "static",
        "sourceTranslatedAddress": "192.0.2.110",
        "destinationTranslatedAddress": "198.51.100.120",
        "sourceTranslatedPort": "52525",
        "destinationTranslatedPort": "9443",
        "bytes": "1200",
        "packets": "12",
        "durationMs": "345",
    }

    event = PfFirewallParser().parse(
        raw,
        ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z"),
        "E-MAPPING",
    )

    assert event.src_ip == "192.0.2.10"
    assert event.dst_ip == "198.51.100.20"
    assert event.src_port == 42424
    assert event.dst_port == 8443
    assert event.tcp_flags == "SYN"
    assert event.source_fqdns == ["source.example.test"]
    assert event.destination_fqdns == ["destination.example.test"]
    assert event.source_username == "analyst"
    assert event.nat_type == "static"
    assert event.translated_src_ip == "192.0.2.110"
    assert event.translated_dst_ip == "198.51.100.120"
    assert event.translated_src_port == 52525
    assert event.translated_dst_port == 9443
    assert event.bytes == 1200
    assert event.packets == 12
    assert event.duration_ms == 345


def test_pf_firewall_metadata_and_excerpt_are_bounded():
    raw = {
        "deviceAction": f"blocked by spi {'x' * 500}",
        "deviceActionReason": "reason-" + ("y" * 1000),
        "deviceInboundZone": "zone-" + ("z" * 1000),
        "src": "192.0.2.10",
        "dst": "198.51.100.20",
        "proto": "tcp",
        "tcpFlags": "S" * 129,
        "type": "synthetic",
    }

    event = PfFirewallParser().parse(
        raw,
        ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z"),
        "E-BOUNDED",
    )

    assert event.parser_metadata is not None
    assert len(event.parser_metadata["original_device_action"]) == 128
    assert event.parser_metadata["pf_event_type"] == "synthetic"
    assert event.parser_metadata["spi_anomaly"] is True
    assert len(event.parser_metadata["original_tcp_flags"]) == 128
    assert event.parser_metadata["tcp_flag_tokens"] == []
    assert event.parse_warnings == ["unrecognized_tcp_flags"]
    assert len(event.safe_message_excerpt) <= 512
    assert "spi=true" in event.safe_message_excerpt

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


def test_pf_firewall_normalizes_initial_syn_and_composite_flags():
    p = PfFirewallParser()
    ctx = ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z")

    syn = p.parse({"tcpFlags": "S"}, ctx, "E-SYN")
    syn_ack = p.parse({"tcpFlags": "SA"}, ctx, "E-SYN-ACK")

    assert syn.tcp_flags == "SYN"
    assert "flags=S" in syn.safe_message_excerpt
    assert syn_ack.tcp_flags == "SYN,ACK"
