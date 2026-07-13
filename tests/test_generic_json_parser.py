# mypy: ignore-errors
from agent.parsers.generic_json import GenericJsonParser
from agent.parsers.base import ParseContext

def test_generic_json_mapping():
    raw = {"client_ip": "1.1.1.1", "status": "deny"}
    p = GenericJsonParser()
    ctx = ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z")
    evt = p.parse(raw, ctx, "E1")
    assert evt.src_ip == "1.1.1.1"
    assert evt.action == "deny"
