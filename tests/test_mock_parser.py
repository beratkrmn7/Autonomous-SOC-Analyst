# mypy: ignore-errors
from agent.parsers.mock_parser import MockParser
from agent.parsers.base import ParseContext

def test_mock_parser():
    p = MockParser()
    ctx = ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z")
    raw = {"parser_name": "mock", "src_ip": "1.1.1.1"}
    match = p.match(raw, ctx)
    assert match.matched
    evt = p.parse(raw, ctx, "1")
    assert evt.src_ip == "1.1.1.1"
