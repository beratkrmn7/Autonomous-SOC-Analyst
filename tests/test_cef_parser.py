# mypy: ignore-errors
from agent.parsers.cef import CEFParser
from agent.parsers.base import ParseContext

def test_cef_parsing():
    raw = "CEF:0|Vendor|Prod|1.0|1|name|5|src=1.1.1.1 act=block msg=hello escaped\\=pipe"
    p = CEFParser()
    ctx = ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z")
    match = p.match(raw, ctx)
    assert match.matched
    evt = p.parse(raw, ctx, "E1")
    assert evt.src_ip == "1.1.1.1"
    assert evt.action == "block"
    assert evt.safe_message_excerpt == "hello escaped=pipe"
