from agent.parsers.syslog import SyslogParser
from agent.parsers.base import ParseContext

def test_rfc5424():
    raw = "<165>1 2026-07-10T09:51:40+03:00 host app 1234 ID47 - message"
    p = SyslogParser()
    ctx = ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z")
    match = p.match(raw, ctx)
    assert match.matched
    evt = p.parse(raw, ctx, "E1")
    assert evt.raw_message == "message"
    assert evt.timestamp is not None
