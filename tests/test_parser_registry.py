# mypy: ignore-errors
from agent.parsers.registry import ParserRegistry
from agent.parsers.base import BaseLogParser, ParseContext, ParserMatch

class DummyParser1(BaseLogParser):
    name = "dummy1"
    version = "1"
    priority = 10
    @classmethod
    def match(cls, raw, ctx): return ParserMatch(matched=True, confidence=0.8, reason="")
    def parse(self, raw, ctx, evt): return None

class DummyParser2(BaseLogParser):
    name = "dummy2"
    version = "1"
    priority = 20
    @classmethod
    def match(cls, raw, ctx): return ParserMatch(matched=True, confidence=0.8, reason="")
    def parse(self, raw, ctx, evt): return None

def test_parser_priority():
    reg = ParserRegistry()
    reg.register(DummyParser1)
    reg.register(DummyParser2)
    sel = reg.select_parser({}, ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z"))
    assert sel.parser_name == "dummy2" # Higher priority
