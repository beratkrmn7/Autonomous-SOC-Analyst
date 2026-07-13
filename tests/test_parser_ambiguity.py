from agent.parsers.registry import ParserRegistry
from agent.parsers.base import BaseLogParser, ParseContext, ParserMatch

class DummyParser1(BaseLogParser):
    name = "dummy1"
    version = "1"
    priority = 10
    @classmethod
    def match(cls, raw, ctx): return ParserMatch(matched=True, confidence=0.9, reason="")
    def parse(self, raw, ctx, evt): return None

class DummyParser2(BaseLogParser):
    name = "dummy2"
    version = "1"
    priority = 10
    @classmethod
    def match(cls, raw, ctx): return ParserMatch(matched=True, confidence=0.88, reason="")
    def parse(self, raw, ctx, evt): return None

import logging
from unittest.mock import patch

@patch("agent.parsers.registry.logger")
def test_parser_ambiguity(mock_logger):
    reg = ParserRegistry()
    reg.register(DummyParser1)
    reg.register(DummyParser2)
    reg.select_parser({}, ParseContext(source_name="t", observed_at="2026-07-10T00:00:00Z"))
    
    found_ambiguity = False
    for call in mock_logger.warning.call_args_list:
        if "Parser ambiguity detected" in call[0][0]:
            found_ambiguity = True
            break
    assert found_ambiguity
