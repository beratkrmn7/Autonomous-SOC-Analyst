# Adding a New Parser to the Agentic SOC Triage Assistant

In Phase 2, the ingestion platform was redesigned to support a robust, modular parser plugin system. The ingestion pipeline safely reads logs, detects formats (JSON, Syslog, CEF), computes a deterministic schema fingerprint, and selects the most appropriate parser based on confidence and priority.

## Step 1: Create Your Parser Class

Create a new file in `agent/parsers/` (e.g., `agent/parsers/my_parser.py`).
Your parser must inherit from `agent.parsers.base.BaseLogParser` and implement two methods: `match` and `parse`.

```python
from typing import Dict, Any, Union
from agent.parsers.base import BaseLogParser, ParseContext, ParserMatch
from agent.schema import CanonicalLogEvent
from agent.parsers.helpers import normalize_timestamp

class MyCustomParser(BaseLogParser):
    name = "my_custom_parser"
    version = "1.0.0"
    priority = 50 # 1-100 (100 is highest priority)

    @classmethod
    def match(
        cls,
        raw_record: Union[Dict[str, Any], str],
        context: ParseContext
    ) -> ParserMatch:
        """
        Evaluate if this parser can handle the given raw_record.
        Returns a ParserMatch with matched=True/False and a confidence score (0.0 to 1.0).
        Confidence must be >= 0.75 for the parser to be selected.
        """
        if not isinstance(raw_record, dict):
            return ParserMatch(matched=False, confidence=0.0, reason="Requires JSON dictionary")
            
        if "my_unique_key" in raw_record:
            return ParserMatch(matched=True, confidence=1.0, reason="Found my_unique_key")
            
        return ParserMatch(matched=False, confidence=0.0, reason="Does not match signature")

    def parse(
        self,
        raw_record: Union[Dict[str, Any], str],
        context: ParseContext,
        event_id: str
    ) -> CanonicalLogEvent:
        """
        Parse the raw_record into a CanonicalLogEvent.
        """
        ts_str = raw_record.get("timestamp")
        timestamp = normalize_timestamp(ts_str) if ts_str else None
        
        return CanonicalLogEvent(
            event_id=event_id,
            timestamp=timestamp,
            observed_at=context.observed_at,
            src_ip=raw_record.get("source_ip"),
            dst_ip=raw_record.get("dest_ip"),
            action=raw_record.get("action"),
            raw_message=raw_record.get("message", ""),
            original_log=raw_record,
            parser_name=self.name,
            parser_version=self.version,
            parser_confidence=1.0,
            schema_fingerprint=context.schema_fingerprint,
            parse_status="parsed",
            source_name=context.source_name,
            source_line=context.line_number,
        )
```

## Step 2: Register Your Parser

Open `agent/parsers/__init__.py` and add your parser to the default registry:

```python
from agent.parsers.my_parser import MyCustomParser

# Register default parsers
...
default_registry.register(MyCustomParser)
```

## Step 3: Test Your Parser

Create a unit test for your parser in `tests/test_my_parser.py`:

```python
import pytest
from agent.parsers.my_parser import MyCustomParser
from agent.parsers.base import ParseContext

def test_my_parser():
    p = MyCustomParser()
    ctx = ParseContext(source_name="test", observed_at="2026-07-10T00:00:00Z")
    raw = {"my_unique_key": True, "source_ip": "1.1.1.1"}
    match = p.match(raw, ctx)
    assert match.matched
    evt = p.parse(raw, ctx, "E1")
    assert evt.src_ip == "1.1.1.1"
```

Run `pytest` to ensure it works properly.
