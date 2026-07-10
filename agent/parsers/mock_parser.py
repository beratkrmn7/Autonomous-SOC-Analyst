from typing import Dict, Any, Union
from agent.parsers.base import BaseLogParser, ParseContext, ParserMatch
from agent.schema import CanonicalLogEvent
from agent.parsers.helpers import normalize_timestamp

class MockParser(BaseLogParser):
    name = "mock_json"
    version = "1.0.0"
    priority = 50

    @classmethod
    def match(
        cls,
        raw_record: Union[Dict[str, Any], str],
        context: ParseContext
    ) -> ParserMatch:
        if not isinstance(raw_record, dict):
            return ParserMatch(matched=False, confidence=0.0, reason="Not a JSON dictionary")
            
        # Our mock logs have parser_name == "mock" or raw_message and event_type
        if raw_record.get("parser_name") == "mock":
            return ParserMatch(matched=True, confidence=1.0, reason="Explicit parser_name=mock")
            
        if "raw_message" in raw_record and "event_type" in raw_record:
            return ParserMatch(matched=True, confidence=0.8, reason="Contains raw_message and event_type")
            
        return ParserMatch(matched=False, confidence=0.0, reason="Does not match mock signature")
        
    def parse(
        self,
        raw_record: Union[Dict[str, Any], str],
        context: ParseContext,
        event_id: str
    ) -> CanonicalLogEvent:
        if not isinstance(raw_record, dict):
            raise ValueError("MockParser requires a dictionary record.")
            
        ts_str = raw_record.get("timestamp")
        timestamp = normalize_timestamp(ts_str) if ts_str else None
        
        return CanonicalLogEvent(
            event_id=event_id,
            timestamp=timestamp,
            observed_at=context.observed_at,
            src_ip=raw_record.get("src_ip"),
            dst_ip=raw_record.get("dst_ip"),
            src_port=raw_record.get("src_port"),
            dst_port=raw_record.get("dst_port"),
            protocol=raw_record.get("protocol"),
            action=raw_record.get("action"),
            event_type=raw_record.get("event_type"),
            raw_message=raw_record.get("raw_message", ""),
            original_log=raw_record,
            source_username=raw_record.get("user") or raw_record.get("username"),
            parser_name=self.name,
            parser_version=self.version,
            parser_confidence=1.0,
            schema_fingerprint=context.schema_fingerprint,
            parse_status="parsed",
            source_name=context.source_name,
            source_line=context.line_number,
        )
