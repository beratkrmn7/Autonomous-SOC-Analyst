import re
from typing import Dict, Any, Union
from agent.parsers.base import BaseLogParser, ParseContext, ParserMatch
from agent.schema import CanonicalLogEvent
from agent.parsers.helpers import normalize_timestamp

class SyslogParser(BaseLogParser):
    name = "syslog"
    version = "1.0.0"
    priority = 20
    
    # RFC3164: <PRI>TIMESTAMP HOSTNAME TAG: MSG
    rfc3164_pattern = re.compile(r"^<(\d+)>(?:([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+)?([^\s]+)\s+([^:]+):\s+(.*)")
    
    # RFC5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ID] MSG
    rfc5424_pattern = re.compile(r"^<(\d+)>[1-9]\d{0,2}\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+(?:(\[.*?\])\s+|- )?(.*)")

    @classmethod
    def match(
        cls,
        raw_record: Union[Dict[str, Any], str],
        context: ParseContext
    ) -> ParserMatch:
        if not isinstance(raw_record, str):
            return ParserMatch(matched=False, confidence=0.0, reason="Syslog requires string input")
            
        record_str = raw_record.strip()
        if not record_str.startswith("<"):
            return ParserMatch(matched=False, confidence=0.0, reason="Missing PRI header")
            
        pri_end = record_str.find(">")
        if pri_end == -1 or pri_end > 5:
            return ParserMatch(matched=False, confidence=0.0, reason="Invalid PRI header")
            
        if cls.rfc5424_pattern.match(record_str):
            return ParserMatch(matched=True, confidence=0.9, reason="Matched RFC5424 pattern")
        elif cls.rfc3164_pattern.match(record_str):
            return ParserMatch(matched=True, confidence=0.8, reason="Matched RFC3164 pattern")
            
        return ParserMatch(matched=False, confidence=0.0, reason="Could not parse syslog pattern")

    def parse(
        self,
        raw_record: Union[Dict[str, Any], str],
        context: ParseContext,
        event_id: str
    ) -> CanonicalLogEvent:
        if not isinstance(raw_record, str):
            raise ValueError("SyslogParser requires string input")
            
        record_str = raw_record.strip()
        warnings = []
        
        timestamp = None
        hostname = None
        app_name = None
        raw_msg = record_str
        pri = None
        
        match_5424 = self.rfc5424_pattern.match(record_str)
        if match_5424:
            pri, ts_str, hostname, app_name, proc_id, msg_id, sd, msg = match_5424.groups()
            if ts_str != "-":
                timestamp = normalize_timestamp(ts_str)
                if timestamp is None:
                    warnings.append(f"Failed to parse RFC5424 timestamp: {ts_str}")
            raw_msg = msg
        else:
            match_3164 = self.rfc3164_pattern.match(record_str)
            if match_3164:
                pri, ts_str, hostname, tag, msg = match_3164.groups()
                app_name = tag
                if ts_str:
                    warnings.append("RFC3164 timestamp parsed. Year might be inaccurate.")
                    timestamp = normalize_timestamp(ts_str)
                raw_msg = msg
        
        # Validating PRI (just warning if invalid)
        if pri and not (0 <= int(pri) <= 191):
             warnings.append(f"Invalid syslog PRI value: {pri}")
             
        original_log = {
            "raw": record_str,
            "pri": pri,
            "hostname": hostname,
            "app_name": app_name
        }
        
        return CanonicalLogEvent(
            event_id=event_id,
            timestamp=timestamp,
            observed_at=context.observed_at,
            event_type="SYSLOG",
            event_category="system",
            safe_message_excerpt=raw_msg,
            parser_metadata=original_log,
            parser_name=self.name,
            parser_version=self.version,
            parser_confidence=0.85,
            schema_fingerprint=context.schema_fingerprint,
            parse_status="parsed",
            parse_warnings=warnings,
            source_name=context.source_name,
            source_line=context.line_number,
        )
