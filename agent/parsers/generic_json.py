from typing import Dict, Any, Union
from agent.parsers.base import BaseLogParser, ParseContext, ParserMatch
from agent.schema import CanonicalLogEvent
from agent.parsers.helpers import normalize_timestamp

class GenericJsonParser(BaseLogParser):
    name = "generic_json"
    version = "1.0.0"
    priority = 10 # Lowest priority, fallback for JSON

    # Aliases
    src_aliases = ["src_ip", "source_ip", "source.address", "client_ip", "src"]
    dst_aliases = ["dst_ip", "destination_ip", "destination.address", "server_ip", "dst"]
    sport_aliases = ["src_port", "source_port", "source.port", "sport"]
    dport_aliases = ["dst_port", "destination_port", "destination.port", "dport"]
    ts_aliases = ["timestamp", "time", "event_time", "event.created", "start", "@timestamp"]
    action_aliases = ["action", "event_action", "disposition", "status", "deviceAction"]

    @classmethod
    def _find_alias(cls, record: dict, aliases: list) -> tuple[Any, int]:
        matches = 0
        best_val = None
        for alias in aliases:
            # simple dot notation support
            if "." in alias:
                parts = alias.split(".")
                val: Any = record
                for part in parts:
                    if isinstance(val, dict) and part in val:
                        val = val[part]
                    else:
                        val = None
                        break
                if val is not None:
                    best_val = val
                    matches += 1
            else:
                if alias in record:
                    best_val = record[alias]
                    matches += 1
        return best_val, matches

    @classmethod
    def match(
        cls,
        raw_record: Union[Dict[str, Any], str],
        context: ParseContext
    ) -> ParserMatch:
        if not isinstance(raw_record, dict):
            return ParserMatch(matched=False, confidence=0.0, reason="Not a JSON dictionary")
            
        found_fields = 0
        _, ts_match = cls._find_alias(raw_record, cls.ts_aliases)
        _, src_match = cls._find_alias(raw_record, cls.src_aliases)
        _, dst_match = cls._find_alias(raw_record, cls.dst_aliases)
        _, act_match = cls._find_alias(raw_record, cls.action_aliases)
        
        found_fields = int(ts_match > 0) + int(src_match > 0) + int(dst_match > 0) + int(act_match > 0)
        
        if found_fields >= 2:
            return ParserMatch(matched=True, confidence=0.76, reason=f"Matched {found_fields} generic aliases")
            
        return ParserMatch(matched=False, confidence=0.0, reason="Insufficient generic aliases found")
        
    def parse(
        self,
        raw_record: Union[Dict[str, Any], str],
        context: ParseContext,
        event_id: str
    ) -> CanonicalLogEvent:
        if not isinstance(raw_record, dict):
            raise ValueError("GenericJsonParser requires a dictionary record.")
            
        warnings = []
        
        ts_val, ts_m = self._find_alias(raw_record, self.ts_aliases)
        src_val, src_m = self._find_alias(raw_record, self.src_aliases)
        dst_val, dst_m = self._find_alias(raw_record, self.dst_aliases)
        sport_val, sport_m = self._find_alias(raw_record, self.sport_aliases)
        dport_val, dport_m = self._find_alias(raw_record, self.dport_aliases)
        act_val, act_m = self._find_alias(raw_record, self.action_aliases)
        
        if ts_m > 1 or src_m > 1 or dst_m > 1:
            warnings.append("Ambiguity in generic alias resolution (multiple matching keys found)")
            
        timestamp = normalize_timestamp(str(ts_val)) if ts_val else None
        
        # Try to guess raw message
        raw_msg = raw_record.get("safe_message_excerpt", raw_record.get("message", raw_record.get("msg", "")))
        
        return CanonicalLogEvent(
            event_id=event_id,
            timestamp=timestamp,
            observed_at=context.observed_at,
            src_ip=str(src_val) if src_val else None,
            dst_ip=str(dst_val) if dst_val else None,
            src_port=int(sport_val) if sport_val else None,
            dst_port=int(dport_val) if dport_val else None,
            action=str(act_val) if act_val else None,
            safe_message_excerpt=str(raw_msg),
            
            parser_name=self.name,
            parser_version=self.version,
            parser_confidence=0.76,
            schema_fingerprint=context.schema_fingerprint,
            parse_status="parsed",
            parse_warnings=warnings,
            source_name=context.source_name,
            source_line=context.line_number,
        )
