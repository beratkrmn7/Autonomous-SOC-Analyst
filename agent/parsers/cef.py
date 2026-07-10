import re
from typing import Dict, Any, Union
from agent.parsers.base import BaseLogParser, ParseContext, ParserMatch
from agent.schema import CanonicalLogEvent
from agent.parsers.helpers import normalize_timestamp

class CEFParser(BaseLogParser):
    name = "cef"
    version = "1.0.0"
    priority = 30
    
    cef_header_pattern = re.compile(
        r"^CEF:(\d+)\|([^\|]+)\|([^\|]+)\|([^\|]+)\|([^\|]+)\|([^\|]+)\|([^\|]+)\|(.*)$"
    )

    @classmethod
    def match(
        cls,
        raw_record: Union[Dict[str, Any], str],
        context: ParseContext
    ) -> ParserMatch:
        if not isinstance(raw_record, str):
            return ParserMatch(matched=False, confidence=0.0, reason="CEF requires string input")
            
        record_str = raw_record.strip()
        if not record_str.startswith("CEF:"):
            return ParserMatch(matched=False, confidence=0.0, reason="Missing CEF: header")
            
        # Verify valid header
        if cls.cef_header_pattern.match(record_str):
            return ParserMatch(matched=True, confidence=0.95, reason="Valid CEF Header format")
            
        return ParserMatch(matched=False, confidence=0.0, reason="Malformed CEF Header")

    def parse(
        self,
        raw_record: Union[Dict[str, Any], str],
        context: ParseContext,
        event_id: str
    ) -> CanonicalLogEvent:
        if not isinstance(raw_record, str):
            raise ValueError("CEFParser requires string input")
            
        record_str = raw_record.strip()
        warnings = []
        
        match = self.cef_header_pattern.match(record_str)
        if not match:
            raise ValueError("Malformed CEF Header")
            
        cef_version, device_vendor, device_product, device_version, \
        signature_id, name, severity, extensions_str = match.groups()
        
        # Parse extensions
        extensions = {}
        # Naive extension parsing handling escaped equals
        # Split by " key="
        parts = re.split(r'\s+([A-Za-z0-9]+)=', " " + extensions_str)
        if len(parts) > 1:
            for i in range(1, len(parts)-1, 2):
                k = parts[i]
                v = parts[i+1].replace(r'\=', '=').replace(r'\|', '|').replace(r'\\', '\\')
                
                if k in extensions:
                    warnings.append(f"Duplicate CEF extension key: {k}")
                extensions[k] = v.strip()
                
        # Canonical Mapping
        src_ip = extensions.get("src")
        dst_ip = extensions.get("dst")
        src_port = extensions.get("spt")
        dst_port = extensions.get("dpt")
        protocol = extensions.get("proto")
        action = extensions.get("act")
        ts_str = extensions.get("rt") or extensions.get("start")
        source_username = extensions.get("suser")
        raw_msg = extensions.get("msg") or name
        
        timestamp = normalize_timestamp(ts_str) if ts_str else None
        
        def safe_int(v):
            try:
                return int(v) if v is not None else None
            except ValueError:
                return None
                
        original_log = {
            "cef_version": cef_version,
            "device_vendor": device_vendor,
            "device_product": device_product,
            "device_version": device_version,
            "signature_id": signature_id,
            "name": name,
            "severity": severity,
            "extensions": extensions,
            "raw": record_str
        }

        return CanonicalLogEvent(
            event_id=event_id,
            timestamp=timestamp,
            observed_at=context.observed_at,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=safe_int(src_port),
            dst_port=safe_int(dst_port),
            protocol=protocol,
            action=action,
            source_username=source_username,
            raw_message=raw_msg,
            original_log=original_log,
            parser_name=self.name,
            parser_version=self.version,
            parser_confidence=0.95,
            schema_fingerprint=context.schema_fingerprint,
            parse_status="parsed",
            parse_warnings=warnings,
            source_name=context.source_name,
            source_line=context.line_number,
        )
