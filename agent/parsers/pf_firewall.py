from typing import Dict, Any, Union
from agent.parsers.base import BaseLogParser, ParseContext, ParserMatch
from agent.schema import CanonicalLogEvent
from agent.parsers.helpers import normalize_timestamp

class PfFirewallParser(BaseLogParser):
    name = "pf_firewall"
    version = "2.0.0"
    priority = 80

    @classmethod
    def match(
        cls,
        raw_record: Union[Dict[str, Any], str],
        context: ParseContext
    ) -> ParserMatch:
        if not isinstance(raw_record, dict):
            return ParserMatch(matched=False, confidence=0.0, reason="Not a JSON dictionary")
            
        # Flexible matching
        has_action = "deviceAction" in raw_record
        has_network = "src" in raw_record or "dst" in raw_record
        has_proto = "proto" in raw_record
        has_pf_marker = any(k in raw_record for k in ["pf", "diag", "rule"])
        
        score = sum([has_action, has_network, has_proto, has_pf_marker])
        
        if score >= 3:
            return ParserMatch(matched=True, confidence=0.95, reason="Matched 3+ pf firewall signals")
        elif score == 2 and has_pf_marker:
            return ParserMatch(matched=True, confidence=0.85, reason="Matched pf marker and 1+ signal")
            
        return ParserMatch(matched=False, confidence=0.0, reason="Insufficient pf firewall signals")
        
    def parse(
        self,
        raw_record: Union[Dict[str, Any], str],
        context: ParseContext,
        event_id: str
    ) -> CanonicalLogEvent:
        if not isinstance(raw_record, dict):
            raise ValueError("PfFirewallParser requires a dictionary record.")
            
        ts_str = raw_record.get("start") or raw_record.get("end")
        timestamp = normalize_timestamp(str(ts_str)) if ts_str else None
        
        action = raw_record.get("deviceAction")
        if action:
            action = action.lower()
            if action in ["allow", "pass", "accepted", "accept"]:
                action = "pass"
            elif "block" in action or "deny" in action or "drop" in action:
                action = "block"
                
        # construct safe_message_excerpt safely
        # Format: BLOCK TCP 45.142.193.169:50668 -> 193.255.181.27:3389 flags=S inbound_zone=wan1-zone
        act = (action or 'UNKNOWN').upper()
        proto = (raw_record.get("proto") or 'UNKNOWN').upper()
        src = raw_record.get("src", "unknown")
        spt = f":{raw_record['sourcePort']}" if raw_record.get("sourcePort") else ""
        dst = raw_record.get("dst", "unknown")
        dpt = f":{raw_record['destinationPort']}" if raw_record.get("destinationPort") else ""
        
        raw_msg_parts = [f"{act} {proto} {src}{spt} -> {dst}{dpt}"]
        if raw_record.get("tcpFlags"):
            raw_msg_parts.append(f"flags={raw_record['tcpFlags']}")
        if raw_record.get("deviceInboundZone"):
            raw_msg_parts.append(f"inbound_zone={raw_record['deviceInboundZone']}")
            
        raw_msg = " ".join(raw_msg_parts)
        
        # safe int conversion
        def safe_int(v):
            try:
                return int(v) if v is not None else None
            except ValueError:
                return None
        
        nat_type = raw_record.get("sourceTranslationType") or raw_record.get("destinationTranslationType")
        
        fqdns = []
        if raw_record.get("sourceFqdns"):
            v = raw_record["sourceFqdns"]
            if isinstance(v, list):
                fqdns.extend(v)
            else:
                fqdns.append(v)
            
        dfqdns = []
        if raw_record.get("destinationFqdns"):
            v = raw_record["destinationFqdns"]
            if isinstance(v, list):
                dfqdns.extend(v)
            else:
                dfqdns.append(v)
            
        return CanonicalLogEvent(
            event_id=event_id,
            timestamp=timestamp,
            observed_at=context.observed_at,
            src_ip=raw_record.get("src"),
            dst_ip=raw_record.get("dst"),
            src_port=safe_int(raw_record.get("sourcePort")),
            dst_port=safe_int(raw_record.get("destinationPort")),
            protocol=raw_record.get("proto"),
            action=action,
            action_reason=raw_record.get("deviceActionReason"),
            tcp_flags=raw_record.get("tcpFlags"),
            inbound_interface=raw_record.get("deviceInboundInterface"),
            outbound_interface=raw_record.get("deviceOutboundInterface"),
            inbound_zone=raw_record.get("deviceInboundZone"),
            outbound_zone=raw_record.get("deviceOutboundZone"),
            source_fqdns=fqdns,
            destination_fqdns=dfqdns,
            source_username=raw_record.get("sourceUserName"),
            bytes=safe_int(raw_record.get("bytes")),
            packets=safe_int(raw_record.get("packets")),
            duration_ms=safe_int(raw_record.get("durationMs")),
            nat_type=nat_type,
            translated_src_ip=raw_record.get("sourceTranslatedAddress"),
            translated_dst_ip=raw_record.get("destinationTranslatedAddress"),
            translated_src_port=safe_int(raw_record.get("sourceTranslatedPort")),
            translated_dst_port=safe_int(raw_record.get("destinationTranslatedPort")),
            safe_message_excerpt=raw_msg,
            
            parser_name=self.name,
            parser_version=self.version,
            parser_confidence=0.95,
            schema_fingerprint=context.schema_fingerprint,
            parse_status="parsed",
            source_name=context.source_name,
            source_line=context.line_number,
        )
