from datetime import datetime
from typing import Any, Dict, Union

from agent.parsers.base import BaseLogParser, ParseContext, ParserMatch
from agent.parsers.helpers import normalize_timestamp
from agent.schema import CanonicalLogEvent
from agent.tcp_flags import canonicalize_tcp_flags


MAX_METADATA_TEXT_CHARS = 128
MAX_REASON_CHARS = 160
MAX_SAFE_MESSAGE_CHARS = 512


def _bounded_text(value: Any, max_chars: int) -> str | None:
    """Return a single-line, bounded representation of a known PF field."""
    if value is None:
        return None

    text = " ".join(str(value).split())
    if not text:
        return None
    return text[:max_chars]


def _is_explicit_spi_event(raw_record: Dict[str, Any]) -> bool:
    """Identify SPI only from explicit PF action or rule-set markers."""
    action = _bounded_text(raw_record.get("deviceAction"), MAX_METADATA_TEXT_CHARS)
    if action and "spi" in action.casefold():
        return True

    return any(
        str(raw_record.get(field, "")).strip().casefold() == "spi"
        for field in ("deviceInboundRuleSet", "deviceOutboundRuleSet")
    )


def _source_timezone_offset(value: Any) -> str | None:
    """Return a validated fixed UTC offset without retaining the raw timestamp."""
    text = _bounded_text(value, MAX_METADATA_TEXT_CHARS)
    if text is None:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    offset = parsed.utcoffset()
    if offset is None:
        return None
    total_minutes = int(offset.total_seconds() // 60)
    sign = "+" if total_minutes >= 0 else "-"
    absolute_minutes = abs(total_minutes)
    hours, minutes = divmod(absolute_minutes, 60)
    return f"{sign}{hours:02d}:{minutes:02d}"


class PfFirewallParser(BaseLogParser):
    name = "pf_firewall"
    version = "2.2.0"
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
        
        raw_device_action = raw_record.get("deviceAction")
        original_device_action = _bounded_text(raw_device_action, MAX_METADATA_TEXT_CHARS)
        action = raw_device_action
        if action:
            action = action.lower()
            if action in ["allow", "pass", "accepted", "accept"]:
                action = "pass"
            elif "block" in action or "deny" in action or "drop" in action:
                action = "block"

        spi_anomaly = _is_explicit_spi_event(raw_record)
        action_reason = raw_record.get("deviceActionReason")
        safe_action_reason = _bounded_text(action_reason, MAX_REASON_CHARS)
        pf_event_type = _bounded_text(raw_record.get("type"), MAX_METADATA_TEXT_CHARS)
        tcp_flags_present = "tcpFlags" in raw_record
        original_tcp_flags = _bounded_text(
            raw_record.get("tcpFlags"), MAX_METADATA_TEXT_CHARS
        )
        normalized_tcp_flags = canonicalize_tcp_flags(
            raw_record.get("tcpFlags"),
            field_present=tcp_flags_present,
        )
        parser_metadata: Dict[str, Any] = {
            "original_device_action": original_device_action,
            "spi_anomaly": spi_anomaly,
            "tcp_flags_present": tcp_flags_present,
            "original_tcp_flags": original_tcp_flags,
            "tcp_flag_tokens": list(normalized_tcp_flags.tokens),
            "tcp_flags_explicit_none": normalized_tcp_flags.explicit_none,
        }
        source_timezone_offset = _source_timezone_offset(ts_str)
        if source_timezone_offset is not None:
            parser_metadata["source_timezone_offset"] = source_timezone_offset
        if pf_event_type is not None:
            parser_metadata["pf_event_type"] = pf_event_type

        # construct safe_message_excerpt safely
        # Format: BLOCK TCP 45.142.193.169:50668 -> 193.255.181.27:3389 flags=S inbound_zone=wan1-zone
        act = (_bounded_text(action, 32) or "UNKNOWN").upper()
        proto = (_bounded_text(raw_record.get("proto"), 16) or "UNKNOWN").upper()
        src = _bounded_text(raw_record.get("src"), 64) or "unknown"
        source_port = _bounded_text(raw_record.get("sourcePort"), 10)
        spt = f":{source_port}" if source_port else ""
        dst = _bounded_text(raw_record.get("dst"), 64) or "unknown"
        destination_port = _bounded_text(raw_record.get("destinationPort"), 10)
        dpt = f":{destination_port}" if destination_port else ""

        raw_msg_parts = [f"{act} {proto} {src}{spt} -> {dst}{dpt}"]
        if original_tcp_flags is not None:
            raw_msg_parts.append(f"flags={original_tcp_flags[:32]}")
        inbound_zone = _bounded_text(raw_record.get("deviceInboundZone"), 64)
        if inbound_zone:
            raw_msg_parts.append(f"inbound_zone={inbound_zone}")
        if safe_action_reason:
            raw_msg_parts.append(f"reason={safe_action_reason}")
        if spi_anomaly:
            raw_msg_parts.append("spi=true")

        raw_msg = " ".join(raw_msg_parts)[:MAX_SAFE_MESSAGE_CHARS]
        
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
            action_reason=action_reason,
            tcp_flags=normalized_tcp_flags.canonical,
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
            parser_metadata=parser_metadata,
            
            parser_name=self.name,
            parser_version=self.version,
            parser_confidence=0.95,
            schema_fingerprint=context.schema_fingerprint,
            parse_status="parsed",
            parse_warnings=(
                [] if normalized_tcp_flags.recognized else ["unrecognized_tcp_flags"]
            ),
            source_name=context.source_name,
            source_line=context.line_number,
        )
