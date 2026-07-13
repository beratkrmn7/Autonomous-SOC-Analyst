from pydantic import BaseModel, Field
from typing import Optional, Any, Dict, List
from datetime import datetime

class CanonicalLogEvent(BaseModel):
    event_id: str
    timestamp: Optional[datetime] = None
    observed_at: Optional[datetime] = None

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    protocol: Optional[str] = None
    action: Optional[str] = None
    action_reason: Optional[str] = None
    event_type: Optional[str] = None
    event_category: Optional[str] = None
    event_outcome: Optional[str] = None

    tcp_flags: Optional[str] = None

    inbound_interface: Optional[str] = None
    outbound_interface: Optional[str] = None
    inbound_zone: Optional[str] = None
    outbound_zone: Optional[str] = None

    source_fqdns: List[str] = Field(default_factory=list)
    destination_fqdns: List[str] = Field(default_factory=list)
    source_username: Optional[str] = None

    bytes: Optional[int] = None
    packets: Optional[int] = None
    duration_ms: Optional[int] = None

    nat_type: Optional[str] = None
    translated_src_ip: Optional[str] = None
    translated_dst_ip: Optional[str] = None
    translated_src_port: Optional[int] = None
    translated_dst_port: Optional[int] = None

    parser_name: str
    parser_version: Optional[str] = None
    parser_confidence: float = 0.0
    schema_fingerprint: Optional[str] = None
    parse_status: str
    parse_warnings: List[str] = Field(default_factory=list)

    source_name: Optional[str] = None
    source_line: Optional[int] = None
    raw_record_hash: Optional[str] = None

    safe_message_excerpt: str = ""
    parser_metadata: Optional[Dict[str, Any]] = None

