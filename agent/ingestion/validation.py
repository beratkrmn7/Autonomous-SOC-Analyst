import ipaddress
from typing import Optional, List
from agent.schema import CanonicalLogEvent
from agent.ingestion.models import ParseStatus

def validate_ip(ip_str: Optional[str]) -> bool:
    if not ip_str:
        return True
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def validate_port(port: Optional[int]) -> bool:
    if port is None:
        return True
    return 0 <= port <= 65535

def normalize_protocol(protocol: Optional[str]) -> Optional[str]:
    if not protocol:
        return None
    proto = protocol.lower()
    mapping = {
        "tcp": "tcp",
        "udp": "udp",
        "icmp": "icmp",
        "icmpv6": "icmpv6",
        "gre": "gre",
        "esp": "esp",
        "ah": "ah"
    }
    return mapping.get(proto, "other")

def validate_and_normalize(event: CanonicalLogEvent) -> CanonicalLogEvent:
    """Perform semantic validation and normalization on a CanonicalLogEvent."""
    warnings: List[str] = list(event.parse_warnings)
    is_fatal = False
    
    if event.src_ip and not validate_ip(event.src_ip):
        warnings.append(f"Invalid src_ip format: {event.src_ip}")
        is_fatal = True
        
    if event.dst_ip and not validate_ip(event.dst_ip):
        warnings.append(f"Invalid dst_ip format: {event.dst_ip}")
        is_fatal = True
        
    if event.src_port is not None and not validate_port(event.src_port):
        warnings.append(f"Invalid src_port range: {event.src_port}")
        is_fatal = True
        
    if event.dst_port is not None and not validate_port(event.dst_port):
        warnings.append(f"Invalid dst_port range: {event.dst_port}")
        is_fatal = True
        
    # Metrics validation
    for metric_name in ["bytes", "packets", "duration_ms"]:
        val = getattr(event, metric_name)
        if val is not None and val < 0:
            warnings.append(f"Negative {metric_name} value: {val}")
            # not fatal, just weird
            
    # Protocol normalization
    if event.protocol:
        norm_proto = normalize_protocol(event.protocol)
        if norm_proto == "other" and event.protocol.lower() not in ["other", "unknown"]:
             warnings.append(f"Unknown protocol mapped to other: {event.protocol}")
        event.protocol = norm_proto
        
    # Action normalization was mostly done by parsers, but double check
    
    event.parse_warnings = warnings
    if is_fatal:
        event.parse_status = ParseStatus.SEMANTICALLY_INVALID.value
        
    return event
