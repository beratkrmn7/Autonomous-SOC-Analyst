import json
from typing import Dict, Any, Union

def get_json_fingerprint(raw_log: Dict[str, Any], max_depth: int = 3, current_depth: int = 0) -> str:
    """Generate a deterministic schema fingerprint for JSON logs."""
    if current_depth > max_depth:
        return "..."
    
    keys = sorted(raw_log.keys())
    parts = []
    for k in keys:
        v = raw_log[k]
        if isinstance(v, dict) and current_depth < max_depth:
            sub_fp = get_json_fingerprint(v, max_depth, current_depth + 1)
            parts.append(f"{k}:{{{sub_fp}}}")
        elif isinstance(v, list):
            parts.append(f"{k}:list")
        else:
            # Just record the key to avoid sensitive data in fingerprint, 
            # optionally we could record type(v).__name__
            parts.append(f"{k}:{type(v).__name__}")
            
    return ",".join(parts)

def get_text_fingerprint(raw_text: str) -> str:
    """Generate a deterministic schema fingerprint for text logs (Syslog, CEF)."""
    raw_text = raw_text.strip()
    if raw_text.startswith("CEF:"):
        # Very basic CEF fingerprint
        parts = raw_text.split("|")
        if len(parts) >= 8:
            return f"CEF|{parts[1]}|{parts[2]}|{parts[3]}" # Vendor|Product|Version
        return "CEF|Malformed"
    elif raw_text.startswith("<") and ">" in raw_text[:10]:
        # Syslog detection
        pri_end = raw_text.find(">")
        if len(raw_text) > pri_end + 1:
            if raw_text[pri_end+1].isdigit(): # RFC5424 usually starts with version digit
                return "SYSLOG|RFC5424"
            else:
                return "SYSLOG|RFC3164"
    
    # Generic text pattern
    words = raw_text.split()
    if words:
        return f"TEXT|{len(words)}_words"
    return "TEXT|EMPTY"

def get_schema_fingerprint(raw_record: Union[Dict[str, Any], str]) -> str:
    if isinstance(raw_record, dict):
        return get_json_fingerprint(raw_record)
    elif isinstance(raw_record, str):
        return get_text_fingerprint(raw_record)
    return "UNKNOWN"
