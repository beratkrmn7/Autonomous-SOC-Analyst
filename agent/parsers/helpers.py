import re
from datetime import datetime, timezone
from typing import Optional

def normalize_timestamp(ts_str: str) -> Optional[datetime]:
    """Parse common timestamp strings into a UTC-aware datetime."""
    if not ts_str:
        return None
        
    ts_str = ts_str.strip()
    
    # ISO 8601 / RFC 3339 (e.g. 2026-07-10T10:00:00Z or +03:00)
    try:
        # replace Z with +00:00 for python's fromisoformat
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass
        
    # Unix seconds or ms
    if ts_str.isdigit():
        ts_num = int(ts_str)
        try:
            if ts_num > 20000000000: # highly likely to be milliseconds or microseconds
                if ts_num > 20000000000000:
                    dt = datetime.fromtimestamp(ts_num / 1000000, tz=timezone.utc)
                else:
                    dt = datetime.fromtimestamp(ts_num / 1000, tz=timezone.utc)
            else:
                dt = datetime.fromtimestamp(ts_num, tz=timezone.utc)
            return dt
        except (ValueError, OverflowError):
            pass

    # Syslog RFC3164 (e.g., Oct 11 22:14:15)
    # RFC3164 does not have a year. We assume the current year, but ideally this is handled with warnings
    rfc3164_pattern = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")
    if rfc3164_pattern.match(ts_str):
        current_year = datetime.now(timezone.utc).year
        try:
            dt = datetime.strptime(ts_str[:15], "%b %d %H:%M:%S")
            dt = dt.replace(year=current_year, tzinfo=timezone.utc)
            return dt
        except ValueError:
            pass
            
    # basic fallback string parse could go here
    return None
