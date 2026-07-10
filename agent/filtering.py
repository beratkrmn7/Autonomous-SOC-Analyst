from typing import List
from agent.schema import CanonicalLogEvent
from agent.models import FilteringResult
import re

class EventFilter:
    def __init__(self):
        pass

    def filter_events(self, events: List[CanonicalLogEvent]) -> FilteringResult:
        result = FilteringResult()
        
        for event in events:
            if event.parse_status == "unsupported_schema":
                # We skip unsupported schemas from correlation, maybe keep them as context if needed.
                continue
                
            if self.is_noise(event):
                result.noise.append(event)
            elif self.is_candidate(event):
                result.candidates.append(event)
            else:
                result.context.append(event)
                
        result.metrics = {
            "total": len(events),
            "noise": len(result.noise),
            "context": len(result.context),
            "candidates": len(result.candidates)
        }
        
        return result

    def is_noise(self, event: CanonicalLogEvent) -> bool:
        # Standard noise filtering rules
        action = str(event.action).lower()
        
        # 1. Normal allowed web traffic (port 80/443) that isn't excessively large
        if action in ["pass", "allow"] and event.dst_port in [80, 443]:
            # Basic rule: assuming a single standard GET/POST without massive payloads isn't inherently a candidate
            if event.bytes and event.bytes < 50000:
                return True
                
        # 2. Normal allowed DNS queries
        if action in ["pass", "allow"] and event.dst_port == 53:
            return True
            
        # 3. NAT responses or internal routing broadcasts
        # (Could be expanded based on specific internal ranges)
        
        return False
        
    def is_candidate(self, event: CanonicalLogEvent) -> bool:
        action = str(event.action).lower()
        
        # 1. Blocked connection attempts from external (proxy by WAN or simple block rule)
        if action in ["block", "deny", "drop"]:
            return True
            
        # 2. Potential SPI anomalies
        msg = str(event.raw_message).lower()
        if "blocked by spi" in msg or "unexpected tcp flags" in msg:
            return True
            
        # 3. Specific sensitive ports even if allowed (e.g. RDP, SSH) - could be probing
        if event.dst_port in [22, 3389, 2022, 2222]:
            # If it's a pass on an internal zone, it might just be context, 
            # but usually it's worth checking if it's external.
            return True
            
        # 4. Known malicious patterns from raw_message
        malicious_patterns = [r"(?i)\bOR\b\s+['\"]?\d['\"]?\s*=\s*['\"]?\d", r"(?i)DROP\s+TABLE", r"(?i)<script>"]
        if any(re.search(p, msg) for p in malicious_patterns):
            return True
            
        return False
