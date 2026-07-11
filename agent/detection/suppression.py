import ipaddress
from typing import List, Optional
from agent.detection.models import DetectionSignal

class SuppressionPolicy:
    def __init__(self):
        # Allowlist configurations
        self.allowed_sources: List[str] = [] # IPs or CIDRs
        self.allowed_destinations: List[str] = []
        self.allowed_rules: List[str] = []
        
    def add_allowed_source(self, cidr: str):
        self.allowed_sources.append(cidr)

    def is_suppressed(self, signal: DetectionSignal) -> Optional[str]:
        # Very simple initial suppression logic
        if signal.rule_id in self.allowed_rules:
            return f"Rule {signal.rule_id} is globally allowed"
            
        try:
            if signal.primary_entity:
                ip = ipaddress.ip_address(signal.primary_entity)
                for allowed in self.allowed_sources:
                    if ip in ipaddress.ip_network(allowed):
                        return f"Source {signal.primary_entity} is in allowed sources"
        except ValueError:
            pass # primary_entity might not be an IP
            
        return None
