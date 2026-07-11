from pydantic import BaseModel
from datetime import datetime
from typing import List, Dict, Optional, Union
import hashlib

class DetectionEvidence(BaseModel):
    event_id: str
    quote: str
    reason: str
    source: str
    original_fields: Dict[str, object]
    correlation_context: Dict[str, object]

class DetectionSignal(BaseModel):
    signal_id: str
    rule_id: str
    rule_version: str
    rule_name: str
    signal_type: str
    signal_family: str
    severity: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    event_ids: List[str]
    primary_entity: str
    target_entities: List[str]
    metrics: Dict[str, Union[int, float, str, bool]]
    evidence: List[DetectionEvidence]
    mitre_techniques: List[str]
    tags: List[str]
    suppressed: bool = False
    suppression_reason: Optional[str] = None

class IncidentBundle(BaseModel):
    incident_id: str
    incident_type: str
    incident_family: str
    title: str
    severity: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    primary_entity: str
    target_entities: List[str]
    signal_ids: List[str]
    event_ids: List[str]
    context_event_ids: List[str]
    evidence: List[DetectionEvidence]
    metrics: Dict[str, Union[int, float, str, bool]]
    mitre_techniques: List[str]
    merge_key: str
    review_reason: Optional[str] = None

class DetectionMetrics(BaseModel):
    total_events: int = 0
    eligible_events: int = 0
    skipped_events: int = 0
    signal_count: int = 0
    suppressed_signal_count: int = 0
    incident_count: int = 0
    duplicate_signal_count: int = 0
    merge_count: int = 0
    duration_ms: float = 0.0

class DetectionResult(BaseModel):
    signals: List[DetectionSignal]
    incidents: List[IncidentBundle]
    suppressed_signals: List[DetectionSignal]
    uncorrelated_event_ids: List[str]
    metrics: DetectionMetrics
    warnings: List[str]

def generate_signal_id(rule_id: str, rule_version: str, primary_entity: str, correlation_key: str, first_seen: datetime, event_ids: List[str]) -> str:
    sorted_event_ids = ",".join(sorted(event_ids))
    first_seen_str = first_seen.replace(microsecond=0, second=0).isoformat() # window bucket down to minute
    data = f"{rule_id}|{rule_version}|{primary_entity}|{correlation_key}|{first_seen_str}|{sorted_event_ids}"
    hash_digest = hashlib.sha256(data.encode('utf-8')).hexdigest()[:12].upper()
    return f"SIG-{hash_digest}"

def generate_incident_id(incident_family: str, incident_type: str, primary_entity: str, merge_key: str, first_seen: datetime) -> str:
    first_seen_str = first_seen.replace(microsecond=0, second=0).isoformat()
    data = f"{incident_family}|{incident_type}|{primary_entity}|{merge_key}|{first_seen_str}"
    hash_digest = hashlib.sha256(data.encode('utf-8')).hexdigest()[:12].upper()
    return f"INC-{hash_digest}"
