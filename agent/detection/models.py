from pydantic import BaseModel, Field, field_validator, model_validator
from datetime import datetime
from typing import List, Dict, Optional, Union, Literal
import hashlib

SeverityType = Literal["informational", "low", "medium", "high", "critical"]

class DetectionEvidence(BaseModel):
    event_id: str = Field(min_length=1)
    quote: str
    reason: str
    source: str
    original_fields: Dict[str, object]
    correlation_context: Dict[str, object]

class DetectionSignal(BaseModel):
    signal_id: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    rule_version: str
    rule_name: str
    signal_type: str
    signal_family: str
    severity: SeverityType
    confidence: float = Field(ge=0.0, le=1.0)
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
    
    @model_validator(mode='after')
    def validate_times(self) -> 'DetectionSignal':
        if self.first_seen > self.last_seen:
            raise ValueError("first_seen must be <= last_seen")
        return self
        
    @field_validator('event_ids', 'target_entities', mode='after')
    @classmethod
    def sort_and_dedup_lists(cls, v: List[str]) -> List[str]:
        return sorted(set(v))

class IncidentBundle(BaseModel):
    """Canonical correlated incident.

    ``primary_entity`` is the effective destination asset for
    ``firewall_exposure``/``firewall_policy`` incidents and the observed
    source for scanning/probing incidents. Other families retain their
    deterministic rule-defined entity. Titles independently identify the
    observed source and must never infer an attacker from the primary entity.
    """

    incident_id: str = Field(min_length=1)
    incident_type: str
    incident_family: str
    title: str
    severity: SeverityType
    confidence: float = Field(ge=0.0, le=1.0)
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
    absorbed_signal_ids: List[str] = Field(default_factory=list)
    
    @model_validator(mode='after')
    def validate_times_and_events(self) -> 'IncidentBundle':
        if self.first_seen > self.last_seen:
            raise ValueError("first_seen must be <= last_seen")
        context_set = set(self.context_event_ids)
        for eid in self.event_ids:
            if eid in context_set:
                raise ValueError(f"Incident event {eid} cannot also be a context event")
        return self
        
    @field_validator('signal_ids', 'event_ids', 'context_event_ids', 'target_entities', 'absorbed_signal_ids', mode='after')
    @classmethod
    def sort_and_dedup_lists(cls, v: List[str]) -> List[str]:
        return sorted(set(v))


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
