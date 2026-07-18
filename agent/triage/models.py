from typing import List, Any, Optional, Literal
from pydantic import BaseModel, Field, model_validator
from agent.triage.enums import TriageVerdict, TriageSeverity, ClaimType, RejectionReason, ReviewReason
from agent.schema import CanonicalLogEvent
from agent.detection.models import IncidentBundle as DetectionIncidentBundle

class TriageIncidentContext(BaseModel):
    incident: DetectionIncidentBundle
    events: List[CanonicalLogEvent] = Field(default_factory=list)
    context_events: List[CanonicalLogEvent] = Field(default_factory=list)

class SafeEventView(BaseModel):
    event_id: str
    timestamp: str
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
    parser_name: str
    source_name: str
    sanitized_message_excerpt: Optional[str] = None

class EvidenceCandidate(BaseModel):
    evidence_id: str
    event_id: str
    quote: str
    reason: str
    source: str
    canonical_fields: dict[str, Any] = Field(default_factory=dict)
    vendor_original_fields: dict[str, Any] = Field(default_factory=dict)
    correlation_context: dict[str, Any] = Field(default_factory=dict)

class TriageInput(BaseModel):
    incident_id: str
    incident_type: str
    incident_family: str
    title: str
    deterministic_severity: str
    deterministic_confidence: float
    first_seen: str
    last_seen: str
    primary_entity: str
    target_entities: List[str] = Field(default_factory=list)
    deterministic_metrics: dict[str, Any] = Field(default_factory=dict)
    signal_summaries: List[str] = Field(default_factory=list)
    candidate_evidence: List[EvidenceCandidate] = Field(default_factory=list)
    limited_context_events: List[SafeEventView] = Field(default_factory=list)
    allowed_mitre_candidates: List[str] = Field(default_factory=list)
    parser_warnings: List[str] = Field(default_factory=list)
    data_quality_warnings: List[str] = Field(default_factory=list)

class TriageClaim(BaseModel):
    claim_id: str
    claim_type: ClaimType
    statement: str
    supporting_event_ids: List[str] = Field(default_factory=list)
    supporting_evidence_ids: List[str] = Field(default_factory=list)

class TriageSubmission(BaseModel):
    triage_verdict: TriageVerdict
    incident_type: str
    severity: TriageSeverity
    confidence_score: float = Field(ge=0.0, le=1.0)
    summary: str = Field(max_length=2000)
    selected_evidence_ids: List[str] = Field(default_factory=list)
    claims: List[TriageClaim] = Field(default_factory=list)

    @model_validator(mode='after')
    def validate_invariants(self) -> 'TriageSubmission':
        if self.triage_verdict == TriageVerdict.NEEDS_REVIEW:
            self.severity = TriageSeverity.NONE
            self.confidence_score = 0.0
        
        if self.triage_verdict == TriageVerdict.CONFIRMED_INCIDENT and not self.selected_evidence_ids:
            raise ValueError("confirmed_incident requires evidence")
            
        # Ensure unique evidence IDs
        self.selected_evidence_ids = list(dict.fromkeys(self.selected_evidence_ids))
        return self

class EvidenceValidationResult(BaseModel):
    evidence_id: str
    event_id: str
    status: Literal["validated", "rejected"]
    rejection_reason: Optional[RejectionReason] = None

class SearchLogsResult(BaseModel):
    query: str
    matched_event_ids: List[str]
    results: List[SafeEventView]
    truncated: bool

class TriageMetrics(BaseModel):
    incident_id: str
    provider: str
    model: str
    prompt_version: str
    schema_version: str
    cache_hit: bool = False
    iteration_count: int = 0
    search_call_count: int = 0
    tool_call_count: int = 0
    retry_count: int = 0
    started_at: str
    completed_at: str
    latency_ms: float = 0.0
    provider_latency_ms: float = 0.0
    estimated_prompt_tokens: int = 0
    provider_prompt_tokens: int = 0
    provider_completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost: Optional[float] = None
    fallback_used: bool = False
    review_reason: ReviewReason = ReviewReason.NONE
    circuit_breaker_state: str = "closed"

class TriageRunResult(BaseModel):
    submission: Optional[TriageSubmission] = None
    review_reason: ReviewReason = ReviewReason.NONE
    metrics: TriageMetrics
    search_results: List[SearchLogsResult] = Field(default_factory=list)
