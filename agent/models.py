
from typing import List, Optional, Literal, Annotated, Dict, Any, Callable
from typing_extensions import TypedDict, NotRequired
from pydantic import BaseModel, Field
from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages
from datetime import datetime
from agent.schema import CanonicalLogEvent

def append_list(left: list, right: list) -> list:
    return left + right

class EvidenceItem(BaseModel):
    event_id: str = Field(description="The unique event ID (from the CANDIDATE EVIDENCE) that this evidence corresponds to.")
    quote: str = Field(description="The exact quote or summary from the log.")
    reason: str = Field(description="Reason why this evidence supports the verdict.")
    source: str = Field(description="The source of the evidence, usually 'raw_logs' or the name of a tool.")
    original_fields: Dict[str, Any] = Field(default_factory=dict, description="Fields from source_line for validation.")
    correlation_context: Dict[str, Any] = Field(default_factory=dict, description="Metrics context.")

class ParseFailure(BaseModel):
    line_number: Optional[int] = None
    parser_name: Optional[str] = None
    reason: str
    raw_event: Any

class IngestionResult(BaseModel):
    total_records: int = 0
    parsed_records: int = 0
    failed_records: int = 0
    unsupported_records: int = 0
    events: List[CanonicalLogEvent] = Field(default_factory=list)
    failures: List[ParseFailure] = Field(default_factory=list)

class FilteringResult(BaseModel):
    noise: List[CanonicalLogEvent] = Field(default_factory=list)
    context: List[CanonicalLogEvent] = Field(default_factory=list)
    candidates: List[CanonicalLogEvent] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)

class IncidentBundle(BaseModel):
    incident_id: str
    incident_type_hint: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    source_ips: List[str] = Field(default_factory=list)
    destination_ips: List[str] = Field(default_factory=list)
    destination_ports: List[int] = Field(default_factory=list)

    event_ids: List[str] = Field(default_factory=list)
    events: List[CanonicalLogEvent] = Field(default_factory=list)
    context_events: List[CanonicalLogEvent] = Field(default_factory=list)

    correlation_reason: str = ""
    correlation_metrics: Dict[str, Any] = Field(default_factory=dict)
    severity_hint: Optional[str] = None
    confidence_hint: Optional[float] = None

class TriageResult(BaseModel):
    """
    Structured output from the Triage Agent after analyzing raw logs.
    """
    triage_verdict: Literal["false_positive", "suspicious", "confirmed_incident", "needs_review"] = Field(
        description="The final verdict on whether these logs represent a threat. Use 'needs_review' if you are unsure or lack evidence."
    )
    incident_type: Literal[
        "sql_injection", "bruteforce_success", "bruteforce_failed", "powershell", 
        "dns_tunneling", "lateral_movement", "port_scan", "malware_hash", "xss",
        "benign_web_traffic", "normal_admin_login", "backup_traffic", "other"
    ] = Field(
        description="The specific type of the incident if identified."
    )
    severity: Literal["low", "medium", "high", "critical", "none"] = Field(
        description="The severity of the incident. Use 'none' if it is a false positive."
    )
    confidence_score: float = Field(
        ge=0.0, le=1.0,
        description="A score between 0.0 and 1.0 indicating confidence in the verdict."
    )
    evidence: List[EvidenceItem] = Field(
        description="Detailed structured evidence supporting the verdict."
    )

class IncidentState(TypedDict, total=False):
    """
    The shared state for the LangGraph state machine.
    """
    incident_id: str
    incident: NotRequired[dict]
    canonical_events: List[dict]
    messages: Annotated[list[AnyMessage], add_messages]
    iteration_count: int
    search_call_count: NotRequired[int]
    tool_call_count: NotRequired[int]
    mitre_techniques: List[str]
    candidate_evidence: List[dict]
    detected_signals: List[dict]
    safe_triage_input: NotRequired[dict]

    # Phase 6E.4: current-job provenance and the canonical primary signal, used
    # to keep this job's material evidence visible inside the bounded LLM view.
    primary_signal_id: NotRequired[Optional[str]]
    current_job_event_ids: NotRequired[List[str]]
    current_job_signal_ids: NotRequired[List[str]]
    
    # State fields added in Phase 3 - Stage 1
    search_history: Annotated[List[dict], append_list]
    tool_results: Annotated[List[dict], append_list]
    errors: Annotated[List[str], append_list]
    
    # Phase 4 Submission state
    triage_submission: NotRequired[dict]
    triage_verdict: NotRequired[str]
    report_content_sha256: NotRequired[str]
    recommendations: NotRequired[list]
    incident_type: NotRequired[str]
    severity: NotRequired[str]
    confidence_score: NotRequired[float]
    review_reason: NotRequired[str]
    
    # Evidence & Claims
    validated_evidence: NotRequired[List[dict]]
    rejected_evidence: NotRequired[List[dict]]
    claims: NotRequired[List[dict]]
    validated_claims: NotRequired[List[dict]]
    rejected_claims: NotRequired[List[dict]]
    policy_adjustments: NotRequired[List[str]]
    
    # Triage Metrics & Cache
    provider_metrics: NotRequired[dict]
    triage_metrics: NotRequired[dict]
    cache_key: NotRequired[str]
    cache_hit: NotRequired[bool]
    
    # Extras
    recommended_actions: NotRequired[List[Any]]
    entities: NotRequired[dict]
    final_report: NotRequired[str]
    detection_engine_executed: NotRequired[bool]
    cancellation_check: NotRequired[Callable[[], None]]

    # Phase 6E.1: deterministic triage routing metadata, set for every
    # incident when triage is enabled, regardless of which route it took.
    triage_route: NotRequired[str]
    routing_reason: NotRequired[str]
    triage_origin: NotRequired[str]
    llm_invoked: NotRequired[bool]
    detection_confidence: NotRequired[float]
