
from typing import List, Optional, Literal, TypedDict, Annotated, Dict, Any, NotRequired
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
    original_fields: Dict[str, Any] = Field(default_factory=dict, description="Fields from original_log for validation.")
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

class IncidentState(TypedDict):
    """
    The shared state for the LangGraph state machine.
    """
    incident_id: str
    canonical_events: List[dict]
    messages: Annotated[list[AnyMessage], add_messages]
    iteration_count: int
    mitre_techniques: List[str]
    candidate_evidence: List[dict]
    detected_signals: List[dict]
    
    # State fields added in Phase 3 - Stage 1
    search_history: Annotated[List[dict], append_list]
    tool_results: Annotated[List[dict], append_list]
    errors: Annotated[List[str], append_list]
    
    # Stage 2 Fields
    entities: NotRequired[dict]
    validated_evidence: NotRequired[List[dict]]
    rejected_evidence: NotRequired[List[dict]]
    evidence: NotRequired[List[dict]]
    triage_verdict: NotRequired[str]
    incident_type: NotRequired[str]
    severity: NotRequired[str]
    confidence: NotRequired[float]
    recommended_actions: NotRequired[List[Any]]
    
    detection_engine_executed: NotRequired[bool]
