from typing import List, Optional, Literal, TypedDict, Annotated
from pydantic import BaseModel, Field
from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages
import operator

def append_list(left: list, right: list) -> list:
    return left + right

class EvidenceItem(BaseModel):
    event_id: str = Field(description="The unique event ID (e.g. INC-006-E001) that this evidence corresponds to.")
    quote: str = Field(description="The exact quote or summary from the log.")
    reason: str = Field(description="Reason why this evidence supports the verdict.")
    source: str = Field(description="The source of the evidence, usually 'raw_logs' or the name of a tool.")

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
    raw_logs: List[dict]
    messages: Annotated[list[AnyMessage], add_messages]
    iteration_count: int
    strategy: str
    
    # State fields added in Phase 3 - Stage 1
    search_history: Annotated[List[dict], append_list]
    tool_results: Annotated[List[dict], append_list]
    errors: Annotated[List[str], append_list]
    
    # Stage 2 Fields
    entities: dict
    validated_evidence: List[dict] # Will store serialized EvidenceItems
    rejected_evidence: List[dict]
    
    # Stage 3 Fields
    recommended_actions: List[str]
    
    # Verdict output
    triage_verdict: Optional[str]
    incident_type: Optional[str]
    severity: Optional[str]
    confidence_score: Optional[float]
    evidence: Optional[List[dict]]
    final_report: Optional[str]
