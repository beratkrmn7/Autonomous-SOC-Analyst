from typing import Any, List, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field
from agent.models import IncidentState
from agent.ingestion.models import CanonicalLogEvent, IngestionResult
from agent.detection.models import DetectionResult, DetectionSignal

class AnalysisResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    source_name: Optional[str] = None
    ingestion_result: Optional[IngestionResult] = None
    detection_result: Optional[DetectionResult] = None
    incidents: List[IncidentState] = []

    # Maps of domain entities
    event_map: Dict[str, CanonicalLogEvent] = {}
    signal_map: Dict[str, DetectionSignal] = {}

    # Phase 6E.1: deterministic triage routing outputs. Digests batch
    # low-value incidents that were never sent to a provider; routing_metrics
    # summarizes how incidents were routed and how many provider calls ran.
    triage_digests: List[Dict[str, Any]] = Field(default_factory=list)
    routing_metrics: Dict[str, Any] = Field(default_factory=dict)

    # Phase 6E.4: bounded scalar counters describing how incoming batch-local
    # incidents were resolved into final canonical incidents when stateful
    # cross-job correlation is enabled. Empty when the feature is disabled.
    stateful_metrics: Dict[str, Any] = Field(default_factory=dict)

    # Idempotency fields
    job_id: Optional[str] = None
    reused: bool = False
    idempotency_status: Optional[str] = None
    idempotency_key: Optional[str] = None
    file_sha256: Optional[str] = None
    pipeline_version: Optional[str] = None
    analysis_mode: Optional[str] = None
