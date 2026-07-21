from enum import Enum

class TriageVerdict(str, Enum):
    FALSE_POSITIVE = "false_positive"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    CONFIRMED_INCIDENT = "confirmed_incident"
    NEEDS_REVIEW = "needs_review"

class TriageSeverity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    NONE = "none"

class ClaimType(str, Enum):
    ACCOUNT_COMPROMISE = "account_compromise"
    CREDENTIAL_THEFT = "credential_theft"
    SUCCESSFUL_EXPLOITATION = "successful_exploitation"
    DATA_EXFILTRATION = "data_exfiltration"
    DATABASE_COMPROMISE = "database_compromise"
    MALWARE_EXECUTION = "malware_execution"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"
    BRUTE_FORCE_SUCCESS = "brute_force_success"
    SUCCESSFUL_AUTHENTICATION = "successful_authentication"
    COMMAND_EXECUTION = "command_execution"
    OTHER = "other"

class RejectionReason(str, Enum):
    MISSING_SUPPORTING_EVIDENCE = "missing_supporting_evidence"
    EVENT_OUTSIDE_INCIDENT_SCOPE = "event_outside_incident_scope"
    UNSUPPORTED_CLAIM_TYPE = "unsupported_claim_type"
    INSUFFICIENT_STRUCTURED_FIELDS = "insufficient_structured_fields"
    EVIDENCE_REJECTED = "evidence_rejected"
    CLAIM_EVIDENCE_MISMATCH = "claim_evidence_mismatch"
    # Phase 6E.3: a free-text ClaimType.OTHER statement cannot be safely
    # classified, so it can never be accepted for a firewall-only
    # exposure/policy/sequence incident (no application/EDR evidence source
    # exists to support any success or compromise claim).
    FIREWALL_ONLY_EVIDENCE_INSUFFICIENT = "firewall_only_evidence_insufficient"

class ReviewReason(str, Enum):
    LLM_DISABLED = "llm_disabled"
    PROVIDER_CONFIGURATION_ERROR = "provider_configuration_error"
    PROVIDER_AUTHENTICATION_FAILED = "provider_authentication_failed"
    PROVIDER_TIMEOUT = "provider_timeout"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    PROVIDER_RATE_LIMITED = "provider_rate_limited"
    CIRCUIT_BREAKER_OPEN = "circuit_breaker_open"
    INVALID_LLM_OUTPUT = "invalid_llm_output"
    INVALID_TOOL_CALL = "invalid_tool_call"
    MIXED_TOOL_CALLS = "mixed_tool_calls"
    MAXIMUM_ITERATIONS_REACHED = "maximum_iterations_reached"
    MAXIMUM_SEARCH_CALLS_REACHED = "maximum_search_calls_reached"
    PROMPT_BUDGET_EXCEEDED = "prompt_budget_exceeded"
    NO_VALIDATED_EVIDENCE = "no_validated_evidence"
    UNSUPPORTED_CLAIM = "unsupported_claim"
    INCIDENT_SCOPE_VIOLATION = "incident_scope_violation"
    NONE = "none"
