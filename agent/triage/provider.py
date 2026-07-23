from typing import Protocol, Any, Dict, Optional
from agent.triage.models import TriageSubmission, TriageInput

class TriageProviderRequest:
    def __init__(
        self, 
        incident_id: str, 
        triage_input: TriageInput, 
        system_prompt: str, 
        context: Optional[Dict[str, Any]] = None,
        deadline: Optional[float] = None
    ):
        self.incident_id = incident_id
        self.triage_input = triage_input
        self.system_prompt = system_prompt
        self.context = context or {}
        self.deadline = deadline

class TriageProviderResponse:
    def __init__(
        self,
        submission: Optional[TriageSubmission] = None,
        search_call: Optional[str] = None,
        raw_output: Optional[str] = None,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        iteration_count: int = 1,
        search_call_count: int = 0,
        tool_call_count: int = 0,
        retry_count: int = 0
    ):
        self.submission = submission
        self.search_call = search_call
        self.raw_output = raw_output
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.iteration_count = iteration_count
        self.search_call_count = search_call_count
        self.tool_call_count = tool_call_count
        self.retry_count = retry_count

class BriefEnrichmentProviderRequest:
    """One bounded batch enrichment call for a whole analyze job.

    ``payload`` is the serialized bounded fact view of at most ten
    deterministic brief rows. It never carries raw records, parser metadata or
    unbounded collections.
    """

    def __init__(
        self,
        system_prompt: str,
        payload: str,
        item_ids: list[str],
        deadline: Optional[float] = None,
    ):
        self.system_prompt = system_prompt
        self.payload = payload
        self.item_ids = item_ids
        self.deadline = deadline


class BriefEnrichmentProviderResponse:
    """The raw provider payload plus telemetry.

    ``retry_count`` counts transport retries inside one logical invocation; it
    is reported separately and never inflates the logical invocation count.
    """

    def __init__(
        self,
        raw_payload: Optional[object] = None,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        retry_count: int = 0,
    ):
        self.raw_payload = raw_payload
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.retry_count = retry_count


class TriageProvider(Protocol):
    def invoke(self, request: TriageProviderRequest) -> TriageProviderResponse:
        ...

    def invoke_brief_enrichment(
        self, request: BriefEnrichmentProviderRequest
    ) -> BriefEnrichmentProviderResponse:
        ...
