import time
from typing import Optional
from agent.models import IncidentState
from agent.triage.models import TriageRunResult, TriageMetrics, TriageIncidentContext
from agent.triage.enums import ReviewReason
from agent.triage.provider import TriageProvider, TriageProviderRequest
from agent.triage.input_builder import build_triage_input
from agent.triage.prompt_builder import build_system_prompt, TRIAGE_PROMPT_VERSION
from agent.triage.exceptions import TriageProviderError
from agent.triage.cache import TriageCache, build_cache_key
from agent.config import get_settings


_RETRYABLE_INVALID_OUTPUT_REASONS = {
    ReviewReason.INVALID_LLM_OUTPUT,
    ReviewReason.INVALID_TOOL_CALL,
    ReviewReason.MIXED_TOOL_CALLS,
    ReviewReason.MAXIMUM_ITERATIONS_REACHED,
}

_CORRECTIVE_RETRY_INSTRUCTION = """

CORRECTIVE RETRY: The previous attempt did not produce one valid structured
submission. Re-read the deterministic metrics, then call
`submit_triage_result` exactly once with schema-valid arguments. Do not return
free-form analysis instead of the tool call.
"""

class TriageRunner:
    def __init__(self, provider: TriageProvider, cache: Optional[TriageCache] = None):
        self.provider = provider
        self.cache = cache
        self.settings = get_settings()

    def run(self, state: IncidentState, context: TriageIncidentContext) -> TriageRunResult:
        start_time = time.monotonic()
        
        # 1. Build TriageInput
        triage_input = build_triage_input(
            context=context,
            detected_signals=state.get("detected_signals", []),
            candidate_evidence=state.get("candidate_evidence", [])
        )
        
        state["safe_triage_input"] = triage_input.model_dump()
        
        # 2. Check Cache
        import json
        import hashlib
        payload = triage_input.model_dump(mode="json")
        serialized = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        content_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        if self.settings.triage_cache_enabled and self.cache:
            cache_key = build_cache_key(
                incident_id=context.incident.incident_id,
                incident_content_hash=content_hash,
                model=self.settings.llm_model,
                provider=self.settings.llm_provider,
                prompt_version=self.settings.triage_prompt_version,
                schema_version=self.settings.triage_schema_version
            )
            state["cache_key"] = cache_key
            cached_result = self.cache.get(cache_key)
            if cached_result:
                cached_result.metrics.cache_hit = True
                return cached_result

        # Initialize Metrics
        metrics = TriageMetrics(
            incident_id=context.incident.incident_id,
            provider=self.settings.llm_provider,
            model=self.settings.llm_model,
            prompt_version=TRIAGE_PROMPT_VERSION,
            schema_version=self.settings.triage_schema_version,
            started_at=time.time().__str__(),
            completed_at=""
        )

        timeout_seconds = float(
            getattr(
                self.provider,
                "timeout_seconds",
                self.settings.triage_timeout_seconds,
            )
        )
        deadline = start_time + timeout_seconds

        system_prompt = build_system_prompt(triage_input)
        
        # Approximate tokens
        approx_tokens = (len(triage_input.model_dump_json()) + len(system_prompt)) // 4
        if approx_tokens > self.settings.max_prompt_tokens:
            from agent.triage.models import TriageSubmission
            from agent.triage.enums import TriageVerdict, TriageSeverity
            metrics.review_reason = ReviewReason.PROMPT_BUDGET_EXCEEDED
            metrics.completed_at = time.time().__str__()
            metrics.latency_ms = (time.monotonic() - start_time) * 1000.0
            return TriageRunResult(
                submission=TriageSubmission(
                    triage_verdict=TriageVerdict.NEEDS_REVIEW,
                    incident_type="other",
                    severity=TriageSeverity.NONE,
                    confidence_score=0.0,
                    summary="Prompt budget exceeded before provider call.",
                    selected_evidence_ids=[],
                    claims=[]
                ),
                review_reason=ReviewReason.PROMPT_BUDGET_EXCEEDED,
                metrics=metrics
            )

        request = TriageProviderRequest(
            incident_id=context.incident.incident_id,
            triage_input=triage_input,
            system_prompt=system_prompt,
            context={"triage_input": triage_input},
            deadline=deadline
        )
        
        # 3. Invoke Provider with global deadline checks
        invalid_response_retry_count = 0
        try:
            while True:
                if time.monotonic() - start_time > timeout_seconds:
                    raise Exception("triage_timeout")

                try:
                    response = self.provider.invoke(request)
                except TriageProviderError as exc:
                    can_retry = (
                        exc.review_reason in _RETRYABLE_INVALID_OUTPUT_REASONS
                        and invalid_response_retry_count
                        < self.settings.llm_invalid_response_retries
                        and time.monotonic() < deadline
                    )
                    if not can_retry:
                        raise
                    invalid_response_retry_count += 1
                    request = TriageProviderRequest(
                        incident_id=context.incident.incident_id,
                        triage_input=triage_input,
                        system_prompt=system_prompt + _CORRECTIVE_RETRY_INSTRUCTION,
                        context={"triage_input": triage_input},
                        deadline=deadline,
                    )
                    continue

                if (
                    response.submission is None
                    and invalid_response_retry_count
                    < self.settings.llm_invalid_response_retries
                    and time.monotonic() < deadline
                ):
                    invalid_response_retry_count += 1
                    request = TriageProviderRequest(
                        incident_id=context.incident.incident_id,
                        triage_input=triage_input,
                        system_prompt=system_prompt + _CORRECTIVE_RETRY_INSTRUCTION,
                        context={"triage_input": triage_input},
                        deadline=deadline,
                    )
                    continue
                break
            
            metrics.provider_prompt_tokens = response.prompt_tokens
            metrics.provider_completion_tokens = response.completion_tokens
            metrics.total_tokens = response.prompt_tokens + response.completion_tokens
            metrics.iteration_count = getattr(response, 'iteration_count', 1)
            metrics.search_call_count = getattr(response, 'search_call_count', 0)
            metrics.tool_call_count = getattr(response, 'tool_call_count', 0)
            metrics.retry_count = (
                getattr(response, 'retry_count', 0)
                + invalid_response_retry_count
            )
            metrics.provider_latency_ms = (time.monotonic() - start_time) * 1000.0
            metrics.estimated_prompt_tokens = approx_tokens
            metrics.estimated_cost = None
            if hasattr(self.provider, 'circuit_breaker'):
                metrics.circuit_breaker_state = self.provider.circuit_breaker.state
            
            # Re-check deadline after invocation
            if time.monotonic() - start_time > timeout_seconds:
                raise Exception("triage_timeout")
            
            result = TriageRunResult(
                submission=response.submission,
                review_reason=ReviewReason.NONE if response.submission else ReviewReason.INVALID_LLM_OUTPUT,
                metrics=metrics,
                search_results=[] 
            )
            
        except TriageProviderError as e:
            metrics.fallback_used = True
            metrics.review_reason = e.review_reason
            metrics.retry_count = invalid_response_retry_count
            
            # Map timeout from provider specifically
            if e.review_reason == ReviewReason.PROVIDER_TIMEOUT:
                from agent.triage.models import TriageSubmission
                from agent.triage.enums import TriageVerdict, TriageSeverity
                
                result = TriageRunResult(
                    submission=TriageSubmission(
                        triage_verdict=TriageVerdict.NEEDS_REVIEW,
                        incident_type="other",
                        severity=TriageSeverity.NONE,
                        confidence_score=0.0,
                        summary="Provider request timed out.",
                        selected_evidence_ids=[],
                        claims=[]
                    ),
                    review_reason=ReviewReason.PROVIDER_TIMEOUT,
                    metrics=metrics
                )
            else:
                result = TriageRunResult(
                    submission=None,
                    review_reason=e.review_reason,
                    metrics=metrics
                )
        except Exception as e:
            metrics.fallback_used = True
            
            # Check for global triage timeout
            if str(e) == "triage_timeout":
                metrics.review_reason = ReviewReason.PROVIDER_TIMEOUT
                from agent.triage.models import TriageSubmission
                from agent.triage.enums import TriageVerdict, TriageSeverity
                
                result = TriageRunResult(
                    submission=TriageSubmission(
                        triage_verdict=TriageVerdict.NEEDS_REVIEW,
                        incident_type="other",
                        severity=TriageSeverity.NONE,
                        confidence_score=0.0,
                        summary="Global triage timeout exceeded.",
                        selected_evidence_ids=[],
                        claims=[]
                    ),
                    review_reason=ReviewReason.PROVIDER_TIMEOUT, # Map to provider_timeout or triage_timeout depending on enum. But review reason only has PROVIDER_TIMEOUT for now
                    metrics=metrics
                )
            else:
                metrics.review_reason = ReviewReason.PROVIDER_UNAVAILABLE
                result = TriageRunResult(
                    submission=None,
                    review_reason=ReviewReason.PROVIDER_UNAVAILABLE,
                    metrics=metrics
                )
            
        metrics.completed_at = time.time().__str__()
        metrics.latency_ms = (time.monotonic() - start_time) * 1000.0
        
        # 4. Save to cache if valid
        if self.settings.triage_cache_enabled and self.cache and result.submission and result.review_reason == ReviewReason.NONE:
            self.cache.set(state["cache_key"], result, ttl_seconds=self.settings.triage_cache_ttl_seconds)
            
        return result
