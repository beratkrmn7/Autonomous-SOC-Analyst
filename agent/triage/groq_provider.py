from typing import Any, List, Optional
from agent.triage.provider import (
    BriefEnrichmentProviderRequest,
    BriefEnrichmentProviderResponse,
    TriageProvider,
    TriageProviderRequest,
    TriageProviderResponse,
)
from agent.triage.models import TriageSubmission
from agent.triage.exceptions import (
    TriageProviderError,
    ProviderConfigurationError,
    ProviderUnavailableError,
    ProviderTimeoutError,
    ProviderRateLimitError,
    ProviderAuthenticationError,
    ProviderInvalidResponseError,
    ProviderMaxIterationsError,
    ProviderMaxSearchCallsError
)
from agent.triage.retry import with_retry
from agent.triage.circuit_breaker import CircuitBreaker, CircuitBreakerOpenError
from agent.triage.tools import SearchLogsTool
from agent.triage.enums import ReviewReason
from agent.config import get_settings

from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
from langchain_groq import ChatGroq
import groq

class GroqTriageProvider(TriageProvider):
    def __init__(self, model_name: str = "llama3-70b-8192", circuit_breaker: Optional['CircuitBreaker'] = None, llm: Optional[Any] = None, settings: Optional[Any] = None):
        self.settings = settings or get_settings()
        self.circuit_breaker = circuit_breaker or CircuitBreaker()
        
        if not self.settings.llm_enabled:
            raise ProviderConfigurationError("LLM is disabled")
        if not self.settings.groq_api_key and not llm:
            raise ProviderConfigurationError("GROQ_API_KEY is missing")
            
        self.llm = llm or ChatGroq(
            model=self.settings.llm_model,
            temperature=0,
            api_key=self.settings.groq_api_key,
            max_retries=0 # Handled by our own retry
        )
        
    def _invoke_with_circuit_breaker(self, messages: List[Any], tools: List[Any], timeout: Optional[float] = None) -> Any:
        self.circuit_breaker.check()
        
        def _call():
            try:
                if timeout is not None and not getattr(self, "_custom_llm_injected", False) and isinstance(self.llm, ChatGroq):
                    temp_llm = ChatGroq(
                        model=self.settings.llm_model,
                        temperature=0,
                        api_key=self.settings.groq_api_key,
                        max_retries=0,
                        request_timeout=max(0.1, timeout)  # type: ignore[call-arg]
                    )
                    llm_with_tools = temp_llm.bind_tools(tools)
                else:
                    llm_with_tools = self.llm.bind_tools(tools)
                kwargs: Any = {}
                return llm_with_tools.invoke(messages, **kwargs)
            except groq.RateLimitError as e:
                retry_after: float | None = None
                try:
                    header = e.response.headers.get("retry-after")
                    if header is not None:
                        retry_after = float(header)
                except (AttributeError, TypeError, ValueError):
                    retry_after = None
                raise ProviderRateLimitError(
                    "Groq rate limit exceeded",
                    retry_after_seconds=retry_after,
                ) from e
            except groq.APITimeoutError as e:
                raise ProviderTimeoutError(str(e))
            except groq.AuthenticationError as e:
                # Auth error should not be retried and breaks immediately
                self.circuit_breaker.record_failure()
                raise ProviderAuthenticationError(str(e))
            except groq.APIError as e:
                raise ProviderUnavailableError(str(e))
                
        try:
            res, retries = with_retry(
                _call, 
                max_retries=self.settings.llm_max_retries, 
                base_delay=self.settings.llm_retry_base_seconds,
                max_delay=self.settings.llm_retry_max_seconds
            )
            self.circuit_breaker.record_success()
            return res, retries
        except (ProviderTimeoutError, ProviderRateLimitError, ProviderAuthenticationError, ProviderUnavailableError) as e:
            self.circuit_breaker.record_failure()
            raise e
        except Exception as e:
            self.circuit_breaker.record_failure()
            raise ProviderUnavailableError(str(e))

    def invoke_brief_enrichment(
        self, request: BriefEnrichmentProviderRequest
    ) -> BriefEnrichmentProviderResponse:
        """One bounded batch enrichment call, reusing the existing transport.

        Shares the circuit breaker, retry policy and timeout handling with
        single-incident triage; no second client or retry stack is introduced.
        """
        import json
        import time

        messages = [
            SystemMessage(content=request.system_prompt),
            HumanMessage(content=request.payload),
        ]

        timeout = None
        if request.deadline:
            timeout = request.deadline - time.monotonic()
            if timeout <= 0:
                raise ProviderTimeoutError("Deadline exceeded before provider call")

        ai_message, retries = self._invoke_with_circuit_breaker(
            messages, [], timeout=timeout
        )

        content = getattr(ai_message, "content", None)
        if isinstance(content, list):
            content = "".join(
                part.get("text", "") if isinstance(part, dict) else str(part)
                for part in content
            )
        parsed: object = None
        if isinstance(content, str) and content.strip():
            text = content.strip()
            # Tolerate a fenced block around the JSON object; anything else is
            # rejected as invalid rather than guessed at.
            if text.startswith("```"):
                text = text.strip("`")
                newline = text.find("\n")
                if newline != -1:
                    text = text[newline + 1 :]
            try:
                parsed = json.loads(text)
            except ValueError as exc:
                raise ProviderInvalidResponseError(
                    "Groq returned non-JSON enrichment output"
                ) from exc

        prompt_tokens = 0
        completion_tokens = 0
        metadata = getattr(ai_message, "response_metadata", None)
        if isinstance(metadata, dict) and "token_usage" in metadata:
            usage = metadata["token_usage"]
            prompt_tokens = usage.get("prompt_tokens", 0)
            completion_tokens = usage.get("completion_tokens", 0)

        return BriefEnrichmentProviderResponse(
            raw_payload=parsed,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            retry_count=retries,
        )

    def invoke(self, request: TriageProviderRequest) -> TriageProviderResponse:
        messages = [
            SystemMessage(content=request.system_prompt),
            HumanMessage(
                content="Analyze the incident data and submit the triage verdict."
            ),
        ]
        
        triage_input = request.context.get("triage_input")
        if not triage_input:
            raise ProviderConfigurationError("TriageInput context missing")
            
        search_tool = SearchLogsTool(
            incident_events=triage_input.limited_context_events,
            max_calls=self.settings.max_search_calls,
            max_query_chars=self.settings.max_search_query_chars,
            max_results=self.settings.max_search_results
        )
        
        # Tools definitions for Langchain
        from langchain_core.tools import tool
        
        @tool
        def search_logs(query: str) -> str:
            """Searches the incident scope logs for the given substring query."""
            res = search_tool(query)
            return res.model_dump_json(include={"query", "matched_event_ids", "truncated", "results"})
            
        @tool(args_schema=TriageSubmission)
        def submit_triage_result(
            triage_verdict: str,
            incident_type: str,
            severity: str,
            confidence_score: float,
            summary: str,
            selected_evidence_ids: List[str],
            claims: List[dict]
        ) -> str:
            """Submit the final triage verdict."""
            return "SUBMITTED"
            
        tools = [search_logs, submit_triage_result]
        
        total_prompt_tokens = 0
        total_completion_tokens = 0
        tool_call_count = 0
        total_retry_count = 0
        
        for iteration in range(self.settings.max_agent_iterations):
            try:
                timeout = None
                if request.deadline:
                    import time
                    timeout = request.deadline - time.monotonic()
                    if timeout <= 0:
                        raise ProviderTimeoutError("Deadline exceeded before provider call")
                ai_message, attempt_count = self._invoke_with_circuit_breaker(messages, tools, timeout=timeout)
                total_retry_count += attempt_count
            except (CircuitBreakerOpenError, ProviderTimeoutError, ProviderRateLimitError, ProviderAuthenticationError, ProviderConfigurationError) as e:
                raise e
            except Exception as e:
                # Wrap any unknown
                raise ProviderUnavailableError(str(e))
                
            if hasattr(ai_message, "response_metadata") and "token_usage" in ai_message.response_metadata:
                usage = ai_message.response_metadata["token_usage"]
                total_prompt_tokens += usage.get("prompt_tokens", 0)
                total_completion_tokens += usage.get("completion_tokens", 0)
                
            messages.append(ai_message)
            
            if not ai_message.tool_calls:
                # Force tool call or fail
                if iteration == self.settings.max_agent_iterations - 1:
                    raise ProviderInvalidResponseError("Max iterations reached without submission")
                messages.append(HumanMessage(content="You must use the submit_triage_result tool to provide your final verdict."))
                continue
                
            # Check for mixed tool calls
            has_submit = any(tc["name"] == "submit_triage_result" for tc in ai_message.tool_calls)
            if has_submit and len(ai_message.tool_calls) > 1:
                raise TriageProviderError("Mixed tool calls", ReviewReason.MIXED_TOOL_CALLS)
                
            for tool_call in ai_message.tool_calls:
                tool_call_count += 1
                if tool_call["name"] == "submit_triage_result":
                    try:
                        submission = TriageSubmission.model_validate(tool_call["args"])
                        return TriageProviderResponse(
                            submission=submission,
                            prompt_tokens=total_prompt_tokens,
                            completion_tokens=total_completion_tokens,
                            iteration_count=iteration + 1,
                            search_call_count=search_tool.calls,
                            tool_call_count=tool_call_count,
                            retry_count=total_retry_count
                        )
                    except Exception as e:
                        if iteration == self.settings.max_agent_iterations - 1:
                            raise ProviderInvalidResponseError(f"Validation error: {e}")
                        messages.append(ToolMessage(tool_call_id=tool_call["id"], content="invalid_submission_schema", name="submit_triage_result"))
                        
                elif tool_call["name"] == "search_logs":
                    try:
                        result_str = search_logs.invoke(tool_call["args"])
                        messages.append(ToolMessage(tool_call_id=tool_call["id"], content=result_str, name="search_logs"))
                    except ProviderMaxSearchCallsError as e:
                        raise e
                    except Exception:
                        messages.append(ToolMessage(tool_call_id=tool_call["id"], content="tool_execution_failed", name="search_logs"))
                else:
                    raise TriageProviderError("Invalid tool call", ReviewReason.INVALID_TOOL_CALL)

        raise ProviderMaxIterationsError("Max iterations reached")
