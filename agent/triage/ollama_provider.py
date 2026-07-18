import json
import time
from typing import Any, Optional
from urllib.parse import urlsplit

import httpx

from agent.config import get_settings
from agent.triage.circuit_breaker import CircuitBreaker, CircuitBreakerOpenError
from agent.triage.enums import ReviewReason
from agent.triage.exceptions import (
    ProviderAuthenticationError,
    ProviderConfigurationError,
    ProviderInvalidResponseError,
    ProviderMaxIterationsError,
    ProviderMaxSearchCallsError,
    ProviderRateLimitError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    TriageProviderError,
)
from agent.triage.models import TriageSubmission
from agent.triage.provider import (
    TriageProvider,
    TriageProviderRequest,
    TriageProviderResponse,
)
from agent.triage.retry import with_retry
from agent.triage.tools import SearchLogsTool


_LOCAL_OLLAMA_HOSTS = {"localhost", "127.0.0.1", "::1"}


class OllamaTriageProvider(TriageProvider):
    """Bounded local triage provider using Ollama's native chat/tool API."""

    def __init__(
        self,
        circuit_breaker: Optional[CircuitBreaker] = None,
        client: Optional[httpx.Client] = None,
        settings: Optional[Any] = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.circuit_breaker = circuit_breaker or CircuitBreaker()
        self.client = client
        self.timeout_seconds = self.settings.ollama_triage_timeout_seconds

        if not self.settings.llm_enabled:
            raise ProviderConfigurationError("LLM is disabled")

        base_url = str(self.settings.ollama_base_url).rstrip("/")
        parsed = urlsplit(base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname not in _LOCAL_OLLAMA_HOSTS
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ProviderConfigurationError(
                "OLLAMA_BASE_URL must reference a local Ollama origin"
            )
        self.chat_url = f"{base_url}/api/chat"

    @staticmethod
    def _tools() -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "search_logs",
                    "description": "Search incident-scope logs for a substring.",
                    "parameters": {
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Substring to find in incident-scope logs.",
                            }
                        },
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "submit_triage_result",
                    "description": "Submit the final structured SOC triage verdict.",
                    "parameters": TriageSubmission.model_json_schema(),
                },
            },
        ]

    @staticmethod
    def _remaining_timeout(deadline: Optional[float], default: float) -> float:
        if deadline is None:
            return default
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProviderTimeoutError("Deadline exceeded before Ollama call")
        return remaining

    def _post_chat(
        self,
        payload: dict[str, Any],
        deadline: Optional[float],
    ) -> tuple[dict[str, Any], int]:
        def call() -> dict[str, Any]:
            timeout = self._remaining_timeout(
                deadline,
                float(self.settings.triage_timeout_seconds),
            )
            try:
                if self.client is not None:
                    response = self.client.post(
                        self.chat_url,
                        json=payload,
                        timeout=timeout,
                    )
                else:
                    with httpx.Client(timeout=timeout) as client:
                        response = client.post(self.chat_url, json=payload)
            except httpx.TimeoutException as exc:
                raise ProviderTimeoutError("Ollama request timed out") from exc
            except httpx.RequestError as exc:
                raise ProviderUnavailableError("Ollama is unavailable") from exc

            if response.status_code == 429:
                raise ProviderRateLimitError("Ollama rate limit exceeded")
            if response.status_code in {401, 403}:
                raise ProviderAuthenticationError("Ollama authentication failed")
            if response.status_code in {408, 504}:
                raise ProviderTimeoutError("Ollama request timed out")
            if response.status_code == 404:
                raise ProviderConfigurationError(
                    "Ollama endpoint or configured model was not found"
                )
            if response.status_code >= 500:
                raise ProviderUnavailableError("Ollama server error")
            if response.status_code >= 400:
                raise ProviderInvalidResponseError("Ollama rejected the request")

            try:
                body = response.json()
            except ValueError as exc:
                raise ProviderInvalidResponseError(
                    "Ollama returned non-JSON output"
                ) from exc
            if not isinstance(body, dict):
                raise ProviderInvalidResponseError("Ollama returned invalid output")
            return body

        try:
            self.circuit_breaker.check()
            result, retries = with_retry(
                call,
                max_retries=self.settings.llm_max_retries,
                base_delay=self.settings.llm_retry_base_seconds,
                max_delay=self.settings.llm_retry_max_seconds,
            )
            self.circuit_breaker.record_success()
            return result, retries
        except CircuitBreakerOpenError as exc:
            raise TriageProviderError(
                "Ollama circuit breaker is open",
                ReviewReason.CIRCUIT_BREAKER_OPEN,
            ) from exc
        except TriageProviderError:
            self.circuit_breaker.record_failure()
            raise
        except Exception as exc:
            self.circuit_breaker.record_failure()
            raise ProviderUnavailableError("Ollama request failed") from exc

    @staticmethod
    def _tool_arguments(tool_call: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        function = tool_call.get("function")
        if not isinstance(function, dict):
            raise TriageProviderError(
                "Invalid Ollama tool call",
                ReviewReason.INVALID_TOOL_CALL,
            )

        name = function.get("name")
        arguments = function.get("arguments", {})
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError as exc:
                raise TriageProviderError(
                    "Invalid Ollama tool arguments",
                    ReviewReason.INVALID_TOOL_CALL,
                ) from exc
        if not isinstance(name, str) or not isinstance(arguments, dict):
            raise TriageProviderError(
                "Invalid Ollama tool call",
                ReviewReason.INVALID_TOOL_CALL,
            )
        return name, arguments

    def invoke(self, request: TriageProviderRequest) -> TriageProviderResponse:
        triage_input = request.context.get("triage_input")
        if not triage_input:
            raise ProviderConfigurationError("TriageInput context missing")

        search_tool = SearchLogsTool(
            incident_events=triage_input.limited_context_events,
            max_calls=self.settings.max_search_calls,
            max_query_chars=self.settings.max_search_query_chars,
            max_results=self.settings.max_search_results,
        )
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": request.system_prompt},
            {
                "role": "user",
                # The bounded triage input is already embedded in the system
                # prompt. Repeating it here nearly doubles local prompt-eval
                # work without adding evidence or instructions.
                "content": "Analyze the incident data and submit the triage verdict.",
            },
        ]
        tools = self._tools()
        prompt_tokens = 0
        completion_tokens = 0
        tool_call_count = 0
        retry_count = 0

        for iteration in range(self.settings.max_agent_iterations):
            payload = {
                "model": self.settings.llm_model,
                "messages": messages,
                "stream": False,
                "tools": tools,
                "keep_alive": self.settings.ollama_keep_alive,
                "options": {
                    "temperature": 0,
                    "num_predict": self.settings.max_completion_tokens,
                },
            }
            body, attempts = self._post_chat(payload, request.deadline)
            retry_count += attempts
            prompt_tokens += int(body.get("prompt_eval_count") or 0)
            completion_tokens += int(body.get("eval_count") or 0)

            assistant_message = body.get("message")
            if not isinstance(assistant_message, dict):
                raise ProviderInvalidResponseError(
                    "Ollama response is missing the assistant message"
                )
            tool_calls = assistant_message.get("tool_calls") or []
            if not isinstance(tool_calls, list):
                raise ProviderInvalidResponseError(
                    "Ollama response contains invalid tool calls"
                )

            messages.append(
                {
                    "role": "assistant",
                    "content": str(assistant_message.get("content") or ""),
                    "tool_calls": tool_calls,
                }
            )
            if not tool_calls:
                if iteration == self.settings.max_agent_iterations - 1:
                    raise ProviderInvalidResponseError(
                        "Maximum iterations reached without submission"
                    )
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "You must call submit_triage_result to provide the final verdict."
                        ),
                    }
                )
                continue

            parsed_calls = [self._tool_arguments(call) for call in tool_calls]
            if any(name == "submit_triage_result" for name, _ in parsed_calls) and len(
                parsed_calls
            ) > 1:
                raise TriageProviderError(
                    "Mixed Ollama tool calls",
                    ReviewReason.MIXED_TOOL_CALLS,
                )

            for name, arguments in parsed_calls:
                tool_call_count += 1
                if name == "submit_triage_result":
                    try:
                        submission = TriageSubmission.model_validate(arguments)
                    except Exception as exc:
                        if iteration == self.settings.max_agent_iterations - 1:
                            raise ProviderInvalidResponseError(
                                "Ollama returned an invalid triage submission"
                            ) from exc
                        messages.append(
                            {
                                "role": "tool",
                                "tool_name": name,
                                "content": "invalid_submission_schema",
                            }
                        )
                        continue
                    return TriageProviderResponse(
                        submission=submission,
                        prompt_tokens=prompt_tokens,
                        completion_tokens=completion_tokens,
                        iteration_count=iteration + 1,
                        search_call_count=search_tool.calls,
                        tool_call_count=tool_call_count,
                        retry_count=retry_count,
                    )

                if name == "search_logs":
                    try:
                        search_result = search_tool(str(arguments.get("query") or ""))
                    except ProviderMaxSearchCallsError:
                        raise
                    messages.append(
                        {
                            "role": "tool",
                            "tool_name": name,
                            "content": search_result.model_dump_json(
                                include={
                                    "query",
                                    "matched_event_ids",
                                    "truncated",
                                    "results",
                                }
                            ),
                        }
                    )
                    continue

                raise TriageProviderError(
                    "Invalid Ollama tool call",
                    ReviewReason.INVALID_TOOL_CALL,
                )

        raise ProviderMaxIterationsError("Maximum Ollama iterations reached")
