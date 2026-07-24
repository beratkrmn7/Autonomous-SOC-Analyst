"""Optional remote OpenAI-compatible ``llama.cpp`` triage provider.

This is a small, isolated third provider. It speaks the OpenAI chat-completions
shape (``/v1/chat/completions``, ``Authorization: Bearer``) and reuses every
existing protection: the shared circuit breaker, the retry policy, deadline
handling, the provider exception hierarchy, the bounded search tool and the
telemetry response models. It does not add a second provider abstraction and it
never touches the Groq or Ollama implementations.

The provider never reads, persists, logs or exposes ``reasoning_content`` and
never places the API key or a raw response body into an error message.
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional

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
    BriefEnrichmentProviderRequest,
    BriefEnrichmentProviderResponse,
    TriageProvider,
    TriageProviderRequest,
    TriageProviderResponse,
)
from agent.triage.retry import with_retry
from agent.triage.tools import SearchLogsTool


class OpenAICompatibleTriageProvider(TriageProvider):
    """Bounded triage provider for a remote OpenAI-compatible server."""

    def __init__(
        self,
        circuit_breaker: Optional[CircuitBreaker] = None,
        client: Optional[httpx.Client] = None,
        settings: Optional[Any] = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.circuit_breaker = circuit_breaker or CircuitBreaker()
        self.client = client

        if not self.settings.llm_enabled:
            raise ProviderConfigurationError("LLM is disabled")

        base_url = str(self.settings.openai_compatible_base_url).strip().rstrip("/")
        if not base_url:
            raise ProviderConfigurationError(
                "OPENAI_COMPATIBLE_BASE_URL is missing"
            )
        api_key = self.settings.openai_compatible_api_key
        if api_key is None or not api_key.get_secret_value().strip():
            raise ProviderConfigurationError(
                "OPENAI_COMPATIBLE_API_KEY is missing"
            )
        if not str(self.settings.llm_model).strip():
            raise ProviderConfigurationError("LLM_MODEL is missing")

        self._api_key = api_key
        self.chat_url = f"{base_url}/chat/completions"

    # -- request construction -------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key.get_secret_value()}",
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
        }

    def _base_payload(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "model": self.settings.llm_model,
            "messages": messages,
            "temperature": 0,
            "max_tokens": self.settings.max_completion_tokens,
            "stream": False,
            "chat_template_kwargs": {
                "enable_thinking": bool(
                    self.settings.openai_compatible_enable_thinking
                ),
            },
        }

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
                                "description": (
                                    "Substring to find in incident-scope logs."
                                ),
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
            raise ProviderTimeoutError(
                "Deadline exceeded before provider call"
            )
        return remaining

    # -- transport ------------------------------------------------------------

    def _post_chat(
        self,
        payload: dict[str, Any],
        deadline: Optional[float],
    ) -> tuple[dict[str, Any], int]:
        # Encode explicitly as UTF-8 so Turkish (and any non-ASCII) evidence in
        # the bounded payload is transmitted safely without escaping.
        body_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        def call() -> dict[str, Any]:
            timeout = self._remaining_timeout(
                deadline,
                float(self.settings.triage_timeout_seconds),
            )
            try:
                if self.client is not None:
                    response = self.client.post(
                        self.chat_url,
                        content=body_bytes,
                        headers=self._headers(),
                        timeout=timeout,
                    )
                else:
                    with httpx.Client(timeout=timeout) as client:
                        response = client.post(
                            self.chat_url,
                            content=body_bytes,
                            headers=self._headers(),
                        )
            except httpx.TimeoutException as exc:
                raise ProviderTimeoutError("Provider request timed out") from exc
            except httpx.RequestError as exc:
                raise ProviderUnavailableError("Provider is unavailable") from exc

            status = response.status_code
            if status in {401, 403}:
                raise ProviderAuthenticationError(
                    "Provider authentication failed"
                )
            if status == 429:
                raise ProviderRateLimitError("Provider rate limit exceeded")
            if status in {408, 504}:
                raise ProviderTimeoutError("Provider request timed out")
            if status >= 500:
                raise ProviderUnavailableError("Provider server error")
            if status >= 400:
                # Never surface the response body: it may echo the prompt,
                # bounded evidence or credentials.
                raise ProviderInvalidResponseError(
                    "Provider rejected the request"
                )

            try:
                parsed = response.json()
            except ValueError as exc:
                raise ProviderInvalidResponseError(
                    "Provider returned non-JSON output"
                ) from exc
            if not isinstance(parsed, dict):
                raise ProviderInvalidResponseError(
                    "Provider returned invalid output"
                )
            return parsed

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
                "Provider circuit breaker is open",
                ReviewReason.CIRCUIT_BREAKER_OPEN,
            ) from exc
        except TriageProviderError:
            self.circuit_breaker.record_failure()
            raise
        except Exception as exc:  # pragma: no cover - defensive
            self.circuit_breaker.record_failure()
            raise ProviderUnavailableError("Provider request failed") from exc

    # -- response parsing -----------------------------------------------------

    @staticmethod
    def _message(body: dict[str, Any]) -> dict[str, Any]:
        choices = body.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ProviderInvalidResponseError(
                "Provider response is missing choices"
            )
        first = choices[0]
        message = first.get("message") if isinstance(first, dict) else None
        if not isinstance(message, dict):
            raise ProviderInvalidResponseError(
                "Provider response is missing the assistant message"
            )
        return message

    @staticmethod
    def _usage(body: dict[str, Any]) -> tuple[int, int]:
        usage = body.get("usage")
        if not isinstance(usage, dict):
            return 0, 0
        return (
            int(usage.get("prompt_tokens") or 0),
            int(usage.get("completion_tokens") or 0),
        )

    @staticmethod
    def _content_text(message: dict[str, Any]) -> Optional[str]:
        # Only the visible answer is read. ``reasoning_content`` is deliberately
        # ignored and never persisted, logged or returned.
        content = message.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            return "".join(
                part.get("text", "") if isinstance(part, dict) else str(part)
                for part in content
            )
        return None

    @staticmethod
    def _parse_json_content(text: str) -> object:
        stripped = text.strip()
        # Tolerate a single fenced block around the JSON object, matching the
        # existing providers. Malformed JSON is rejected, never repaired.
        if stripped.startswith("```"):
            stripped = stripped.strip("`")
            newline = stripped.find("\n")
            if newline != -1:
                stripped = stripped[newline + 1 :]
            stripped = stripped.strip()
        try:
            return json.loads(stripped)
        except ValueError as exc:
            raise ProviderInvalidResponseError(
                "Provider returned non-JSON enrichment output"
            ) from exc

    @staticmethod
    def _tool_arguments(tool_call: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        function = tool_call.get("function")
        if not isinstance(function, dict):
            raise TriageProviderError(
                "Invalid tool call",
                ReviewReason.INVALID_TOOL_CALL,
            )
        name = function.get("name")
        arguments = function.get("arguments", {})
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError as exc:
                raise TriageProviderError(
                    "Invalid tool arguments",
                    ReviewReason.INVALID_TOOL_CALL,
                ) from exc
        if not isinstance(name, str) or not isinstance(arguments, dict):
            raise TriageProviderError(
                "Invalid tool call",
                ReviewReason.INVALID_TOOL_CALL,
            )
        return name, arguments

    # -- brief enrichment -----------------------------------------------------

    def invoke_brief_enrichment(
        self, request: BriefEnrichmentProviderRequest
    ) -> BriefEnrichmentProviderResponse:
        """One bounded batch enrichment call, reusing the existing transport.

        The same client, timeout handling, retry policy and circuit breaker as
        single-incident triage; no second HTTP stack is introduced and
        one-call-per-file behaviour is preserved.
        """
        payload = self._base_payload(
            [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.payload},
            ]
        )
        body, retries = self._post_chat(payload, request.deadline)
        message = self._message(body)
        content = self._content_text(message)
        if not isinstance(content, str) or not content.strip():
            raise ProviderInvalidResponseError(
                "Provider returned empty enrichment output"
            )
        parsed = self._parse_json_content(content)
        prompt_tokens, completion_tokens = self._usage(body)

        return BriefEnrichmentProviderResponse(
            raw_payload=parsed,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            retry_count=retries,
        )

    # -- legacy per-incident triage ------------------------------------------

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
                # prompt; repeating it here only inflates prompt tokens.
                "content": "Analyze the incident data and submit the triage verdict.",
            },
        ]
        tools = self._tools()
        prompt_tokens = 0
        completion_tokens = 0
        tool_call_count = 0
        retry_count = 0

        for iteration in range(self.settings.max_agent_iterations):
            payload = self._base_payload(messages)
            payload["tools"] = tools
            body, attempts = self._post_chat(payload, request.deadline)
            retry_count += attempts
            call_prompt, call_completion = self._usage(body)
            prompt_tokens += call_prompt
            completion_tokens += call_completion

            assistant_message = self._message(body)
            tool_calls = assistant_message.get("tool_calls") or []
            if not isinstance(tool_calls, list):
                raise ProviderInvalidResponseError(
                    "Provider response contains invalid tool calls"
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
                            "You must call submit_triage_result to provide the "
                            "final verdict."
                        ),
                    }
                )
                continue

            parsed_calls = [
                (self._tool_arguments(call), call) for call in tool_calls
            ]
            if (
                any(name == "submit_triage_result" for (name, _), _ in parsed_calls)
                and len(parsed_calls) > 1
            ):
                raise TriageProviderError(
                    "Mixed tool calls",
                    ReviewReason.MIXED_TOOL_CALLS,
                )

            for (name, arguments), raw_call in parsed_calls:
                tool_call_count += 1
                call_id = raw_call.get("id") if isinstance(raw_call, dict) else None
                if name == "submit_triage_result":
                    try:
                        submission = TriageSubmission.model_validate(arguments)
                    except Exception as exc:
                        if iteration == self.settings.max_agent_iterations - 1:
                            raise ProviderInvalidResponseError(
                                "Provider returned an invalid triage submission"
                            ) from exc
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": call_id,
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
                        search_result = search_tool(
                            str(arguments.get("query") or "")
                        )
                    except ProviderMaxSearchCallsError:
                        raise
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call_id,
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
                    "Invalid tool call",
                    ReviewReason.INVALID_TOOL_CALL,
                )

        raise ProviderMaxIterationsError("Maximum iterations reached")
