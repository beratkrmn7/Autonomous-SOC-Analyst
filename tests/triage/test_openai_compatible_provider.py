"""Focused unit tests for the optional OpenAI-compatible llama.cpp provider.

Every test uses an injected ``httpx.Client`` backed by ``MockTransport`` (or a
raising transport); none of them contact a real server. The suite also asserts
that the API key never leaks into exceptions or captured logs and that
deterministic detection makes zero provider calls.
"""

import json
import logging
import time
from datetime import datetime

import httpx
import pytest

import agent.nodes as nodes
from agent.config import Settings
from agent.detection.engine import DetectionEngine
from agent.schema import CanonicalLogEvent
from agent.triage.enums import ReviewReason
from agent.triage.exceptions import (
    ProviderAuthenticationError,
    ProviderConfigurationError,
    ProviderInvalidResponseError,
    ProviderRateLimitError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    TriageProviderError,
)
from agent.triage.models import SafeEventView, TriageInput
from agent.triage.openai_compatible_provider import OpenAICompatibleTriageProvider
from agent.triage.provider import (
    BriefEnrichmentProviderRequest,
    TriageProviderRequest,
)


SECRET_API_KEY = "super-secret-key-value-42"
BASE_URL = "https://model.internal:8000/v1"
MODEL = "Qwen3.5-35B-A3B-UD-IQ4_XS.gguf"


def _settings(**overrides) -> Settings:
    values = {
        "llm_enabled": True,
        "llm_provider": "openai_compatible",
        "llm_model": MODEL,
        "openai_compatible_base_url": BASE_URL,
        "openai_compatible_api_key": SECRET_API_KEY,
        "openai_compatible_enable_thinking": False,
        "openai_compatible_context_window_tokens": 8192,
        "max_prompt_tokens": 5500,
        "max_completion_tokens": 1500,
        "llm_max_retries": 0,
        "llm_retry_base_seconds": 0.01,
        "llm_retry_max_seconds": 0.01,
        "max_agent_iterations": 3,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def _provider(client, **overrides) -> OpenAICompatibleTriageProvider:
    return OpenAICompatibleTriageProvider(
        client=client, settings=_settings(**overrides)
    )


def _request(*, with_event: bool = False) -> TriageProviderRequest:
    events = []
    if with_event:
        events = [
            SafeEventView(
                event_id="event-1",
                timestamp="2026-07-10T09:54:00Z",
                parser_name="pf_firewall",
                source_name="firewall.json",
                sanitized_message_excerpt="blocked SYN probe",
            )
        ]
    triage_input = TriageInput(
        incident_id="incident-1",
        incident_type="horizontal_scan",
        incident_family="network_scanning",
        title="Horizontal scan",
        deterministic_severity="high",
        deterministic_confidence=0.91,
        first_seen="2026-07-10T09:54:00Z",
        last_seen="2026-07-10T09:55:00Z",
        primary_entity="192.0.2.10",
        limited_context_events=events,
    )
    return TriageProviderRequest(
        incident_id=triage_input.incident_id,
        triage_input=triage_input,
        system_prompt="Use the tools and remain evidence-bound. Şüpheli tarama.",
        context={"triage_input": triage_input},
        deadline=time.monotonic() + 10,
    )


def _submit_call(verdict: str = "suspicious_activity", call_id: str = "call-1") -> dict:
    return {
        "id": call_id,
        "type": "function",
        "function": {
            "name": "submit_triage_result",
            "arguments": json.dumps(
                {
                    "triage_verdict": verdict,
                    "incident_type": "horizontal_scan",
                    "severity": "high" if verdict != "false_positive" else "none",
                    "confidence_score": 0.88,
                    "summary": "Repeated blocked SYN probes were detected.",
                    "selected_evidence_ids": [],
                    "claims": [],
                }
            ),
        },
    }


def _chat_response(tool_calls, *, prompt=120, completion=32) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "choices": [
                {"message": {"role": "assistant", "tool_calls": tool_calls}}
            ],
            "usage": {"prompt_tokens": prompt, "completion_tokens": completion},
        },
    )


# -- factory selection --------------------------------------------------------


def test_factory_selects_openai_compatible(monkeypatch) -> None:
    import agent.triage.openai_compatible_provider as oc_module
    from agent.triage import provider_factory

    sentinel = object()
    provider_factory.reset_shared_circuit_breaker()
    monkeypatch.setattr(nodes, "get_settings", lambda: _settings())
    monkeypatch.setattr(
        oc_module,
        "OpenAICompatibleTriageProvider",
        lambda circuit_breaker: sentinel,
    )
    monkeypatch.setattr(
        "agent.triage.groq_provider.GroqTriageProvider",
        lambda circuit_breaker: pytest.fail("Groq must not be selected"),
    )

    assert nodes.get_triage_runner().provider is sentinel


def test_factory_still_selects_groq_by_default(monkeypatch) -> None:
    from agent.triage import provider_factory

    sentinel = object()
    provider_factory.reset_shared_circuit_breaker()
    monkeypatch.setattr(
        nodes,
        "get_settings",
        lambda: Settings(_env_file=None, llm_provider="groq", groq_api_key="k"),
    )
    monkeypatch.setattr(
        "agent.triage.groq_provider.GroqTriageProvider",
        lambda circuit_breaker: sentinel,
    )
    monkeypatch.setattr(
        "agent.triage.openai_compatible_provider.OpenAICompatibleTriageProvider",
        lambda circuit_breaker: pytest.fail("openai_compatible must not be selected"),
    )

    assert nodes.get_triage_runner().provider is sentinel


def test_factory_still_selects_ollama(monkeypatch) -> None:
    import agent.triage.ollama_provider as ollama_module
    from agent.triage import provider_factory

    sentinel = object()
    provider_factory.reset_shared_circuit_breaker()
    monkeypatch.setattr(
        nodes,
        "get_settings",
        lambda: Settings(_env_file=None, llm_provider="ollama"),
    )
    monkeypatch.setattr(
        ollama_module,
        "OllamaTriageProvider",
        lambda circuit_breaker: sentinel,
    )
    monkeypatch.setattr(
        "agent.triage.openai_compatible_provider.OpenAICompatibleTriageProvider",
        lambda circuit_breaker: pytest.fail("openai_compatible must not be selected"),
    )

    assert nodes.get_triage_runner().provider is sentinel


# -- settings validation ------------------------------------------------------


def test_missing_api_key_is_rejected() -> None:
    with pytest.raises(ValueError) as exc:
        _settings(openai_compatible_api_key=None)
    assert "openai_compatible_api_key_required" in str(exc.value)


def test_invalid_base_url_is_rejected() -> None:
    with pytest.raises(ValueError) as exc:
        _settings(openai_compatible_base_url="ftp://model.internal/v1")
    assert "openai_compatible_base_url_invalid" in str(exc.value)


def test_base_url_with_embedded_credentials_is_rejected() -> None:
    with pytest.raises(ValueError):
        _settings(openai_compatible_base_url="https://user:pass@model.internal/v1")


def test_remote_http_requires_explicit_opt_in() -> None:
    with pytest.raises(ValueError) as exc:
        _settings(openai_compatible_base_url="http://10.0.0.5:8000/v1")
    assert "openai_compatible_insecure_http_not_allowed" in str(exc.value)

    # Opt-in makes it valid; loopback never needs the opt-in.
    _settings(
        openai_compatible_base_url="http://10.0.0.5:8000/v1",
        openai_compatible_allow_insecure_http=True,
    )
    _settings(openai_compatible_base_url="http://127.0.0.1:8000/v1")


def test_trailing_slash_is_stripped() -> None:
    settings = _settings(openai_compatible_base_url=BASE_URL + "/")
    assert settings.openai_compatible_base_url == BASE_URL


def test_context_budget_validation() -> None:
    with pytest.raises(ValueError) as exc:
        _settings(
            max_prompt_tokens=7000,
            max_completion_tokens=1500,
            openai_compatible_context_window_tokens=8192,
        )
    assert "openai_compatible_context_budget_exceeded" in str(exc.value)


# -- HTTP request shape -------------------------------------------------------


def test_request_uses_bearer_auth_model_endpoint_and_thinking() -> None:
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("Authorization")
        captured["content_type"] = request.headers.get("Content-Type")
        captured["raw"] = request.content  # bytes
        payload = json.loads(request.content.decode("utf-8"))
        captured["payload"] = payload
        return _chat_response([_submit_call()])

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        _provider(client).invoke(_request())

    assert captured["url"] == f"{BASE_URL}/chat/completions"
    assert captured["auth"] == f"Bearer {SECRET_API_KEY}"
    assert "charset=utf-8" in captured["content_type"].lower()
    # Body is valid UTF-8 carrying Turkish characters from the system prompt.
    decoded = captured["raw"].decode("utf-8")
    assert "Şüpheli" in decoded
    payload = captured["payload"]
    assert payload["model"] == MODEL
    assert payload["stream"] is False
    assert payload["temperature"] == 0
    assert payload["max_tokens"] == 1500
    assert payload["chat_template_kwargs"] == {"enable_thinking": False}
    # No Ollama-native fields leak into the OpenAI-compatible request.
    for forbidden in ("keep_alive", "options", "num_predict", "format"):
        assert forbidden not in payload


def test_enable_thinking_true_is_honored() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert payload["chat_template_kwargs"] == {"enable_thinking": True}
        return _chat_response([_submit_call()])

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        _provider(client, openai_compatible_enable_thinking=True).invoke(_request())


def test_invoke_returns_structured_submission_and_token_usage() -> None:
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _r: _chat_response([_submit_call()], prompt=120, completion=32)
        )
    ) as client:
        response = _provider(client).invoke(_request())

    assert response.submission is not None
    assert response.submission.triage_verdict.value == "suspicious_activity"
    assert response.prompt_tokens == 120
    assert response.completion_tokens == 32
    assert response.iteration_count == 1


def test_search_then_submit_uses_openai_tool_result_fields() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payload = json.loads(request.content)
        if calls == 1:
            return _chat_response(
                [
                    {
                        "id": "call-search",
                        "function": {
                            "name": "search_logs",
                            "arguments": json.dumps({"query": "SYN"}),
                        },
                    }
                ]
            )
        last = payload["messages"][-1]
        assert last["role"] == "tool"
        assert last["tool_call_id"] == "call-search"
        return _chat_response([_submit_call("false_positive")])

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        response = _provider(client).invoke(_request(with_event=True))

    assert calls == 2
    assert response.submission.triage_verdict.value == "false_positive"
    assert response.search_call_count == 1


def test_mixed_tool_calls_are_rejected() -> None:
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _r: _chat_response(
                [
                    {
                        "id": "s",
                        "function": {
                            "name": "search_logs",
                            "arguments": json.dumps({"query": "SYN"}),
                        },
                    },
                    _submit_call(),
                ]
            )
        )
    ) as client:
        with pytest.raises(TriageProviderError) as exc:
            _provider(client).invoke(_request())
    assert exc.value.review_reason == ReviewReason.MIXED_TOOL_CALLS


# -- brief enrichment ---------------------------------------------------------


def _brief_request() -> BriefEnrichmentProviderRequest:
    return BriefEnrichmentProviderRequest(
        system_prompt="Enrich the bounded brief. Türkçe açıklama üret.",
        payload=json.dumps({"items": []}),
        item_ids=["INC-1"],
        deadline=time.monotonic() + 10,
    )


def _content_response(content, *, prompt=40, completion=12) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "choices": [{"message": {"role": "assistant", "content": content}}],
            "usage": {"prompt_tokens": prompt, "completion_tokens": completion},
        },
    )


def test_brief_enrichment_uses_message_content_and_maps_usage() -> None:
    payload_obj = {"items": [{"id": "INC-1", "explanation": "text"}]}

    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _r: _content_response(json.dumps(payload_obj), prompt=40, completion=12)
        )
    ) as client:
        response = _provider(client).invoke_brief_enrichment(_brief_request())

    assert response.raw_payload == payload_obj
    assert response.prompt_tokens == 40
    assert response.completion_tokens == 12


def test_brief_enrichment_tolerates_single_fenced_block() -> None:
    fenced = "```json\n{\"items\": []}\n```"
    with httpx.Client(
        transport=httpx.MockTransport(lambda _r: _content_response(fenced))
    ) as client:
        response = _provider(client).invoke_brief_enrichment(_brief_request())
    assert response.raw_payload == {"items": []}


def test_brief_enrichment_ignores_reasoning_content() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": json.dumps({"items": []}),
                            "reasoning_content": "chain of thought that must be ignored",
                        }
                    }
                ],
                "usage": {"prompt_tokens": 5, "completion_tokens": 3},
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        response = _provider(client).invoke_brief_enrichment(_brief_request())

    assert response.raw_payload == {"items": []}
    # Nothing from reasoning_content is surfaced on the response object.
    assert "chain of thought" not in repr(response.raw_payload)


def test_brief_enrichment_rejects_empty_content() -> None:
    with httpx.Client(
        transport=httpx.MockTransport(lambda _r: _content_response("   "))
    ) as client:
        with pytest.raises(ProviderInvalidResponseError):
            _provider(client).invoke_brief_enrichment(_brief_request())


def test_brief_enrichment_rejects_invalid_json_content() -> None:
    with httpx.Client(
        transport=httpx.MockTransport(lambda _r: _content_response("not json at all"))
    ) as client:
        with pytest.raises(ProviderInvalidResponseError):
            _provider(client).invoke_brief_enrichment(_brief_request())


def test_missing_choices_is_rejected() -> None:
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _r: httpx.Response(200, json={"usage": {}})
        )
    ) as client:
        with pytest.raises(ProviderInvalidResponseError):
            _provider(client).invoke_brief_enrichment(_brief_request())


# -- error mapping ------------------------------------------------------------


@pytest.mark.parametrize("status", [401, 403])
def test_authentication_error_mapping(status) -> None:
    with httpx.Client(
        transport=httpx.MockTransport(lambda _r: httpx.Response(status))
    ) as client:
        with pytest.raises(ProviderAuthenticationError):
            _provider(client).invoke_brief_enrichment(_brief_request())


def test_rate_limit_mapping() -> None:
    with httpx.Client(
        transport=httpx.MockTransport(lambda _r: httpx.Response(429))
    ) as client:
        with pytest.raises(ProviderRateLimitError):
            _provider(client).invoke_brief_enrichment(_brief_request())


@pytest.mark.parametrize("status", [408, 504])
def test_timeout_status_mapping(status) -> None:
    with httpx.Client(
        transport=httpx.MockTransport(lambda _r: httpx.Response(status))
    ) as client:
        with pytest.raises(ProviderTimeoutError):
            _provider(client).invoke_brief_enrichment(_brief_request())


def test_transport_timeout_mapping() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ProviderTimeoutError):
            _provider(client).invoke_brief_enrichment(_brief_request())


def test_connection_failure_mapping() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ProviderUnavailableError):
            _provider(client).invoke_brief_enrichment(_brief_request())


def test_server_error_mapping() -> None:
    with httpx.Client(
        transport=httpx.MockTransport(lambda _r: httpx.Response(503))
    ) as client:
        with pytest.raises(ProviderUnavailableError):
            _provider(client).invoke_brief_enrichment(_brief_request())


def test_other_4xx_mapping() -> None:
    with httpx.Client(
        transport=httpx.MockTransport(lambda _r: httpx.Response(400))
    ) as client:
        with pytest.raises(ProviderInvalidResponseError):
            _provider(client).invoke_brief_enrichment(_brief_request())


def test_malformed_json_body_is_rejected() -> None:
    with httpx.Client(
        transport=httpx.MockTransport(
            lambda _r: httpx.Response(200, content=b"<html>not json</html>")
        )
    ) as client:
        with pytest.raises(ProviderInvalidResponseError):
            _provider(client).invoke_brief_enrichment(_brief_request())


# -- retry and circuit breaker integration ------------------------------------


def test_retry_then_success_and_circuit_breaker_are_active() -> None:
    from agent.triage.circuit_breaker import CircuitBreaker

    attempts = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(503)
        return _content_response(json.dumps({"items": []}))

    breaker = CircuitBreaker()
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        provider = OpenAICompatibleTriageProvider(
            client=client,
            circuit_breaker=breaker,
            settings=_settings(llm_max_retries=2),
        )
        response = provider.invoke_brief_enrichment(_brief_request())

    assert attempts == 2
    assert response.retry_count == 1
    assert breaker.failures == 0  # success reset the breaker


def test_circuit_breaker_opens_after_repeated_failures() -> None:
    from agent.triage.circuit_breaker import CircuitBreaker

    breaker = CircuitBreaker(failure_threshold=1, reset_seconds=60)
    with httpx.Client(
        transport=httpx.MockTransport(lambda _r: httpx.Response(503))
    ) as client:
        provider = OpenAICompatibleTriageProvider(
            client=client, circuit_breaker=breaker, settings=_settings()
        )
        with pytest.raises(ProviderUnavailableError):
            provider.invoke_brief_enrichment(_brief_request())
        # Breaker is now open; the next call short-circuits.
        with pytest.raises(TriageProviderError) as exc:
            provider.invoke_brief_enrichment(_brief_request())
    assert exc.value.review_reason == ReviewReason.CIRCUIT_BREAKER_OPEN


# -- secret hygiene -----------------------------------------------------------


def test_api_key_never_appears_in_exceptions_or_logs(caplog) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        # A body that echoes the key back must never be surfaced.
        return httpx.Response(400, json={"error": SECRET_API_KEY})

    with caplog.at_level(logging.DEBUG):
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(TriageProviderError) as exc:
                _provider(client).invoke_brief_enrichment(_brief_request())

    assert SECRET_API_KEY not in str(exc.value)
    assert SECRET_API_KEY not in caplog.text


def test_construction_error_does_not_leak_key() -> None:
    # A disabled LLM raises before any request; the message must stay generic.
    with pytest.raises(ProviderConfigurationError) as exc:
        OpenAICompatibleTriageProvider(
            settings=_settings(llm_enabled=False)
        )
    assert SECRET_API_KEY not in str(exc.value)


# -- deterministic detection makes zero provider calls ------------------------


def test_detection_makes_zero_provider_calls() -> None:
    def boom(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("detection must not call the provider")

    events = [
        CanonicalLogEvent(
            event_id=f"e{i}",
            timestamp=datetime(2026, 7, 10, 9, 54, i % 60),
            src_ip="192.0.2.10",
            dst_ip=f"10.0.0.{i}",
            dst_port=22,
            action="block",
            parser_name="pf_firewall",
            parse_status="parsed",
        )
        for i in range(1, 12)
    ]

    with httpx.Client(transport=httpx.MockTransport(boom)) as client:
        # Constructing the provider must not issue any request either.
        _provider(client)
        result = DetectionEngine().analyze(events)

    # Deterministic detection produced a result without touching the transport.
    assert result is not None
