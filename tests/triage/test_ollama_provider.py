import json
import time

import httpx
import pytest

import agent.nodes as nodes
from agent.config import Settings
from agent.triage.enums import ReviewReason
from agent.triage.exceptions import ProviderConfigurationError, TriageProviderError
from agent.triage.models import SafeEventView, TriageInput
from agent.triage.ollama_provider import OllamaTriageProvider
from agent.triage.provider import TriageProviderRequest


def _settings(**overrides):
    values = {
        "llm_enabled": True,
        "llm_provider": "ollama",
        "llm_model": "llama3.1:latest",
        "ollama_base_url": "http://127.0.0.1:11434",
        "llm_max_retries": 0,
        "max_agent_iterations": 3,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


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
        system_prompt="Use the tools and remain evidence-bound.",
        context={"triage_input": triage_input},
        deadline=time.monotonic() + 10,
    )


def _submit_call(verdict: str = "suspicious_activity") -> dict:
    return {
        "function": {
            "name": "submit_triage_result",
            "arguments": {
                "triage_verdict": verdict,
                "incident_type": "horizontal_scan",
                "severity": "high" if verdict != "false_positive" else "none",
                "confidence_score": 0.88,
                "summary": "Repeated blocked SYN probes were detected.",
                "selected_evidence_ids": [],
                "claims": [],
            },
        }
    }


def test_ollama_provider_returns_valid_structured_submission() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert payload["model"] == "llama3.1:latest"
        assert "192.0.2.10" not in payload["messages"][1]["content"]
        assert {tool["function"]["name"] for tool in payload["tools"]} == {
            "search_logs",
            "submit_triage_result",
        }
        return httpx.Response(
            200,
            json={
                "message": {"role": "assistant", "tool_calls": [_submit_call()]},
                "prompt_eval_count": 120,
                "eval_count": 32,
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        response = OllamaTriageProvider(
            client=client,
            settings=_settings(),
        ).invoke(_request())

    assert response.submission is not None
    assert response.submission.triage_verdict.value == "suspicious_activity"
    assert response.prompt_tokens == 120
    assert response.completion_tokens == 32
    assert response.iteration_count == 1


def test_ollama_provider_searches_only_scoped_events_then_submits() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        payload = json.loads(request.content)
        if calls == 1:
            return httpx.Response(
                200,
                json={
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "search_logs",
                                    "arguments": {"query": "SYN"},
                                }
                            }
                        ],
                    }
                },
            )
        assert payload["messages"][-1]["role"] == "tool"
        assert payload["messages"][-1]["tool_name"] == "search_logs"
        return httpx.Response(
            200,
            json={
                "message": {
                    "role": "assistant",
                    "tool_calls": [_submit_call("false_positive")],
                }
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        response = OllamaTriageProvider(
            client=client,
            settings=_settings(),
        ).invoke(_request(with_event=True))

    assert calls == 2
    assert response.submission is not None
    assert response.submission.triage_verdict.value == "false_positive"
    assert response.search_call_count == 1


def test_ollama_provider_rejects_mixed_tool_calls() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "function": {
                                "name": "search_logs",
                                "arguments": {"query": "SYN"},
                            }
                        },
                        _submit_call(),
                    ],
                }
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        provider = OllamaTriageProvider(client=client, settings=_settings())
        with pytest.raises(TriageProviderError) as exc:
            provider.invoke(_request())

    assert exc.value.review_reason == ReviewReason.MIXED_TOOL_CALLS


def test_ollama_provider_rejects_non_local_base_url() -> None:
    with pytest.raises(ProviderConfigurationError):
        OllamaTriageProvider(
            settings=_settings(ollama_base_url="https://example.com"),
        )


def test_triage_runner_selects_ollama_provider(monkeypatch) -> None:
    local_provider = object()

    monkeypatch.setattr(nodes, "_circuit_breaker", None)
    monkeypatch.setattr(nodes, "get_settings", lambda: _settings())
    monkeypatch.setattr(
        nodes,
        "OllamaTriageProvider",
        lambda circuit_breaker: local_provider,
    )
    monkeypatch.setattr(
        nodes,
        "GroqTriageProvider",
        lambda circuit_breaker: pytest.fail("Groq provider must not be selected"),
    )

    runner = nodes.get_triage_runner()

    assert runner.provider is local_provider
