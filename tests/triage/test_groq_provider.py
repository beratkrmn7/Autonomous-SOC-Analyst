# mypy: ignore-errors
import pytest
from langchain_core.messages import AIMessage
from agent.triage.groq_provider import GroqTriageProvider
from agent.triage.models import TriageInput, SafeEventView
from agent.triage.provider import TriageProviderRequest
from agent.triage.exceptions import (
    ProviderInvalidResponseError,
    TriageProviderError,
    ProviderConfigurationError
)
from agent.triage.enums import ReviewReason
from agent.config import Settings

def test_groq_provider_valid_submission(fake_llm, triage_test_settings):
    # Setup FakeLLM
    actions = [
        AIMessage(
            content="",
            tool_calls=[{
                "name": "submit_triage_result",
                "args": {
                    "triage_verdict": "confirmed_incident",
                    "incident_type": "test",
                    "severity": "high",
                    "confidence_score": 0.9,
                    "summary": "Verified",
                    "selected_evidence_ids": ["ev_1"],
                    "claims": []
                },
                "id": "call_1"
            }],
            response_metadata={"token_usage": {"prompt_tokens": 10, "completion_tokens": 10}}
        )
    ]
    llm = fake_llm(actions)
    provider = GroqTriageProvider(llm=llm, settings=triage_test_settings)
    
    request = TriageProviderRequest(
        incident_id="INC-1",
        triage_input=TriageInput(
            incident_id="INC-1",
            incident_type="test",
            incident_family="test",
            title="test",
            deterministic_severity="high",
            deterministic_confidence=1.0,
            first_seen="2024",
            last_seen="2024",
            primary_entity="ip",
        ),
        system_prompt="Test",
        context={"triage_input": TriageInput(
            incident_id="INC-1",
            incident_type="test",
            incident_family="test",
            title="test",
            deterministic_severity="high",
            deterministic_confidence=1.0,
            first_seen="2024",
            last_seen="2024",
            primary_entity="ip",
        )}
    )
    
    response = provider.invoke(request)
    assert response.submission is not None
    assert response.submission.severity.value == "high"
    assert response.prompt_tokens == 10

def test_groq_provider_search_then_submit(fake_llm, triage_test_settings):
    actions = [
        AIMessage(
            content="",
            tool_calls=[{
                "name": "search_logs",
                "args": {"query": "error"},
                "id": "call_1"
            }]
        ),
        AIMessage(
            content="",
            tool_calls=[{
                "name": "submit_triage_result",
                "args": {
                    "triage_verdict": "false_positive",
                    "incident_type": "test",
                    "severity": "none",
                    "confidence_score": 0.9,
                    "summary": "FP",
                    "selected_evidence_ids": [],
                    "claims": []
                },
                "id": "call_2"
            }]
        )
    ]
    llm = fake_llm(actions)
    provider = GroqTriageProvider(llm=llm, settings=triage_test_settings)
    
    # Needs valid events for search
    ti = TriageInput(
        incident_id="INC-1", incident_type="test", incident_family="test", title="test",
        deterministic_severity="high", deterministic_confidence=1.0, first_seen="2024",
        last_seen="2024", primary_entity="ip",
        limited_context_events=[
            SafeEventView(event_id="EVT-1", timestamp="2024", parser_name="test", source_name="test", sanitized_message_excerpt="error")
        ]
    )
    request = TriageProviderRequest(incident_id="INC-1", triage_input=ti, system_prompt="", context={"triage_input": ti})
    
    response = provider.invoke(request)
    assert response.submission.triage_verdict.value == "false_positive"

def test_groq_provider_max_iterations(fake_llm, triage_test_settings):
    # Return plain text forever
    actions = [AIMessage(content="Thinking...")] * 10
    llm = fake_llm(actions)
    provider = GroqTriageProvider(llm=llm, settings=triage_test_settings)
    provider.settings.max_agent_iterations = 3
    
    ti = TriageInput(
        incident_id="INC-1", incident_type="test", incident_family="test", title="test",
        deterministic_severity="high", deterministic_confidence=1.0, first_seen="2024",
        last_seen="2024", primary_entity="ip"
    )
    request = TriageProviderRequest(incident_id="INC-1", triage_input=ti, system_prompt="", context={"triage_input": ti})
    
    with pytest.raises(ProviderInvalidResponseError):
        provider.invoke(request)

def test_groq_provider_init_llm_disabled():
    # If llm is disabled and we don't provide a mock LLM, it should raise
    settings = Settings(llm_enabled=False)
    with pytest.raises(ProviderConfigurationError) as exc:
        GroqTriageProvider(settings=settings)
    assert "LLM is disabled" in str(exc.value)

def test_groq_provider_init_explicit_settings_fake_llm(fake_llm, triage_test_settings):
    # If we pass explicit settings and a fake LLM, it should initialize successfully
    llm = fake_llm([])
    provider = GroqTriageProvider(llm=llm, settings=triage_test_settings)
    assert provider.settings.llm_enabled is True
    assert provider.llm is llm

def test_groq_provider_mixed_tools(fake_llm, triage_test_settings):
    actions = [
        AIMessage(
            content="",
            tool_calls=[
                {"name": "search_logs", "args": {"query": "error"}, "id": "call_1"},
                {"name": "submit_triage_result", "args": {"triage_verdict": "false_positive", "incident_type": "test", "severity": "none", "confidence_score": 0.9, "summary": "FP", "selected_evidence_ids": [], "claims": []}, "id": "call_2"}
            ]
        )
    ]
    llm = fake_llm(actions)
    provider = GroqTriageProvider(llm=llm, settings=triage_test_settings)
    
    ti = TriageInput(
        incident_id="INC-1", incident_type="test", incident_family="test", title="test",
        deterministic_severity="high", deterministic_confidence=1.0, first_seen="2024",
        last_seen="2024", primary_entity="ip"
    )
    request = TriageProviderRequest(incident_id="INC-1", triage_input=ti, system_prompt="", context={"triage_input": ti})
    
    with pytest.raises(TriageProviderError) as exc:
        provider.invoke(request)
    assert exc.value.review_reason == ReviewReason.MIXED_TOOL_CALLS

def test_groq_provider_invalid_tool(fake_llm, triage_test_settings):
    actions = [
        AIMessage(
            content="",
            tool_calls=[
                {"name": "made_up_tool", "args": {}, "id": "call_1"}
            ]
        )
    ]
    llm = fake_llm(actions)
    provider = GroqTriageProvider(llm=llm, settings=triage_test_settings)
    ti = TriageInput(
        incident_id="INC-1", incident_type="test", incident_family="test", title="test",
        deterministic_severity="high", deterministic_confidence=1.0, first_seen="2024",
        last_seen="2024", primary_entity="ip"
    )
    request = TriageProviderRequest(incident_id="INC-1", triage_input=ti, system_prompt="", context={"triage_input": ti})
    
    with pytest.raises(TriageProviderError) as exc:
        provider.invoke(request)
    assert exc.value.review_reason == ReviewReason.INVALID_TOOL_CALL

def test_groq_provider_search_loop_limit(fake_llm, triage_test_settings):
    actions = [
        AIMessage(content="", tool_calls=[{"name": "search_logs", "args": {"query": "error"}, "id": "call_1"}])
    ] * 5
    llm = fake_llm(actions)
    provider = GroqTriageProvider(llm=llm, settings=triage_test_settings)
    provider.settings.max_search_calls = 2 # Exceeding this will throw ProviderMaxSearchCallsError
    
    ti = TriageInput(
        incident_id="INC-1", incident_type="test", incident_family="test", title="test",
        deterministic_severity="high", deterministic_confidence=1.0, first_seen="2024",
        last_seen="2024", primary_entity="ip"
    )
    request = TriageProviderRequest(incident_id="INC-1", triage_input=ti, system_prompt="", context={"triage_input": ti})
    
    with pytest.raises(TriageProviderError) as exc:
        provider.invoke(request)
    assert exc.value.review_reason == ReviewReason.MAXIMUM_SEARCH_CALLS_REACHED
