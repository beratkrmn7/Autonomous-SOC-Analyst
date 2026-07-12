import pytest
import datetime
from unittest.mock import patch, MagicMock
import time

from agent.models import IncidentState
from agent.detection.models import IncidentBundle as DetectionIncidentBundle
from agent.triage.models import TriageIncidentContext
from agent.schema import CanonicalLogEvent
from agent.triage.models import TriageSubmission, TriageClaim, EvidenceValidationResult, TriageInput, EvidenceCandidate
from agent.triage.enums import ClaimType, RejectionReason, TriageVerdict, TriageSeverity, ReviewReason
from agent.triage.validation import validate_evidence
from agent.triage.claims import validate_claims
from agent.triage.groq_provider import GroqTriageProvider
from agent.triage.runner import TriageRunner
from agent.triage.cache import InMemoryTriageCache
from agent.config import get_settings
from agent.triage.exceptions import ProviderAuthenticationError
from fastapi.testclient import TestClient
from server import app as fast_app
from agent.nodes import triage_node, evidence_validation_node, action_recommendation_node

def _make_dummy_event(eid="E01"):
    return CanonicalLogEvent(
        event_id=eid,
        observed_at=datetime.datetime.now(datetime.timezone.utc),
        parser_name="test",
        source_name="test",
        raw_message="dummy log",
        parse_status="success",
        original_log={"test_field": "test_value"}
    )

def test_actual_incidentbundle_round_trip():
    bundle = DetectionIncidentBundle(
        incident_id="INC-001",
        incident_type="test",
        incident_family="test",
        title="test",
        severity="low",
        confidence=1.0,
        primary_entity="unknown",
        target_entities=[],
        signal_ids=[],
        evidence=[],
        metrics={},
        mitre_techniques=[],
        merge_key="mock",
        event_ids=["E01"],
        context_event_ids=["CTX01"],
        first_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        last_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    )
    
    context = TriageIncidentContext(
        incident=bundle,
        events=[_make_dummy_event("E01")],
        context_events=[_make_dummy_event("CTX01")]
    )
    
    state = IncidentState(
        incident_id="INC-001",
        incident=context.model_dump(mode="json"),
        canonical_events=[],
        messages=[],
        iteration_count=0,
        mitre_techniques=[],
        candidate_evidence=[],
        detected_signals=[],
        search_history=[],
        tool_results=[],
        errors=[]
    )
    
    # Validate that the context seamlessly reconstructs from state["incident"] without loss
    deserialized = TriageIncidentContext.model_validate(state["incident"])
    
    # Assert exact field preservation
    assert deserialized.incident.incident_type == "test"
    assert deserialized.incident.incident_family == "test"
    assert deserialized.incident.severity == "low"
    assert deserialized.incident.confidence == 1.0
    assert deserialized.incident.primary_entity == "unknown"
    assert deserialized.incident.target_entities == []
    assert deserialized.incident.signal_ids == []
    assert deserialized.incident.event_ids == ["E01"]
    assert deserialized.incident.context_event_ids == ["CTX01"]
    assert deserialized.incident.evidence == []
    assert deserialized.incident.metrics == {}
    assert deserialized.incident.mitre_techniques == []
    assert deserialized.incident.merge_key == "mock"
    assert len(deserialized.events) == 1
    assert deserialized.events[0].event_id == "E01"
    assert len(deserialized.context_events) == 1
    assert deserialized.context_events[0].event_id == "CTX01"
    
    # Verify the actual node run does not fail with validation errors
    res = triage_node(state)
    assert res.get("review_reason") != ReviewReason.INVALID_LLM_OUTPUT.value

def test_true_interrupting_provider_timeout():
    timeout_passed = [None]
    
    class FakeChatGroq:
        def __init__(self, *args, **kwargs):
            timeout_passed[0] = kwargs.get("request_timeout")
            
        def bind_tools(self, tools):
            return self
            
        def invoke(self, *args, **kwargs):
            t = timeout_passed[0]
            if t is not None:
                time.sleep(t)
            import groq
            raise groq.APITimeoutError(MagicMock())
            
    with patch('agent.triage.groq_provider.get_settings') as mock_settings, patch('agent.triage.groq_provider.ChatGroq', FakeChatGroq):
        m = MagicMock()
        m.llm_enabled = True
        m.groq_api_key = "mock"
        m.triage_timeout_seconds = 0.5
        m.llm_model = "test"
        m.max_agent_iterations = 5
        m.llm_max_retries = 0
        m.llm_retry_base_seconds = 0.01
        m.llm_retry_max_seconds = 0.01
        mock_settings.return_value = m
        
        provider = GroqTriageProvider()
        provider._custom_llm_injected = False
        
        runner = TriageRunner(provider=provider, cache=InMemoryTriageCache())
        runner.settings.triage_timeout_seconds = 0.5
        
        context = TriageIncidentContext(
            incident=DetectionIncidentBundle(
                incident_id="INC-001", incident_type="test", incident_family="test", title="test", severity="low",
                confidence=1.0, primary_entity="unknown", target_entities=[], signal_ids=[], evidence=[], metrics={},
                mitre_techniques=[], merge_key="mock", event_ids=[], context_event_ids=[],
                first_seen=datetime.datetime.now(datetime.timezone.utc), last_seen=datetime.datetime.now(datetime.timezone.utc)
            ),
            events=[], context_events=[]
        )
        
        start = time.monotonic()
        result = runner.run({}, context)
        elapsed = time.monotonic() - start
        
        assert timeout_passed[0] is not None
        assert 0.4 < timeout_passed[0] < 0.6
        assert 0.4 < elapsed < 1.0 # Tolerant but definitely not 5 seconds
        assert result.review_reason == ReviewReason.PROVIDER_TIMEOUT
        assert result.submission is not None
        assert result.submission.triage_verdict == TriageVerdict.NEEDS_REVIEW
        assert result.submission.severity == TriageSeverity.NONE
        assert result.submission.confidence_score == 0.0

def test_auth_failure_mapping():
    provider = GroqTriageProvider(llm=MagicMock())
    
    with patch.object(provider, '_invoke_with_circuit_breaker', side_effect=ProviderAuthenticationError("auth failed")):
        with pytest.raises(ProviderAuthenticationError):
            provider.invoke(MagicMock(context={"triage_input": MagicMock()}, deadline=None, triage_input=MagicMock(), system_prompt=""))

def test_rate_limit_then_success():
    calls = [0]
    
    class FakeChatGroq:
        def __init__(self, *args, **kwargs):
            pass
            
        def bind_tools(self, tools):
            return self
            
        def invoke(self, *args, **kwargs):
            calls[0] += 1
            if calls[0] == 1:
                import groq
                raise groq.RateLimitError("rate limited", response=MagicMock(), body=None)
            return MagicMock(
                tool_calls=[{
                    "name": "submit_triage_result",
                    "args": {
                        "triage_verdict": "false_positive",
                        "incident_type": "other",
                        "severity": "none",
                        "confidence_score": 1.0,
                        "summary": "test",
                        "selected_evidence_ids": [],
                        "claims": []
                    },
                    "id": "call_1"
                }],
                response_metadata={"token_usage": {"prompt_tokens": 10, "completion_tokens": 10}}
            )
            
    with patch('agent.triage.groq_provider.get_settings') as mock_settings, patch('agent.triage.groq_provider.ChatGroq', FakeChatGroq):
        m = MagicMock()
        m.llm_enabled = True
        m.groq_api_key = "mock"
        m.llm_retry_base_seconds = 0.01
        m.llm_retry_max_seconds = 0.01
        m.llm_max_retries = 3
        m.llm_model = "test"
        m.max_agent_iterations = 5
        mock_settings.return_value = m
        
        provider = GroqTriageProvider()
        provider._custom_llm_injected = False
        
        # Decrease delays to make test run fast
        provider.settings.llm_retry_base_seconds = 0.01
        provider.settings.llm_retry_max_seconds = 0.01
        
        runner = TriageRunner(provider=provider, cache=InMemoryTriageCache())
        
        context = TriageIncidentContext(
            incident=DetectionIncidentBundle(
                incident_id="INC-RATE-LIMIT", incident_type="test", incident_family="test", title="test", severity="low",
                confidence=1.0, primary_entity="unknown", target_entities=[], signal_ids=[], evidence=[], metrics={},
                mitre_techniques=[], merge_key="mock", event_ids=[], context_event_ids=[],
                first_seen=datetime.datetime.now(datetime.timezone.utc), last_seen=datetime.datetime.now(datetime.timezone.utc)
            ),
            events=[], context_events=[]
        )
        
        result = runner.run({}, context)
        
        assert calls[0] == 2
        assert provider.circuit_breaker.failures == 0 # Reset after success
        assert result.metrics.retry_count == 1
        assert result.submission is not None
        assert result.submission.triage_verdict == TriageVerdict.FALSE_POSITIVE

def test_process_stable_content_hash():
    bundle = DetectionIncidentBundle(
        incident_id="INC-001",
        incident_type="test",
        incident_family="test",
        title="test",
        severity="low",
        confidence=1.0,
        primary_entity="unknown",
        target_entities=[],
        signal_ids=[],
        evidence=[],
        metrics={},
        mitre_techniques=[],
        merge_key="mock",
        event_ids=["E01"],
        context_event_ids=[],
        first_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        last_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    )
    context = TriageIncidentContext(incident=bundle, events=[_make_dummy_event("E01")])
    runner = TriageRunner(provider=MagicMock(), cache=InMemoryTriageCache())
    state = {}
    with patch.object(runner.provider, 'invoke', return_value=MagicMock(submission=None)):
        runner.run(state, context)
        key1 = state["cache_key"]
        
    runner2 = TriageRunner(provider=MagicMock(), cache=InMemoryTriageCache())
    state2 = {}
    with patch.object(runner2.provider, 'invoke', return_value=MagicMock(submission=None)):
        runner2.run(state2, context)
        key2 = state2["cache_key"]
        
    assert key1 == key2

def test_unknown_original_field_rejection():
    trusted = [_make_dummy_event("E01")] # has {"test_field": "test_value"}
    
    sub = TriageSubmission(
        triage_verdict=TriageVerdict.CONFIRMED_INCIDENT,
        incident_type="other",
        severity=TriageSeverity.HIGH,
        confidence_score=0.9,
        summary="test",
        selected_evidence_ids=["ev1"]
    )
    
    t_input = TriageInput(
        incident_id="test", incident_type="test", incident_family="test", title="test",
        deterministic_severity="low", deterministic_confidence=0, first_seen="", last_seen="", primary_entity="test",
        candidate_evidence=[
            EvidenceCandidate(
                evidence_id="ev1", event_id="E01", quote="dummy log", reason="test", source="test",
                canonical_fields={"non_existent_field": "value"}, vendor_original_fields={}
            )
        ]
    )
    
    bundle = DetectionIncidentBundle(
        incident_id="INC-001",
        incident_type="test",
        incident_family="test",
        title="test",
        severity="low",
        confidence=1.0,
        primary_entity="unknown",
        target_entities=[],
        signal_ids=[],
        evidence=[],
        metrics={},
        mitre_techniques=[],
        merge_key="mock",
        event_ids=["E01"],
        context_event_ids=[],
        first_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        last_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    )
    context = TriageIncidentContext(incident=bundle, events=trusted)
    res = validate_evidence(sub, t_input, context)
    assert len(res) == 1
    assert res[0].status == "rejected"
    
def test_claim_specific_rejection():
    claim = TriageClaim(
        claim_id="c1", claim_type=ClaimType.BRUTE_FORCE_SUCCESS, statement="test",
        supporting_evidence_ids=["ev1"], supporting_event_ids=["E01"]
    )
    valid_ev = [EvidenceValidationResult(evidence_id="ev1", event_id="E01", status="validated")]
    accepted, rejected = validate_claims([claim], valid_ev)
    assert len(accepted) == 0
    assert len(rejected) == 1
    assert rejected[0]["reason"] == RejectionReason.UNSUPPORTED_CLAIM_TYPE.value

def test_supporting_event_id_validation():
    claim = TriageClaim(
        claim_id="c1", claim_type=ClaimType.OTHER, statement="test",
        supporting_evidence_ids=["ev1"], supporting_event_ids=["E02"] # invalid event id
    )
    valid_ev = [EvidenceValidationResult(evidence_id="ev1", event_id="E01", status="validated")]
    accepted, rejected = validate_claims([claim], valid_ev)
    assert len(accepted) == 0
    assert len(rejected) == 1
    assert rejected[0]["reason"] == RejectionReason.EVIDENCE_REJECTED.value

def test_prompt_budget_exceeded():
    bundle = DetectionIncidentBundle(
        incident_id="INC-001",
        incident_type="test",
        incident_family="test",
        title="test",
        severity="low",
        confidence=1.0,
        primary_entity="unknown",
        target_entities=[],
        signal_ids=[],
        evidence=[],
        metrics={},
        mitre_techniques=[],
        merge_key="mock",
        event_ids=["E01"],
        context_event_ids=[],
        first_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        last_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    )
    context = TriageIncidentContext(incident=bundle, events=[_make_dummy_event("E01")])
    settings = get_settings()
    settings.max_prompt_tokens = -1 # force fail
    runner = TriageRunner(provider=MagicMock(), cache=InMemoryTriageCache())
    state = {}
    res = runner.run(state, context)
    assert res.review_reason == ReviewReason.PROMPT_BUDGET_EXCEEDED
    settings.max_prompt_tokens = 30000

def test_metrics_counters():
    settings = get_settings()
    settings.max_prompt_tokens = 30000 # ensure it's reset
    
    provider_mock = MagicMock()
    from agent.triage.provider import TriageProviderResponse
    provider_mock.invoke.return_value = TriageProviderResponse(
        submission=MagicMock(),
        prompt_tokens=100,
        completion_tokens=50,
        iteration_count=3,
        search_call_count=2,
        tool_call_count=4
    )
    
    runner = TriageRunner(provider=provider_mock, cache=None)
    bundle = DetectionIncidentBundle(
        incident_id="INC", incident_type="test", incident_family="test", title="test",
        severity="low", confidence=1.0, primary_entity="unknown", target_entities=[],
        signal_ids=[], evidence=[], metrics={}, mitre_techniques=[], merge_key="mock",
        event_ids=[], context_event_ids=[],
        first_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        last_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    )
    context = TriageIncidentContext(incident=bundle, events=[])
    res = runner.run({}, context)
    assert res.metrics.iteration_count == 3
    assert res.metrics.search_call_count == 2
    assert res.metrics.tool_call_count == 4
    assert res.metrics.provider_prompt_tokens == 100
    assert res.metrics.total_tokens == 150

@patch('agent.nodes.get_triage_runner')
def test_ingest_detect_endpoints_zero_calls(mock_get_triage_runner):
    client = TestClient(fast_app)
    
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".jsonl") as tf:
        tf.write('{"src_ip": "10.0.0.1", "action": "allow"}\n')
        tf_name = tf.name
        
    with open(tf_name, "rb") as f:
        res = client.post("/ingest/file", files={"file": f})
    assert res.status_code == 200
    
    with open(tf_name, "rb") as f:
        res = client.post("/detect/file", files={"file": f})
    assert res.status_code == 200
    mock_get_triage_runner.assert_not_called()

def test_graph_integration():
    bundle = DetectionIncidentBundle(
        incident_id="INC", incident_type="bruteforce_success", incident_family="bruteforce_success", title="t",
        severity="high", confidence=0.9, primary_entity="unknown", target_entities=[],
        signal_ids=[], evidence=[], metrics={}, mitre_techniques=[], merge_key="mock",
        event_ids=["E01"], context_event_ids=[],
        first_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        last_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    )
    context = TriageIncidentContext(incident=bundle, events=[_make_dummy_event("E01")])
    
    sub = TriageSubmission(
        triage_verdict=TriageVerdict.CONFIRMED_INCIDENT,
        incident_type="bruteforce_success",
        severity=TriageSeverity.HIGH,
        confidence_score=0.9,
        summary="test",
        selected_evidence_ids=["ev1"]
    )
    
    state = {
        "incident_id": "INC",
        "incident": context.model_dump(mode="json"),
        "triage_submission": sub.model_dump(),
        "safe_triage_input": TriageInput(
            incident_id="INC", incident_type="brute", incident_family="brute", title="t",
            deterministic_severity="high", deterministic_confidence=1.0, first_seen="", last_seen="", primary_entity="",
            candidate_evidence=[EvidenceCandidate(evidence_id="ev1", event_id="E01", quote="dummy log", reason="test", source="test", canonical_fields={}, vendor_original_fields={"test_field": "test_value"})]
        ).model_dump()
    }
    
    res = evidence_validation_node(state)
    assert len(res["validated_evidence"]) == 1
    
    state.update(res)
    state["triage_verdict"] = "confirmed_incident"
    state["incident_type"] = "bruteforce_success"
    
    res2 = action_recommendation_node(state)
    assert "SOC Analyst should" in res2["recommended_actions"][0]
