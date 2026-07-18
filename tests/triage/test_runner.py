# mypy: ignore-errors
from agent.triage.runner import TriageRunner
from agent.triage.provider import TriageProvider, TriageProviderResponse, TriageProviderRequest
from agent.triage.exceptions import ProviderInvalidResponseError, ProviderTimeoutError
from agent.triage.enums import ReviewReason, TriageVerdict, TriageSeverity
from agent.triage.models import TriageSubmission
from agent.detection.models import IncidentBundle as DetectionIncidentBundle
from agent.triage.models import TriageIncidentContext
import datetime
import time

class SlowFakeProvider(TriageProvider):
    def invoke(self, request: TriageProviderRequest) -> TriageProviderResponse:
        time.sleep(0.2)
        return TriageProviderResponse(
            submission=TriageSubmission(
                triage_verdict=TriageVerdict.FALSE_POSITIVE,
                incident_type="test",
                severity=TriageSeverity.NONE,
                confidence_score=0.9,
                summary="Done"
            ),
            prompt_tokens=10,
            completion_tokens=10
        )

class ExceptionFakeProvider(TriageProvider):
    def invoke(self, request: TriageProviderRequest) -> TriageProviderResponse:
        raise ProviderTimeoutError("Timed out from groq")


class InvalidThenValidProvider(TriageProvider):
    timeout_seconds = 10

    def __init__(self):
        self.calls = 0
        self.prompts = []

    def invoke(self, request: TriageProviderRequest) -> TriageProviderResponse:
        self.calls += 1
        self.prompts.append(request.system_prompt)
        if self.calls == 1:
            raise ProviderInvalidResponseError("missing structured submission")
        return TriageProviderResponse(
            submission=TriageSubmission(
                triage_verdict=TriageVerdict.SUSPICIOUS_ACTIVITY,
                incident_type="horizontal_scan",
                severity=TriageSeverity.MEDIUM,
                confidence_score=0.6,
                summary="Blocked scan",
            )
        )

def test_triage_runner_global_timeout():
    provider = SlowFakeProvider()
    runner = TriageRunner(provider=provider)
    runner.settings.triage_timeout_seconds = 0.1 # Very short timeout
    
    bundle = DetectionIncidentBundle(
        incident_id="INC-1",
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
        event_ids=[],
        context_event_ids=[],
        first_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        last_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    )
    context = TriageIncidentContext(incident=bundle, events=[])
    
    state = {"incident_id": "INC-1", "detected_signals": [], "candidate_evidence": []}
    
    result = runner.run(state, context)
    assert result.submission is not None
    assert result.submission.triage_verdict == TriageVerdict.NEEDS_REVIEW
    assert result.review_reason == ReviewReason.PROVIDER_TIMEOUT
    assert result.metrics.fallback_used is True

def test_triage_runner_provider_timeout_exception():
    provider = ExceptionFakeProvider()
    runner = TriageRunner(provider=provider)
    
    bundle = DetectionIncidentBundle(
        incident_id="INC-1",
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
        event_ids=[],
        context_event_ids=[],
        first_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        last_seen=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    )
    context = TriageIncidentContext(incident=bundle, events=[])
    
    state = {"incident_id": "INC-1", "detected_signals": [], "candidate_evidence": []}
    
    result = runner.run(state, context)
    assert result.submission is not None
    assert result.submission.triage_verdict == TriageVerdict.NEEDS_REVIEW
    assert result.review_reason == ReviewReason.PROVIDER_TIMEOUT
    assert result.metrics.fallback_used is True


def test_triage_runner_retries_invalid_structured_output_once():
    provider = InvalidThenValidProvider()
    runner = TriageRunner(provider=provider)
    runner.settings.llm_invalid_response_retries = 1

    timestamp = datetime.datetime(2026, 7, 10, tzinfo=datetime.timezone.utc)
    bundle = DetectionIncidentBundle(
        incident_id="INC-RETRY",
        incident_type="horizontal_scan",
        incident_family="network_scanning",
        title="scan",
        severity="medium",
        confidence=0.6,
        primary_entity="192.0.2.10",
        target_entities=[],
        signal_ids=[],
        evidence=[],
        metrics={},
        mitre_techniques=[],
        merge_key="mock",
        event_ids=[],
        context_event_ids=[],
        first_seen=timestamp,
        last_seen=timestamp,
    )

    result = runner.run(
        {"incident_id": "INC-RETRY", "detected_signals": [], "candidate_evidence": []},
        TriageIncidentContext(incident=bundle, events=[]),
    )

    assert provider.calls == 2
    assert "CORRECTIVE RETRY" in provider.prompts[1]
    assert result.submission is not None
    assert result.submission.triage_verdict == TriageVerdict.SUSPICIOUS_ACTIVITY
    assert result.metrics.retry_count == 1
