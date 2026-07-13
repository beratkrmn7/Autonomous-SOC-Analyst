# mypy: ignore-errors
from agent.triage.provider import TriageProvider, TriageProviderRequest, TriageProviderResponse
from agent.triage.models import TriageSubmission
from agent.triage.enums import TriageVerdict, TriageSeverity

class FakeTriageProvider(TriageProvider):
    def __init__(self, predefined_submission: TriageSubmission = None, exception_to_raise: Exception = None):
        self.predefined_submission = predefined_submission
        self.exception_to_raise = exception_to_raise
        self.call_count = 0
        
    def invoke(self, request: TriageProviderRequest) -> TriageProviderResponse:
        self.call_count += 1
        
        if self.exception_to_raise:
            raise self.exception_to_raise
            
        if self.predefined_submission:
            sub = self.predefined_submission
        else:
            sub = TriageSubmission(
                triage_verdict=TriageVerdict.CONFIRMED_INCIDENT,
                incident_type="port_scan",
                severity=TriageSeverity.MEDIUM,
                confidence_score=0.9,
                summary="Fake verified incident",
                selected_evidence_ids=[],
                claims=[]
            )
            
        return TriageProviderResponse(
            submission=sub,
            prompt_tokens=100,
            completion_tokens=50
        )
