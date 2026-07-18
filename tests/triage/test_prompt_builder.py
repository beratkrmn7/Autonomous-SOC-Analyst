from agent.triage.input_builder import _build_safe_event
from agent.triage.models import TriageInput
from agent.triage.prompt_builder import TRIAGE_PROMPT_VERSION, build_system_prompt
from agent.schema import CanonicalLogEvent


def test_system_prompt_compacts_empty_fields_without_losing_safe_event_data() -> None:
    event = CanonicalLogEvent(
        event_id="event-1",
        parser_name="pf_firewall",
        parse_status="parsed",
        source_name="firewall.json",
        safe_message_excerpt="BLOCK TCP flags=SYN",
    )
    triage_input = TriageInput(
        incident_id="incident-1",
        incident_type="horizontal_scan",
        incident_family="network_scanning",
        title="Horizontal scan",
        deterministic_severity="high",
        deterministic_confidence=0.9,
        first_seen="2026-07-10T09:54:00Z",
        last_seen="2026-07-10T09:55:00Z",
        primary_entity="192.0.2.10",
        deterministic_metrics={
            "total_events": 18,
            "distinct_targets": 18,
            "all_attempts_blocked": True,
        },
        limited_context_events=[_build_safe_event(event)],
    )

    prompt = build_system_prompt(triage_input)

    assert TRIAGE_PROMPT_VERSION == "phase4-v2"
    assert "<UNTRUSTED_INCIDENT_DATA>" in prompt
    assert "BLOCK TCP flags=SYN" in prompt
    assert '"total_events":18' in prompt
    assert "maximum permitted verdict" in prompt
    assert '"src_ip":null' not in prompt
    assert '"target_entities":[]' not in prompt
