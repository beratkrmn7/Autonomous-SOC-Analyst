from datetime import datetime, timedelta, timezone

from rich.console import Console

from agent.detection.models import DetectionEvidence, IncidentBundle
from agent.detection.presentation import build_brief_selection
from agent.detection.rollup import build_rollup
from agent.triage.brief import render_soc_brief
from agent.triage.enrichment import BriefEnrichmentResult, deterministic_fallback
from tests.detection.helpers import FIXED_TIME, build_event


def _incident(events) -> IncidentBundle:
    return IncidentBundle(
        incident_id="INC-BRIEF",
        incident_type="critical_management_service_exposed",
        incident_family="firewall_exposure",
        title="Critical Management Service Exposed from 8.8.8.8",
        severity="critical",
        confidence=0.8,
        first_seen=events[0].timestamp,
        last_seen=events[-1].timestamp,
        primary_entity="10.0.0.20",
        target_entities=["8.8.8.8"],
        signal_ids=["SIG-BRIEF"],
        event_ids=[event.event_id for event in events],
        context_event_ids=[],
        evidence=[
            DetectionEvidence(
                event_id=events[0].event_id,
                quote="structured evidence",
                reason="allowed critical exposure",
                source="critical_management_service_exposed",
                original_fields={},
                correlation_context={},
            )
        ],
        metrics={
            "allowed_event_count": len(events),
            "blocked_event_count": 0,
            "severity_total_event_count": len(events),
            "contributing_job_count": 2,
            "current_job_event_count": 1,
            "prior_job_event_count": 1,
        },
        mitre_techniques=[],
        merge_key="brief",
        absorbed_signal_ids=[],
    )


def test_brief_renders_deterministic_facts_provenance_and_evidence() -> None:
    plus_three = timezone(timedelta(hours=3))
    events = [
        build_event(
            f"brief-{index}",
            timestamp=datetime(2026, 7, 10, 9, 50, index, tzinfo=plus_three),
            src_ip="8.8.8.8",
            dst_ip="203.0.113.20",
            dst_port=443,
            translated_dst_ip="10.0.0.20",
            translated_dst_port=6379,
            inbound_zone="wan1-zone",
            action="pass",
        )
        for index in range(2)
    ]
    incident = _incident(events)
    event_lookup = {event.event_id: event for event in events}
    rollup = build_rollup([incident], event_lookup)
    selection = build_brief_selection([incident], event_lookup)
    enrichment = BriefEnrichmentResult(
        items=tuple(
            deterministic_fallback(item) for item in selection.all_items
        )
    )
    console = Console(record=True, width=160, color_system=None)

    render_soc_brief(
        console,
        rollup=rollup,
        event_lookup=event_lookup,
        source_name="firewall.json",
        job_id="job-1",
        provider_call_count=0,
        selection=selection,
        enrichment=enrichment,
        generated_at=FIXED_TIME,
    )
    output = console.export_text()

    assert "SOC TRIAGE BRIEF" in output
    assert "2026-07-10 09:50:00+03:00" in output
    assert "Evidence: brief-0" in output
    assert "Firewall pass proves policy" in output
    assert "exposure only; it does not prove authentication" in output
    assert "Provider calls for this request: 0" in output
    # The deterministic row carries its evidence strength and ATT&CK context.
    assert "Evidence strength: bidirectional_transport" in output
    assert "ATT&CK context:" in output


def test_brief_restores_persisted_utc_events_to_source_offset() -> None:
    event = build_event(
        "offset-event",
        timestamp=datetime(2026, 7, 10, 6, 50),
        parser_metadata={"source_timezone_offset": "+03:00"},
        src_ip="8.8.8.8",
        dst_ip="10.0.0.20",
        dst_port=6379,
        inbound_zone="wan",
        action="pass",
    )
    incident = _incident([event])
    event_lookup = {event.event_id: event}
    console = Console(record=True, width=160, color_system=None)

    render_soc_brief(
        console,
        rollup=build_rollup([incident], event_lookup),
        event_lookup=event_lookup,
        source_name="firewall.json",
        job_id="job-offset",
        provider_call_count=0,
        generated_at=FIXED_TIME,
    )

    output = console.export_text()
    assert "2026-07-10 09:50:00+03:00" in output
    assert "events ->" in output


def test_brief_action_sections_are_bounded_to_ten_combined_items() -> None:
    events = [
        build_event(
            f"event-{index}",
            src_ip=f"8.8.8.{index + 1}",
            dst_ip=f"10.0.0.{index + 1}",
            dst_port=3389,
            inbound_zone="wan",
            action="pass",
        )
        for index in range(14)
    ]
    incidents = []
    for index, event in enumerate(events):
        incident = _incident([event]).model_copy(
            update={
                "incident_id": f"inc-{index}",
                "signal_ids": [f"sig-{index}"],
                "merge_key": f"merge-{index}",
                "severity": "high" if index < 7 else "medium",
            }
        )
        incidents.append(incident)
    rollup = build_rollup(
        incidents, {event.event_id: event for event in events}
    )
    assert len(rollup.act_now) == 5
    assert len(rollup.investigate) == 5
