"""T-C: source/service exposure grouping is presentation-only."""

from __future__ import annotations

import copy

from agent.detection.detectors.scan_helpers import classify_service
from agent.detection.models import DetectionEvidence, IncidentBundle
from agent.detection.presentation import (
    build_brief_selection,
    build_exposure_groups,
)

from tests.fixtures.sanitized_real_log import (
    DOCKER_EXPOSURE,
    SSH_SWEEP_PORT_22,
    SSH_SWEEP_PORT_22022,
    SSH_SWEEP_SOURCE,
)


def _incident(event, incident_id: str) -> IncidentBundle:
    return IncidentBundle(
        incident_id=incident_id,
        incident_type="inbound_sensitive_service_allowed",
        incident_family="firewall_exposure",
        title=f"Externally allowed service on {event.dst_ip}",
        severity="medium",
        confidence=0.7,
        first_seen=event.timestamp,
        last_seen=event.timestamp,
        primary_entity=event.dst_ip,
        target_entities=[],
        signal_ids=[f"SIG-{incident_id}"],
        event_ids=[event.event_id],
        context_event_ids=[],
        evidence=[
            DetectionEvidence(
                event_id=event.event_id,
                quote="",
                reason="allowed inbound service",
                source="detection",
                original_fields={},
                correlation_context={},
            )
        ],
        metrics={},
        mitre_techniques=[],
        merge_key=incident_id,
    )


def test_port_22022_is_excluded_because_the_classifier_does_not_call_it_ssh() -> None:
    """The destination count comes from the classifier, never a hardcoded number."""
    assert classify_service(22) == "ssh"
    assert classify_service(22022) is None


# 13. One compatible SSH exposure group with a classifier-derived destination
#     count.
def test_ssh_sweep_forms_one_group_with_classifier_derived_destinations() -> None:
    events = list(SSH_SWEEP_PORT_22) + list(SSH_SWEEP_PORT_22022)
    incidents = [
        _incident(event, f"INC-{index}") for index, event in enumerate(events)
    ]
    lookup = {event.event_id: event for event in events}

    groups = build_exposure_groups(incidents, lookup)
    ssh_groups = [group for group in groups if group.service == "ssh"]

    assert len(ssh_groups) == 1
    group = ssh_groups[0]
    assert group.source_ips == (SSH_SWEEP_SOURCE,)
    # Four port-22 destinations. Port 22022 is not SSH to the classifier, so
    # its host is not a fifth SSH destination.
    assert len(group.effective_destinations) == 4
    assert set(group.effective_destinations) == {
        event.dst_ip for event in SSH_SWEEP_PORT_22
    }
    assert group.ports == (22,)
    assert len(group.member_incident_ids) == 4

    # The 22022 events are not classified as a sensitive service at all, so
    # they form no exposure group of their own.
    assert all(group.service is not None for group in groups)
    assert "198.51.100.96" not in group.effective_destinations


# 12. Grouping never deletes or mutates canonical incidents.
def test_grouping_does_not_mutate_or_delete_canonical_incidents() -> None:
    events = list(SSH_SWEEP_PORT_22)
    incidents = [
        _incident(event, f"INC-{index}") for index, event in enumerate(events)
    ]
    lookup = {event.event_id: event for event in events}
    before = copy.deepcopy(incidents)

    groups = build_exposure_groups(incidents, lookup)
    selection = build_brief_selection(incidents, lookup)

    assert incidents == before  # untouched
    assert len(incidents) == 4  # none deleted

    # Every canonical incident is still reachable from the presentation row.
    grouped_ids = {
        incident_id for group in groups for incident_id in group.member_incident_ids
    }
    assert grouped_ids == {incident.incident_id for incident in incidents}
    for item in selection.all_items:
        assert item.member_incident_ids


def test_different_services_are_never_merged() -> None:
    events = [SSH_SWEEP_PORT_22[0], DOCKER_EXPOSURE]
    incidents = [
        _incident(event, f"INC-{index}") for index, event in enumerate(events)
    ]
    lookup = {event.event_id: event for event in events}

    groups = build_exposure_groups(incidents, lookup)

    assert {group.service for group in groups} == {"ssh", "docker"}
    for group in groups:
        assert len(group.source_ips) == 1


def test_grouping_uses_exact_source_never_a_network() -> None:
    neighbour = SSH_SWEEP_PORT_22[0].model_copy(
        update={"event_id": "neighbour-1", "src_ip": "192.0.2.11"}
    )
    events = [SSH_SWEEP_PORT_22[0], neighbour]
    incidents = [
        _incident(event, f"INC-{index}") for index, event in enumerate(events)
    ]
    lookup = {event.event_id: event for event in events}

    groups = build_exposure_groups(incidents, lookup)

    # Same /24 and same service, but different exact sources -> two groups.
    assert len(groups) == 2
    assert {group.source_ips[0] for group in groups} == {"192.0.2.10", "192.0.2.11"}
