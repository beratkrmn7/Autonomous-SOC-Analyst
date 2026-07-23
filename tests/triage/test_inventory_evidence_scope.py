"""Inventory evidence strength is scoped to real exposure events only."""

from __future__ import annotations

from rich.console import Console

from agent.detection.models import DetectionEvidence, IncidentBundle
from agent.detection.rollup import build_rollup
from agent.triage.brief import (
    _asset_evidence_strength,
    _asset_priority,
    render_soc_brief,
)
from agent.triage.disposition import EvidenceStrength

from tests.fixtures.sanitized_real_log import REDIS_EXPOSURE_SINGLE_SYN, _event


# RFC 6598 shared address space. Unlike the RFC 5737 documentation ranges it
# is neither "private" nor "global" to Python's ipaddress module, which is what
# the roll-up's external-inbound check needs to see on the destination side.
# It is still assigned to no organisation, so nothing identifying is committed.
DESTINATION = "100.64.10.20"
PORT = REDIS_EXPOSURE_SINGLE_SYN.dst_port


def _exposure_event(event_id: str, **overrides):
    defaults = dict(
        src_ip="192.0.2.149",
        src_port=49552,
        dst_ip=DESTINATION,
        dst_port=PORT,
        action="pass",
        offset_seconds=28.0,
        packets=1,
        byte_count=44,
        tcp_flags="S",
    )
    defaults.update(overrides)
    return _event(event_id, **defaults)


def _exposure_incident(events) -> IncidentBundle:
    return IncidentBundle(
        incident_id="INC-EXPOSURE",
        incident_type="critical_management_service_exposed",
        incident_family="firewall_exposure",
        title="Externally allowed Redis",
        severity="high",
        confidence=0.8,
        first_seen=min(e.timestamp for e in events),
        last_seen=max(e.timestamp for e in events),
        primary_entity=DESTINATION,
        target_entities=[],
        signal_ids=["SIG-EXPOSURE"],
        event_ids=[e.event_id for e in events],
        context_event_ids=[],
        evidence=[
            DetectionEvidence(
                event_id=events[0].event_id,
                quote="",
                reason="allowed",
                source="detection",
                original_fields={},
                correlation_context={},
            )
        ],
        metrics={},
        mitre_techniques=[],
        merge_key="exposure",
    )


def _noise_events():
    """Unrelated traffic to the same destination and port."""
    return [
        # A blocked multi-packet scan from a different source.
        _event(
            "noise-blocked",
            src_ip="203.0.113.200",
            src_port=51000,
            dst_ip=DESTINATION,
            dst_port=PORT,
            action="block",
            offset_seconds=60.0,
            packets=40,
            byte_count=4000,
            tcp_flags="S",
        ),
        # An internal flow with a completed handshake.
        _event(
            "noise-internal",
            src_ip="10.1.2.3",
            src_port=52000,
            dst_ip=DESTINATION,
            dst_port=PORT,
            action="pass",
            offset_seconds=61.0,
            packets=30,
            byte_count=9000,
            tcp_flags="SA",
            inbound_zone="lan1-zone",
        ),
        # A payload-bearing flow from elsewhere.
        _event(
            "noise-payload",
            src_ip="203.0.113.201",
            src_port=53000,
            dst_ip=DESTINATION,
            dst_port=PORT,
            action="block",
            offset_seconds=62.0,
            packets=12,
            byte_count=6000,
            tcp_flags="P",
        ),
    ]


def test_unrelated_traffic_does_not_strengthen_an_exposed_asset() -> None:
    exposure = _exposure_event("exposure-syn")
    incident = _exposure_incident([exposure])
    events = [exposure, *_noise_events()]
    lookup = {event.event_id: event for event in events}

    rollup = build_rollup([incident], lookup)
    assert len(rollup.exposed_assets) == 1
    asset = rollup.exposed_assets[0]

    # The asset was built from exactly the one allowed inbound exposure event.
    assert asset.exposure_event_ids == (exposure.event_id,)
    assert asset.event_count == 1

    strengths = _asset_evidence_strength(rollup, lookup)
    assert strengths[asset.effective_destination_ip] is EvidenceStrength.SYN_ONLY

    # Priority must not be inflated by the noise either.
    assert _asset_priority(asset, strengths[asset.effective_destination_ip]) == "P2"


def test_rendered_inventory_reports_the_scoped_strength() -> None:
    exposure = _exposure_event("exposure-syn")
    incident = _exposure_incident([exposure])
    events = [exposure, *_noise_events()]
    lookup = {event.event_id: event for event in events}

    console = Console(record=True, width=200, color_system=None)
    render_soc_brief(
        console,
        rollup=build_rollup([incident], lookup),
        event_lookup=lookup,
        source_name="firewall.json",
        job_id="job-inv",
        provider_call_count=0,
    )
    output = console.export_text()

    assert "syn_only" in output
    for stronger in (
        "bidirectional_transport",
        "application_evidence",
        "payload_bearing_unidirectional",
        "multi_packet_unidirectional",
    ):
        assert stronger not in output


def test_genuine_stronger_exposure_evidence_is_still_reported() -> None:
    """Scoping must not blind the inventory to real exposure evidence."""
    strong = _event(
        "exposure-strong",
        src_ip="192.0.2.55",
        src_port=54000,
        dst_ip=DESTINATION,
        dst_port=PORT,
        action="pass",
        offset_seconds=5.0,
        packets=20,
        byte_count=8000,
        tcp_flags="SA",
    )
    incident = _exposure_incident([strong])
    lookup = {event.event_id: event for event in [strong, *_noise_events()]}

    rollup = build_rollup([incident], lookup)
    strengths = _asset_evidence_strength(rollup, lookup)
    assert (
        strengths[rollup.exposed_assets[0].effective_destination_ip]
        is EvidenceStrength.BIDIRECTIONAL_TRANSPORT
    )
