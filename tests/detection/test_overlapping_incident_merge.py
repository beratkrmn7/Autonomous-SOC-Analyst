from datetime import datetime, timedelta, timezone

from agent.detection.config import DetectionSettings
from agent.detection.incident_correlation import merge_overlapping_incidents
from agent.detection.models import DetectionSignal, IncidentBundle


BASE_TIME = datetime(2026, 7, 10, 9, 53, 41, tzinfo=timezone.utc)


def _signal(signal_id: str, event_ids: list[str]) -> DetectionSignal:
    return DetectionSignal(
        signal_id=signal_id,
        rule_id="subnet_sweep",
        rule_version="1.0.0",
        rule_name="Subnet Sweep",
        signal_type="subnet_sweep",
        signal_family="network_scanning",
        severity="medium",
        confidence=0.8,
        first_seen=BASE_TIME,
        last_seen=BASE_TIME + timedelta(seconds=2),
        event_ids=event_ids,
        primary_entity="45.33.88.175",
        target_entities=[f"192.0.2.{index}" for index in range(len(event_ids))],
        metrics={},
        evidence=[],
        mitre_techniques=["T1046"],
        tags=[],
    )


def _incident(
    incident_id: str,
    signal: DetectionSignal,
    *,
    event_ids: list[str],
) -> IncidentBundle:
    return IncidentBundle(
        incident_id=incident_id,
        incident_type="subnet_sweep",
        incident_family="network_scanning",
        title="Detected Subnet Sweep from 45.33.88.175",
        severity="medium",
        confidence=signal.confidence,
        first_seen=signal.first_seen,
        last_seen=signal.last_seen,
        primary_entity=signal.primary_entity,
        target_entities=signal.target_entities,
        signal_ids=[signal.signal_id],
        event_ids=event_ids,
        context_event_ids=[],
        evidence=[],
        metrics={
            "primary_signal_id": signal.signal_id,
            "total_events": len(event_ids),
        },
        mitre_techniques=signal.mitre_techniques,
        merge_key=f"merge-{incident_id}",
    )


def test_nested_overlapping_incidents_merge_into_larger_incident() -> None:
    larger_ids = [f"event-{index:02d}" for index in range(38)]
    subset_ids = larger_ids[-14:]
    larger_signal = _signal("SIG-LARGER", larger_ids)
    subset_signal = _signal("SIG-SUBSET", subset_ids)
    larger = _incident("INC-A9639A6B3ED3", larger_signal, event_ids=larger_ids)
    subset = _incident("INC-FCB046816A80", subset_signal, event_ids=subset_ids)

    merged, merge_count = merge_overlapping_incidents(
        [subset, larger],
        [subset_signal, larger_signal],
        DetectionSettings(),
    )

    assert merge_count == 1
    assert len(merged) == 1
    assert merged[0].incident_id == larger.incident_id
    assert merged[0].event_ids == sorted(larger_ids)
    assert merged[0].signal_ids == ["SIG-LARGER", "SIG-SUBSET"]
    assert merged[0].absorbed_signal_ids == ["SIG-SUBSET"]
    assert merged[0].metrics["overlapping_incident_merge_count"] == 1


def test_same_type_and_entity_without_required_overlap_do_not_merge() -> None:
    left_signal = _signal("SIG-LEFT", ["left-1", "left-2"])
    right_signal = _signal("SIG-RIGHT", ["right-1", "right-2"])
    left = _incident("INC-LEFT", left_signal, event_ids=left_signal.event_ids)
    right = _incident("INC-RIGHT", right_signal, event_ids=right_signal.event_ids)

    merged, merge_count = merge_overlapping_incidents(
        [left, right],
        [left_signal, right_signal],
        DetectionSettings(),
    )

    assert merge_count == 0
    assert {incident.incident_id for incident in merged} == {
        "INC-LEFT",
        "INC-RIGHT",
    }
