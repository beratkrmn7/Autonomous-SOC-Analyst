"""Focused test for DetectionSignal primary_entity hydration.

DetectionSignal has no dedicated primary_entity column. orm_to_domain_signal
must restore the real source/attacker primary_entity from the reserved
internal metrics key it was stashed under, never from target_entities
(which would reverse source/attacker and target/victim).
"""

from datetime import datetime, timezone

from agent.detection.models import DetectionSignal
from agent.persistence.mappers import DataMapper


NOW = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)


def _signal() -> DetectionSignal:
    return DetectionSignal(
        signal_id="signal-1",
        rule_id="network_scan_horizontal",
        rule_version="1.0.0",
        rule_name="Horizontal Port Scan",
        signal_type="horizontal_scan",
        signal_family="network_scanning",
        severity="high",
        confidence=0.91,
        first_seen=NOW,
        last_seen=NOW,
        event_ids=["event-1"],
        primary_entity="203.0.113.5",
        target_entities=["192.0.2.10", "192.0.2.11"],
        metrics={"event_count": 4},
        evidence=[],
        mitre_techniques=["T1046"],
        tags=["network", "scan"],
    )


def test_fresh_and_hydrated_signal_have_same_primary_entity_and_targets() -> None:
    fresh = _signal()

    orm_signal = DataMapper.domain_signal_to_orm(fresh)
    hydrated = DataMapper.orm_to_domain_signal(orm_signal)

    assert hydrated.primary_entity == fresh.primary_entity
    assert hydrated.target_entities == fresh.target_entities
    assert hydrated.primary_entity not in fresh.target_entities
    assert "_primary_entity" not in hydrated.metrics
    assert hydrated.metrics == fresh.metrics


def test_row_without_reserved_key_falls_back_to_unknown_not_a_target_entity() -> None:
    fresh = _signal()
    orm_signal = DataMapper.domain_signal_to_orm(fresh)
    # Simulate a row persisted before the reserved key existed.
    orm_signal.metrics = {"event_count": 4}

    hydrated = DataMapper.orm_to_domain_signal(orm_signal)

    assert hydrated.primary_entity == "unknown"
    assert hydrated.primary_entity not in fresh.target_entities
