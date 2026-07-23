"""Engine-level regression for the fixed-source-port signal variant.

These tests drive ``DetectionEngine.analyze`` rather than the helper
functions, so a signal that the helpers happily build but the engine rejects
for a contract violation cannot pass unnoticed again.
"""

from __future__ import annotations

from agent.detection.engine import DetectionEngine

from tests.fixtures.sanitized_real_log import (
    FILE0_EVENTS,
    FILE1_EVENTS,
    FIXED_SOURCE_PORT,
    FSP_CANONICAL_A,
    FSP_CLUSTER_A,
    FSP_SOURCE_CANONICAL_A,
)


def _analyze(events):
    return DetectionEngine().analyze(list(events), [])


def _fixed_source_port_signals(result):
    return [
        signal
        for signal in result.signals
        if signal.signal_type == "fixed_source_port_scan"
    ]


def test_qualifying_fixture_produces_one_active_fixed_source_port_signal() -> None:
    result = _analyze(FSP_CANONICAL_A)

    signals = _fixed_source_port_signals(result)
    assert len(signals) == 1
    signal = signals[0]
    assert signal.rule_id == "network_scan_vertical"
    assert signal.rule_name == "Vertical Port Scan"
    assert signal.rule_version == "1.1.0"
    assert signal.signal_family == "network_scanning"
    assert signal.primary_entity == FSP_SOURCE_CANONICAL_A
    assert signal.metrics["fixed_source_port"] == FIXED_SOURCE_PORT
    assert signal.metrics["event_count"] == 7
    # Technique and tactic stay in separate fields.
    assert signal.mitre_techniques == ["T1046"]
    assert signal.metrics["mitre_tactic"] == "TA0007"

    # The signal is active, not suppressed away.
    assert signal.suppressed is False
    assert signal not in result.suppressed_signals


def test_no_contract_or_variant_warning_is_emitted() -> None:
    result = _analyze(FSP_CANONICAL_A)

    joined = " ".join(result.warnings)
    assert "signal_type_mismatch" not in joined
    assert "undeclared_signal_variant" not in joined
    assert "rule_version_mismatch" not in joined
    assert "network_scan_vertical produced invalid signal" not in joined


def test_non_qualifying_fixture_produces_no_fixed_source_port_signal() -> None:
    # Three events from one source: below the 5-event exact-source threshold.
    result = _analyze(FSP_CLUSTER_A)
    assert _fixed_source_port_signals(result) == []


def test_signal_survives_deduplication_and_correlation() -> None:
    # Feeding the same events twice must not yield two signals, and the
    # surviving signal must be correlated into an incident.
    result = _analyze(list(FSP_CANONICAL_A) + list(FSP_CANONICAL_A))

    signals = _fixed_source_port_signals(result)
    assert len(signals) == 1
    signal = signals[0]
    assert len(signal.event_ids) == len(set(signal.event_ids)) == 7

    correlated = [
        incident
        for incident in result.incidents
        if signal.signal_id in incident.signal_ids
    ]
    assert len(correlated) == 1
    assert correlated[0].incident_family == "network_scanning"


def test_full_file_fixtures_stay_contract_clean() -> None:
    for events in (FILE0_EVENTS, FILE1_EVENTS):
        result = _analyze(events)
        joined = " ".join(result.warnings)
        assert "produced invalid signal" not in joined


def test_registry_count_is_unchanged_at_thirty_six() -> None:
    assert len(DetectionEngine().registry.get_all_rules()) == 36


def test_detection_remains_provider_free(monkeypatch) -> None:
    def provider_forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("provider call attempted during detection")

    monkeypatch.setattr(
        "agent.triage.provider_factory.build_provider", provider_forbidden
    )
    result = _analyze(FILE0_EVENTS)
    assert result.signals
