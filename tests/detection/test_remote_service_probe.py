from datetime import timedelta

import pytest

from agent.detection.config import DetectionSettings
from agent.detection.contracts import validate_signal_contract
from agent.detection.detectors.base import DetectionContext
from agent.detection.detectors.remote_service_probe import RemoteServiceProbeRule
from agent.detection.engine import DetectionEngine
from agent.detection.registry import RuleRegistry
from agent.schema import CanonicalLogEvent
from tests.detection.helpers import FIXED_TIME, build_event


def _settings() -> DetectionSettings:
    return DetectionSettings(
        REMOTE_SERVICE_MIN_EVENTS=2,
        REMOTE_SERVICE_MIN_DISTINCT_TARGETS=2,
    )


def _service_events(port: int) -> list[CanonicalLogEvent]:
    return [
        build_event(
            f"service-{port}-{index}",
            timestamp=FIXED_TIME + timedelta(seconds=index),
            src_ip="192.0.2.44",
            dst_ip=f"198.51.100.{index + 1}",
            dst_port=port,
            action="block",
            protocol="TCP",
            tcp_flags="SYN",
        )
        for index in range(2)
    ]


@pytest.mark.parametrize(
    ("port", "expected_identity"),
    [
        (3389, ("rdp_probe", "RDP Probe", "rdp_probe")),
        (22, ("ssh_probe", "SSH Probe", "ssh_probe")),
    ],
)
def test_remote_service_declared_variants_pass_contract(
    port: int,
    expected_identity: tuple[str, str, str],
) -> None:
    rule = RemoteServiceProbeRule()
    events = _service_events(port)
    context = DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME)

    signals = rule.evaluate(events, context)

    assert rule.rule_id == "remote_service_probe"
    assert len(signals) == 1
    signal = signals[0]
    assert (signal.rule_id, signal.rule_name, signal.signal_type) == expected_identity
    validate_signal_contract(signal, rule, {event.event_id for event in events})


@pytest.mark.parametrize(
    ("port", "expected_type"),
    [(3389, "rdp_probe"), (22, "ssh_probe")],
)
def test_remote_service_incident_compatibility_and_deterministic_ids(
    port: int,
    expected_type: str,
) -> None:
    registry = RuleRegistry()
    registry.register(RemoteServiceProbeRule())
    engine = DetectionEngine(registry=registry, settings=_settings())
    events = _service_events(port)

    first = engine.analyze(events)
    second = engine.analyze(events)

    assert len(first.signals) == 1
    assert len(first.incidents) == 1
    assert first.signals[0].signal_type == expected_type
    assert first.incidents[0].incident_type == expected_type
    assert first.signals[0].signal_id == second.signals[0].signal_id
    assert first.incidents[0].incident_id == second.incidents[0].incident_id
    assert first.signals[0].model_dump(mode="json") == second.signals[0].model_dump(mode="json")
    assert first.incidents[0].model_dump(mode="json") == second.incidents[0].model_dump(
        mode="json"
    )
