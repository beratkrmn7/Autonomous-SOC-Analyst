from agent.detection.config import DetectionSettings
from agent.detection.detectors.inbound_exposure import (
    CriticalManagementServiceExposedRule,
    DnatSensitiveServiceExposureRule,
)
from agent.detection.detectors.remote_service_probe import RemoteServiceProbeRule
from agent.detection.engine import DetectionEngine
from agent.detection.registry import RuleRegistry
from tests.detection.helpers import build_event


def _engine(rule, **settings) -> DetectionEngine:
    registry = RuleRegistry()
    registry.register(rule)
    return DetectionEngine(
        registry=registry,
        settings=DetectionSettings.model_validate(settings),
    )


def test_dnat_title_names_source_while_primary_entity_is_effective_asset() -> None:
    event = build_event(
        "dnat",
        src_ip="8.8.8.8",
        dst_ip="203.0.113.20",
        dst_port=443,
        translated_dst_ip="10.0.0.20",
        translated_dst_port=6379,
        inbound_zone="wan",
        action="pass",
    )
    incident = _engine(DnatSensitiveServiceExposureRule()).analyze([event]).incidents[0]
    assert incident.primary_entity == "10.0.0.20"
    assert incident.title == "Detected DNAT Sensitive Service Exposure from 8.8.8.8"
    assert "from 10.0.0.20" not in incident.title


def test_critical_exposure_uses_asset_primary_without_losing_source_title() -> None:
    event = build_event(
        "ipmi",
        src_ip="193.176.29.18",
        dst_ip="193.255.131.254",
        dst_port=623,
        inbound_zone="wan1-zone",
        action="pass",
    )
    incident = _engine(CriticalManagementServiceExposedRule()).analyze([event]).incidents[0]
    assert incident.primary_entity == "193.255.131.254"
    assert incident.title.endswith("from 193.176.29.18")


def test_service_probe_keeps_source_primary_and_source_title() -> None:
    events = [
        build_event(
            f"rdp-{index}",
            src_ip="203.0.113.10",
            dst_ip=f"10.0.0.{index + 1}",
            dst_port=3389,
            tcp_flags="SYN",
            action="block",
        )
        for index in range(3)
    ]
    incident = _engine(
        RemoteServiceProbeRule(),
        REMOTE_SERVICE_MIN_EVENTS=3,
        REMOTE_SERVICE_MIN_DISTINCT_TARGETS=3,
        REMOTE_SERVICE_MIN_BLOCK_RATIO=0.6,
        REMOTE_SERVICE_MIN_SYN_RATIO=0.5,
    ).analyze(events).incidents[0]
    assert incident.primary_entity == "203.0.113.10"
    assert incident.title == "Detected RDP Probe from 203.0.113.10"
