from dataclasses import dataclass
from datetime import timedelta

import pytest
from pydantic import ValidationError

from agent.detection.config import DetectionSettings
from agent.detection.contracts import (
    DetectionRuleMetadata,
    RuleContractError,
    validate_signal_contract,
)
from agent.detection.detectors import register_default_rules
from agent.detection.detectors.base import BaseDetectionRule, DetectionContext
from agent.detection.detectors.coordinated_scan import RepeatedBlockedScannerRule
from agent.detection.detectors.extended_service_probe import (
    DatabaseServiceProbeRule,
    DockerDaemonProbeRule,
    KubernetesServiceProbeRule,
    LegacyCleartextServiceProbeRule,
    SmbProbeRule,
    VncProbeRule,
    WebAdminPanelProbeRule,
    WinRmProbeRule,
    _ProfiledServiceProbeRule,
)
from agent.detection.detectors.horizontal_scan import HorizontalScanRule
from agent.detection.detectors.remote_service_probe import RemoteServiceProbeRule
from agent.detection.detectors.service_sweep import MultiServiceSweepRule
from agent.detection.engine import DetectionEngine
from agent.detection.registry import RuleRegistry, default_registry
from agent.schema import CanonicalLogEvent
from tests.detection.helpers import (
    FIXED_TIME,
    assert_evidence_belongs_to_signal,
    assert_signal_contract,
    assert_signal_is_deterministic,
    build_event,
)


PHASE6B1_RULE_IDS = {
    "scan_followed_by_allowed_connection",
    "remote_service_probe",
    "internal_lateral_scan",
    "distributed_scan",
    "multi_service_sweep",
    "subnet_sweep",
    "network_flood_dos",
    "network_scan_horizontal",
    "network_scan_vertical",
    "spi_anomaly_burst",
    "repeated_blocked_scanner",
    "low_and_slow_horizontal_scan",
    "low_and_slow_vertical_scan",
}
NEW_REGISTERED_RULE_IDS = {
    "smb_probe",
    "vnc_probe",
    "winrm_probe",
    "database_service_probe",
    "kubernetes_service_probe",
    "docker_daemon_probe",
    "web_admin_panel_probe",
    "legacy_cleartext_service_probe",
}


def _settings(**overrides: object) -> DetectionSettings:
    values: dict[str, object] = {
        "EXTENDED_SERVICE_PROBE_WINDOW_SECONDS": 120,
        "EXTENDED_SERVICE_PROBE_MIN_EVENTS": 3,
        "EXTENDED_SERVICE_PROBE_MIN_DISTINCT_TARGETS": 3,
        "EXTENDED_SERVICE_PROBE_MIN_BLOCK_RATIO": 0.6,
        "EXTENDED_SERVICE_PROBE_MIN_SYN_RATIO": 0.5,
        "WEB_ADMIN_PROBE_MIN_EVENTS": 3,
        "WEB_ADMIN_PROBE_MIN_DISTINCT_TARGETS": 3,
        "WEB_ADMIN_PROBE_MIN_BLOCK_RATIO": 0.8,
        "WEB_ADMIN_PROBE_MIN_SYN_RATIO": 0.6,
    }
    values.update(overrides)
    return DetectionSettings.model_validate(values)


def _probe_events(
    port: int,
    *,
    count: int = 3,
    action: str = "block",
    protocol: str = "TCP",
    tcp_flags: str = "SYN",
    prefix: str = "probe",
) -> list[CanonicalLogEvent]:
    return [
        build_event(
            f"{prefix}-{port}-{index}",
            timestamp=FIXED_TIME + timedelta(seconds=index),
            src_ip="192.0.2.40",
            dst_ip=f"198.51.100.{index + 1}",
            dst_port=port,
            action=action,
            protocol=protocol,
            tcp_flags=tcp_flags,
        )
        for index in range(count)
    ]


@dataclass(frozen=True)
class ProbeRuleCase:
    case_id: str
    rule: BaseDetectionRule
    port: int
    expected_identity: tuple[str, str, str]


PROBE_RULE_CASES = (
    ProbeRuleCase(
        "smb",
        SmbProbeRule(),
        445,
        ("smb_probe", "SMB Probe", "smb_probe"),
    ),
    ProbeRuleCase(
        "vnc",
        VncProbeRule(),
        5900,
        ("vnc_probe", "VNC Probe", "vnc_probe"),
    ),
    ProbeRuleCase(
        "winrm",
        WinRmProbeRule(),
        5985,
        ("winrm_probe", "WinRM Probe", "winrm_probe"),
    ),
    ProbeRuleCase(
        "database",
        DatabaseServiceProbeRule(),
        3306,
        ("mysql_probe", "MySQL Probe", "mysql_probe"),
    ),
    ProbeRuleCase(
        "kubernetes",
        KubernetesServiceProbeRule(),
        6443,
        ("kubernetes_api_probe", "Kubernetes API Probe", "kubernetes_api_probe"),
    ),
    ProbeRuleCase(
        "docker",
        DockerDaemonProbeRule(),
        2375,
        ("docker_daemon_probe", "Docker Daemon Probe", "docker_daemon_probe"),
    ),
    ProbeRuleCase(
        "web-admin",
        WebAdminPanelProbeRule(),
        8443,
        ("web_admin_panel_probe", "Web Admin Panel Probe", "web_admin_panel_probe"),
    ),
    ProbeRuleCase(
        "legacy-cleartext",
        LegacyCleartextServiceProbeRule(),
        23,
        ("telnet_probe", "Telnet Probe", "telnet_probe"),
    ),
)


@pytest.mark.parametrize("case", PROBE_RULE_CASES, ids=lambda case: case.case_id)
def test_profiled_probe_rule_positive_contract_and_determinism(
    case: ProbeRuleCase,
) -> None:
    events = _probe_events(case.port, prefix=case.case_id)
    context = DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME)

    first = case.rule.evaluate(events, context)
    second = case.rule.evaluate(list(reversed(events)), context)

    assert len(first) == 1
    assert len(second) == 1
    signal = first[0]
    assert (signal.rule_id, signal.rule_name, signal.signal_type) == case.expected_identity
    assert signal.metrics.keys() >= {
        "service",
        "event_count",
        "distinct_targets",
        "destination_ports",
        "block_ratio",
        "syn_ratio",
        "allowed_events",
    }
    assert signal.metrics["destination_ports"] == str(case.port)
    assert_signal_contract(signal, case.rule, events)
    assert_evidence_belongs_to_signal(signal)
    assert_signal_is_deterministic(signal, second[0])


@pytest.mark.parametrize("case", PROBE_RULE_CASES, ids=lambda case: case.case_id)
def test_profiled_probe_rule_allowed_only_traffic_does_not_trigger(
    case: ProbeRuleCase,
) -> None:
    events = _probe_events(
        case.port,
        action="allow",
        tcp_flags="ACK",
        prefix=f"allowed-{case.case_id}",
    )
    context = DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME)

    assert case.rule.evaluate(events, context) == []


@pytest.mark.parametrize(
    ("rule", "ports", "expected_rule_id", "expected_ports"),
    [
        (SmbProbeRule(), (139, 445, 139), "smb_probe", "139,445"),
        (VncProbeRule(), (5900, 5901, 5902), "vnc_probe", "5900,5901,5902"),
        (WinRmProbeRule(), (5985, 5986, 5985), "winrm_probe", "5985,5986"),
        (
            DockerDaemonProbeRule(),
            (2375, 2376, 2375),
            "docker_daemon_probe",
            "2375,2376",
        ),
        (
            LegacyCleartextServiceProbeRule(),
            (20, 21, 20),
            "ftp_probe",
            "20,21",
        ),
    ],
)
def test_multi_port_service_profiles_produce_one_bounded_signal(
    rule: BaseDetectionRule,
    ports: tuple[int, ...],
    expected_rule_id: str,
    expected_ports: str,
) -> None:
    events = [
        _probe_events(port, count=1, prefix=f"multi-port-{index}")[0].model_copy(
            update={
                "event_id": f"multi-port-{index}",
                "timestamp": FIXED_TIME + timedelta(seconds=index),
                "dst_ip": f"198.51.100.{index + 1}",
            }
        )
        for index, port in enumerate(ports)
    ]

    signals = rule.evaluate(
        events,
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    )

    assert len(signals) == 1
    assert signals[0].rule_id == expected_rule_id
    assert signals[0].metrics["destination_ports"] == expected_ports


VARIANT_CASES = (
    (DatabaseServiceProbeRule(), 1433, ("mssql_probe", "MSSQL Probe", "mssql_probe")),
    (DatabaseServiceProbeRule(), 1521, ("oracle_probe", "Oracle Probe", "oracle_probe")),
    (DatabaseServiceProbeRule(), 3306, ("mysql_probe", "MySQL Probe", "mysql_probe")),
    (
        DatabaseServiceProbeRule(),
        5432,
        ("postgresql_probe", "PostgreSQL Probe", "postgresql_probe"),
    ),
    (DatabaseServiceProbeRule(), 6379, ("redis_probe", "Redis Probe", "redis_probe")),
    (
        DatabaseServiceProbeRule(),
        9200,
        ("elasticsearch_probe", "Elasticsearch Probe", "elasticsearch_probe"),
    ),
    (DatabaseServiceProbeRule(), 27017, ("mongodb_probe", "MongoDB Probe", "mongodb_probe")),
    (
        KubernetesServiceProbeRule(),
        6443,
        ("kubernetes_api_probe", "Kubernetes API Probe", "kubernetes_api_probe"),
    ),
    (
        KubernetesServiceProbeRule(),
        10250,
        ("kubelet_probe", "Kubelet Probe", "kubelet_probe"),
    ),
    (
        LegacyCleartextServiceProbeRule(),
        23,
        ("telnet_probe", "Telnet Probe", "telnet_probe"),
    ),
    (
        LegacyCleartextServiceProbeRule(),
        21,
        ("ftp_probe", "FTP Probe", "ftp_probe"),
    ),
)


@pytest.mark.parametrize(
    ("rule", "port", "expected_identity"),
    VARIANT_CASES,
    ids=[identity[0] for _, _, identity in VARIANT_CASES],
)
def test_all_declared_service_probe_variants_emit_exact_identity(
    rule: BaseDetectionRule,
    port: int,
    expected_identity: tuple[str, str, str],
) -> None:
    events = _probe_events(port, prefix=expected_identity[0])
    signal = rule.evaluate(
        events,
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    )[0]

    assert (signal.rule_id, signal.rule_name, signal.signal_type) == expected_identity
    assert_signal_contract(signal, rule, events)


@pytest.mark.parametrize(
    ("rule", "port"),
    [(DatabaseServiceProbeRule(), 3306), (KubernetesServiceProbeRule(), 6443)],
)
def test_undeclared_profile_variant_is_rejected(
    rule: BaseDetectionRule,
    port: int,
) -> None:
    events = _probe_events(port, prefix="undeclared")
    signal = rule.evaluate(
        events,
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    )[0].model_copy(
        update={
            "rule_id": "undeclared_probe",
            "rule_name": "Undeclared Probe",
            "signal_type": "undeclared_probe",
        }
    )

    with pytest.raises(RuleContractError, match="undeclared_signal_variant"):
        validate_signal_contract(signal, rule, {event.event_id for event in events})


def test_multi_identity_profiles_remain_separate_signals() -> None:
    context = DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME)
    database_events = [*_probe_events(3306, prefix="mysql"), *_probe_events(6379, prefix="redis")]
    kubernetes_events = [
        *_probe_events(6443, prefix="kubernetes-api"),
        *_probe_events(10250, prefix="kubelet"),
    ]
    legacy_events = [*_probe_events(23, prefix="telnet"), *_probe_events(21, prefix="ftp")]

    database_signals = DatabaseServiceProbeRule().evaluate(database_events, context)
    kubernetes_signals = KubernetesServiceProbeRule().evaluate(
        kubernetes_events, context
    )
    legacy_signals = LegacyCleartextServiceProbeRule().evaluate(legacy_events, context)

    assert {signal.rule_id for signal in database_signals} == {
        "mysql_probe",
        "redis_probe",
    }
    assert {signal.rule_id for signal in kubernetes_signals} == {
        "kubernetes_api_probe",
        "kubelet_probe",
    }
    assert {signal.rule_id for signal in legacy_signals} == {
        "telnet_probe",
        "ftp_probe",
    }


def test_default_registry_retains_service_pack_with_twenty_nine_rules() -> None:
    register_default_rules()
    first = default_registry.get_all_rules()
    first_metadata = [rule.metadata.model_dump(mode="json") for rule in first]
    register_default_rules()
    second_metadata = [
        rule.metadata.model_dump(mode="json")
        for rule in default_registry.get_all_rules()
    ]
    rule_ids = {rule.rule_id for rule in first}

    assert len(first) == 29
    assert len(rule_ids) == 29
    assert PHASE6B1_RULE_IDS <= rule_ids
    assert NEW_REGISTERED_RULE_IDS <= rule_ids
    assert first_metadata == second_metadata
    assert all(
        DetectionRuleMetadata.model_validate(rule.metadata.model_dump()) == rule.metadata
        for rule in first
    )
    for rule in first:
        if rule.rule_id not in NEW_REGISTERED_RULE_IDS:
            continue
        assert rule.metadata.window_setting == "EXTENDED_SERVICE_PROBE_WINDOW_SECONDS"
        expected_minimum = (
            "WEB_ADMIN_PROBE_MIN_EVENTS"
            if rule.rule_id == "web_admin_panel_probe"
            else "EXTENDED_SERVICE_PROBE_MIN_EVENTS"
        )
        assert rule.metadata.minimum_events_setting == expected_minimum


def test_service_probe_default_thresholds_are_conservative() -> None:
    settings = DetectionSettings()

    assert settings.EXTENDED_SERVICE_PROBE_WINDOW_SECONDS == 300
    assert settings.EXTENDED_SERVICE_PROBE_MIN_EVENTS == 5
    assert settings.EXTENDED_SERVICE_PROBE_MIN_DISTINCT_TARGETS == 3
    assert settings.EXTENDED_SERVICE_PROBE_MIN_BLOCK_RATIO == 0.6
    assert settings.EXTENDED_SERVICE_PROBE_MIN_SYN_RATIO == 0.5
    assert settings.WEB_ADMIN_PROBE_MIN_EVENTS == 8
    assert settings.WEB_ADMIN_PROBE_MIN_DISTINCT_TARGETS == 5
    assert settings.WEB_ADMIN_PROBE_MIN_BLOCK_RATIO == 0.8
    assert settings.WEB_ADMIN_PROBE_MIN_SYN_RATIO == 0.6


@pytest.mark.parametrize(
    ("rule", "expected_profiles"),
    [
        (SmbProbeRule(), ((139, 445),)),
        (VncProbeRule(), ((5900, 5901, 5902, 5903, 5904, 5905),)),
        (WinRmProbeRule(), ((5985, 5986),)),
        (
            DatabaseServiceProbeRule(),
            ((1433,), (1521,), (3306,), (5432,), (6379,), (9200,), (27017,)),
        ),
        (KubernetesServiceProbeRule(), ((6443,), (10250,))),
        (DockerDaemonProbeRule(), ((2375, 2376),)),
        (
            WebAdminPanelProbeRule(),
            ((8000, 8080, 8443, 8888, 9000, 9443, 10000),),
        ),
        (LegacyCleartextServiceProbeRule(), ((23,), (20, 21))),
    ],
)
def test_registered_rules_use_exact_immutable_port_profiles(
    rule: _ProfiledServiceProbeRule,
    expected_profiles: tuple[tuple[int, ...], ...],
) -> None:
    assert tuple(profile.ports for profile in rule.profiles) == expected_profiles


@pytest.mark.parametrize(
    "overrides",
    [
        {"EXTENDED_SERVICE_PROBE_WINDOW_SECONDS": 0},
        {"EXTENDED_SERVICE_PROBE_MIN_EVENTS": 0},
        {"EXTENDED_SERVICE_PROBE_MIN_BLOCK_RATIO": 1.01},
        {"WEB_ADMIN_PROBE_MIN_DISTINCT_TARGETS": 0},
        {"WEB_ADMIN_PROBE_MIN_SYN_RATIO": -0.01},
    ],
)
def test_service_probe_settings_reject_invalid_values(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _settings(**overrides)


def test_web_admin_profile_excludes_broad_and_elasticsearch_ports() -> None:
    assert set(WebAdminPanelProbeRule.profiles[0].ports).isdisjoint({80, 443, 9200})


def test_profiled_evaluator_skips_malformed_and_non_tcp_events() -> None:
    valid_events = _probe_events(445, prefix="valid-smb")
    invalid_events = [
        build_event(
            "malformed-smb",
            timestamp=FIXED_TIME,
            src_ip="not-an-ip",
            dst_ip="198.51.100.90",
            dst_port=445,
            protocol="TCP",
            action="block",
            tcp_flags="SYN",
        ),
        build_event(
            "udp-smb",
            timestamp=FIXED_TIME,
            src_ip="192.0.2.40",
            dst_ip="198.51.100.91",
            dst_port=445,
            protocol="UDP",
            action="block",
        ),
    ]

    signal = SmbProbeRule().evaluate(
        [*invalid_events, *valid_events],
        DetectionContext(settings=_settings(), analysis_started_at=FIXED_TIME),
    )[0]

    assert set(signal.event_ids) == {event.event_id for event in valid_events}


@pytest.mark.parametrize(
    ("port", "identity"),
    [
        (3389, ("rdp_probe", "RDP Probe", "rdp_probe")),
        (22, ("ssh_probe", "SSH Probe", "ssh_probe")),
    ],
)
def test_existing_rdp_and_ssh_identities_remain_unchanged(
    port: int,
    identity: tuple[str, str, str],
) -> None:
    events = _probe_events(port, prefix="existing-remote")
    rule = RemoteServiceProbeRule()
    signals = rule.evaluate(
        events,
        DetectionContext(
            settings=_settings(
                REMOTE_SERVICE_MIN_EVENTS=3,
                REMOTE_SERVICE_MIN_DISTINCT_TARGETS=3,
            ),
            analysis_started_at=FIXED_TIME,
        ),
    )

    assert len(signals) == 1
    assert (signals[0].rule_id, signals[0].rule_name, signals[0].signal_type) == identity


def test_existing_multi_service_sweep_remains_functional() -> None:
    ports = [22, 3389, 445, 5985]
    events = [
        build_event(
            f"multi-service-{index}",
            timestamp=FIXED_TIME + timedelta(seconds=index),
            src_ip="192.0.2.50",
            dst_ip=f"198.51.100.{index + 1}",
            dst_port=port,
            protocol="TCP",
            action="block",
            tcp_flags="SYN",
        )
        for index, port in enumerate(ports)
    ]
    rule = MultiServiceSweepRule()
    signals = rule.evaluate(
        events,
        DetectionContext(
            settings=_settings(
                MULTI_SERVICE_SWEEP_MIN_EVENTS=4,
                MULTI_SERVICE_SWEEP_MIN_DISTINCT_SERVICES=3,
                MULTI_SERVICE_SWEEP_MIN_DISTINCT_TARGETS=3,
            ),
            analysis_started_at=FIXED_TIME,
        ),
    )

    assert len(signals) == 1
    assert signals[0].signal_type == "multi_service_sweep"


def test_smb_precedence_absorbs_only_generic_horizontal_scan() -> None:
    registry = RuleRegistry()
    registry.register(SmbProbeRule())
    registry.register(HorizontalScanRule())
    registry.register(RepeatedBlockedScannerRule())
    events = _probe_events(445, prefix="precedence-smb")
    settings = _settings(
        HORIZONTAL_SCAN_MIN_EVENTS=3,
        HORIZONTAL_SCAN_MIN_DISTINCT_TARGETS=3,
        REPEATED_BLOCKED_SCANNER_MIN_EVENTS=3,
        REPEATED_BLOCKED_SCANNER_MIN_DISTINCT_TARGETS=2,
    )

    result = DetectionEngine(registry=registry, settings=settings).analyze(events)

    assert {signal.signal_type for signal in result.signals} == {
        "smb_probe",
        "repeated_blocked_scanner",
    }


def test_new_default_probe_pack_makes_zero_provider_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("provider or agent invocation is forbidden during detection")

    monkeypatch.setattr("agent.triage.runner.TriageRunner.run", fail_if_called)
    register_default_rules()

    result = DetectionEngine(settings=_settings()).analyze(
        _probe_events(445, prefix="provider-free-smb")
    )

    assert any(signal.signal_type == "smb_probe" for signal in result.signals)
