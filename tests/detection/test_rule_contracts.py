from datetime import timedelta

import pytest
from pydantic import ValidationError

from agent.detection.config import DetectionSettings
from agent.detection.contracts import (
    DetectionRuleMetadata,
    DetectionSignalVariant,
    RuleContractError,
    event_has_required_fields,
    select_rule_events,
    validate_signal_contract,
)
from agent.detection.detectors import register_default_rules
from agent.detection.detectors.base import BaseDetectionRule
from agent.detection.detectors.remote_service_probe import RemoteServiceProbeRule
from agent.detection.models import DetectionEvidence, DetectionSignal
from agent.detection.registry import default_registry
from agent.schema import CanonicalLogEvent
from tests.detection.helpers import FIXED_TIME, build_event


def make_metadata(**overrides: object) -> DetectionRuleMetadata:
    values: dict[str, object] = {
        "rule_id": "contract_rule",
        "version": "1.0.0",
        "name": "Contract Rule",
        "family": "contract_tests",
        "priority": 500,
        "supported_event_types": (),
        "required_fields": (),
        "signal_type": "contract_signal",
        "signal_variants": (),
        "default_severity": "low",
        "mitre_techniques": (),
        "window_setting": None,
        "minimum_events_setting": None,
    }
    values.update(overrides)
    return DetectionRuleMetadata.model_validate(values)


class ContractRule(BaseDetectionRule):
    metadata = make_metadata()

    def evaluate(self, events, context):
        return []


def make_signal(**overrides: object) -> DetectionSignal:
    values: dict[str, object] = {
        "signal_id": "SIG-CONTRACT",
        "rule_id": ContractRule.metadata.rule_id,
        "rule_version": ContractRule.metadata.version,
        "rule_name": ContractRule.metadata.name,
        "signal_type": ContractRule.metadata.signal_type,
        "signal_family": ContractRule.metadata.family,
        "severity": "low",
        "confidence": 0.75,
        "first_seen": FIXED_TIME,
        "last_seen": FIXED_TIME,
        "event_ids": ["event-1"],
        "primary_entity": "192.0.2.10",
        "target_entities": ["198.51.100.20"],
        "metrics": {"event_count": 1},
        "evidence": [],
        "mitre_techniques": [],
        "tags": ["test"],
    }
    values.update(overrides)
    return DetectionSignal.model_validate(values)


def test_all_default_rules_have_valid_deterministic_metadata() -> None:
    for rule in list(default_registry.get_all_rules()):
        default_registry.unregister(rule.rule_id)
    register_default_rules()
    first = [item.model_dump(mode="json") for item in default_registry.list_rule_metadata()]
    register_default_rules()
    second = [item.model_dump(mode="json") for item in default_registry.list_rule_metadata()]

    assert len(first) == 29
    assert first == second
    assert len({item["rule_id"] for item in first}) == 29
    for item in default_registry.list_rule_metadata():
        assert item.name and item.family and item.signal_type
        assert all(field in CanonicalLogEvent.model_fields for field in item.required_fields)
        if item.window_setting:
            assert item.window_setting in DetectionSettings.model_fields
        if item.minimum_events_setting:
            assert item.minimum_events_setting in DetectionSettings.model_fields


@pytest.mark.parametrize("rule_id", ["Horizontal Scan", "horizontal-scan", ""])
def test_invalid_rule_identifiers_are_rejected(rule_id: str) -> None:
    with pytest.raises(ValidationError):
        make_metadata(rule_id=rule_id)


def test_invalid_canonical_field_and_setting_are_rejected() -> None:
    with pytest.raises(ValidationError, match="field_that_does_not_exist"):
        make_metadata(required_fields=("field_that_does_not_exist",))
    with pytest.raises(ValidationError, match="MISSING_SETTING"):
        make_metadata(window_setting="MISSING_SETTING")


def test_rule_event_selection_preserves_order_and_missing_semantics() -> None:
    metadata = make_metadata(
        supported_event_types=("network",),
        required_fields=("src_ip", "dst_port"),
    )
    zero_port = build_event("zero", dst_port=0)
    missing = build_event("missing", dst_ip=None)
    authentication = build_event("auth", event_type="authentication")
    blank = build_event("blank", src_ip="")

    selected = select_rule_events([zero_port, missing, authentication, blank], metadata)
    assert [event.event_id for event in selected] == ["zero", "missing"]
    assert event_has_required_fields(zero_port, ("dst_port",))


def test_empty_supported_types_accept_missing_event_type() -> None:
    event = build_event(event_type=None)
    assert select_rule_events([event], make_metadata()) == [event]


def test_valid_signal_contract_passes() -> None:
    validate_signal_contract(make_signal(), ContractRule(), {"event-1"})


def test_signal_variants_are_immutable_deterministic_and_duplicate_free() -> None:
    ssh = DetectionSignalVariant(
        rule_id="ssh_probe",
        rule_name="SSH Probe",
        signal_type="ssh_probe",
    )
    rdp = DetectionSignalVariant(
        rule_id="rdp_probe",
        rule_name="RDP Probe",
        signal_type="rdp_probe",
    )

    metadata = make_metadata(signal_variants=(ssh, rdp))

    assert metadata.signal_variants == (rdp, ssh)
    with pytest.raises(ValidationError, match="duplicate-free"):
        make_metadata(signal_variants=(rdp, rdp))


def test_undeclared_remote_service_variant_is_rejected() -> None:
    rule = RemoteServiceProbeRule()
    signal = make_signal(
        rule_id="telnet_probe",
        rule_name="TELNET Probe",
        signal_type="telnet_probe",
        signal_family=rule.family,
    )

    with pytest.raises(RuleContractError, match="undeclared_signal_variant"):
        validate_signal_contract(signal, rule, {"event-1"})


def test_rule_without_signal_variants_remains_strict() -> None:
    assert ContractRule.metadata.signal_variants == ()
    with pytest.raises(RuleContractError, match="signal_type_mismatch"):
        validate_signal_contract(
            make_signal(signal_type="another_signal"),
            ContractRule(),
            {"event-1"},
        )


@pytest.mark.parametrize(
    ("overrides", "category"),
    [
        ({"rule_id": "another_rule"}, "rule_id_mismatch"),
        ({"rule_version": "2.0.0"}, "rule_version_mismatch"),
        ({"rule_name": "Another Rule"}, "rule_name_mismatch"),
        ({"signal_type": "another_signal"}, "signal_type_mismatch"),
        ({"event_ids": ["foreign"]}, "foreign_event_id"),
        ({"event_ids": []}, "empty_event_ids"),
    ],
)
def test_invalid_signal_contract_is_rejected(overrides: dict[str, object], category: str) -> None:
    with pytest.raises(RuleContractError, match=category):
        validate_signal_contract(make_signal(**overrides), ContractRule(), {"event-1"})


def test_foreign_evidence_is_rejected() -> None:
    evidence = DetectionEvidence(
        event_id="foreign",
        quote="safe",
        reason="test",
        source="contract_rule",
        original_fields={},
        correlation_context={},
    )
    with pytest.raises(RuleContractError, match="evidence_not_in_signal_events"):
        validate_signal_contract(make_signal(evidence=[evidence]), ContractRule(), {"event-1"})


def test_detection_signal_model_rejects_invalid_time_range() -> None:
    with pytest.raises(ValidationError, match="first_seen"):
        make_signal(first_seen=FIXED_TIME + timedelta(seconds=1))
