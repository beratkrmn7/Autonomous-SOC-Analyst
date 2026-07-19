import re
from collections.abc import Sequence
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent.detection.config import DetectionSettings
from agent.detection.models import DetectionSignal, SeverityType
from agent.schema import CanonicalLogEvent

if TYPE_CHECKING:
    from agent.detection.detectors.base import BaseDetectionRule


_IDENTIFIER_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
_VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")


class RuleContractError(ValueError):
    """Raised when a detection rule or signal violates its declared contract."""


class DetectionSignalVariant(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(max_length=100)
    rule_name: str = Field(max_length=200)
    signal_type: str = Field(max_length=100)

    @field_validator("rule_id", "signal_type")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if not _IDENTIFIER_PATTERN.fullmatch(value):
            raise ValueError("must be a non-empty lowercase snake-case identifier")
        return value

    @field_validator("rule_name")
    @classmethod
    def validate_rule_name(cls, value: str) -> str:
        if not value.strip() or "\n" in value or "\r" in value:
            raise ValueError("must be non-empty and must not contain newlines")
        return value


class DetectionRuleMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(max_length=100)
    version: str = Field(max_length=32)
    name: str = Field(max_length=200)
    family: str = Field(max_length=100)
    priority: int = Field(strict=True, ge=0, le=10_000)
    supported_event_types: tuple[str, ...] = ()
    required_fields: tuple[str, ...] = ()
    signal_type: str = Field(max_length=100)
    signal_variants: tuple[DetectionSignalVariant, ...] = ()
    default_severity: SeverityType
    mitre_techniques: tuple[str, ...] = ()
    window_setting: str | None = None
    minimum_events_setting: str | None = None

    @field_validator("rule_id", "family", "signal_type")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        if not _IDENTIFIER_PATTERN.fullmatch(value):
            raise ValueError("must be a non-empty lowercase snake-case identifier")
        return value

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        if not _VERSION_PATTERN.fullmatch(value):
            raise ValueError("must use numeric semantic version format (for example 1.0.0)")
        return value

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not value.strip() or "\n" in value or "\r" in value:
            raise ValueError("must be non-empty and must not contain newlines")
        return value

    @field_validator("supported_event_types", "mitre_techniques")
    @classmethod
    def validate_unique_values(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not item or item != item.strip() for item in value):
            raise ValueError("values must be non-empty and must not contain surrounding whitespace")
        if len(value) != len(set(value)):
            raise ValueError("values must be duplicate-free")
        return tuple(sorted(value))

    @field_validator("required_fields")
    @classmethod
    def validate_required_fields(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("required_fields must be duplicate-free")
        canonical_fields = set(CanonicalLogEvent.model_fields)
        for field_name in value:
            if field_name.startswith("_") or "." in field_name or field_name not in canonical_fields:
                raise ValueError(f"unknown canonical event field: {field_name}")
        return tuple(sorted(value))

    @field_validator("signal_variants")
    @classmethod
    def validate_signal_variants(
        cls,
        value: tuple[DetectionSignalVariant, ...],
    ) -> tuple[DetectionSignalVariant, ...]:
        identities = [
            (variant.rule_id, variant.rule_name, variant.signal_type)
            for variant in value
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("signal_variants must be duplicate-free")
        return tuple(
            sorted(
                value,
                key=lambda variant: (
                    variant.rule_id,
                    variant.rule_name,
                    variant.signal_type,
                ),
            )
        )

    @field_validator("window_setting", "minimum_events_setting")
    @classmethod
    def validate_setting_reference(cls, value: str | None) -> str | None:
        if value is not None and value not in DetectionSettings.model_fields:
            raise ValueError(f"unknown detection setting: {value}")
        return value


def event_has_required_fields(
    event: CanonicalLogEvent,
    required_fields: Sequence[str],
) -> bool:
    for field_name in required_fields:
        value = getattr(event, field_name, None)
        if value is None or (isinstance(value, str) and not value.strip()):
            return False
    return True


def select_rule_events(
    events: Sequence[CanonicalLogEvent],
    metadata: DetectionRuleMetadata,
) -> list[CanonicalLogEvent]:
    supported_types = set(metadata.supported_event_types)
    return [
        event
        for event in events
        if (not supported_types or event.event_type in supported_types)
        and event_has_required_fields(event, metadata.required_fields)
    ]


def validate_signal_contract(
    signal: DetectionSignal,
    rule: "BaseDetectionRule",
    input_event_ids: set[str],
) -> None:
    metadata = rule.metadata
    if metadata.signal_variants:
        signal_identity = (signal.rule_id, signal.rule_name, signal.signal_type)
        permitted_identities = {
            (variant.rule_id, variant.rule_name, variant.signal_type)
            for variant in metadata.signal_variants
        }
        if signal_identity not in permitted_identities:
            raise RuleContractError("undeclared_signal_variant")
    else:
        identity_checks = {
            "rule_id_mismatch": signal.rule_id == metadata.rule_id,
            "rule_name_mismatch": signal.rule_name == metadata.name,
            "signal_type_mismatch": signal.signal_type == metadata.signal_type,
        }
        for category, valid in identity_checks.items():
            if not valid:
                raise RuleContractError(category)
    common_identity_checks = {
        "rule_version_mismatch": signal.rule_version == metadata.version,
        "signal_family_mismatch": signal.signal_family == metadata.family,
    }
    for category, valid in common_identity_checks.items():
        if not valid:
            raise RuleContractError(category)
    if signal.severity not in {"informational", "low", "medium", "high", "critical"}:
        raise RuleContractError("invalid_severity")
    if not signal.event_ids:
        raise RuleContractError("empty_event_ids")
    if not set(signal.event_ids).issubset(input_event_ids):
        raise RuleContractError("foreign_event_id")
    if any(evidence.event_id not in signal.event_ids for evidence in signal.evidence):
        raise RuleContractError("evidence_not_in_signal_events")
    if signal.first_seen > signal.last_seen:
        raise RuleContractError("invalid_time_range")
    if not isinstance(signal.primary_entity, str) or not signal.primary_entity.strip():
        raise RuleContractError("empty_primary_entity")
    if len(signal.event_ids) != len(set(signal.event_ids)):
        raise RuleContractError("duplicate_event_ids")
    evidence_ids = [item.event_id for item in signal.evidence]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise RuleContractError("duplicate_evidence_event_ids")
    for category, values in (
        ("duplicate_target_entities", signal.target_entities),
        ("duplicate_mitre_techniques", signal.mitre_techniques),
        ("duplicate_tags", signal.tags),
    ):
        if len(values) != len(set(values)):
            raise RuleContractError(category)
