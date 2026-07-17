from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_address
import json
import math
from typing import Any, cast, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent.archive.schemas import safe_string_list, safe_text
from agent.persistence.orm_models import CanonicalEvent, DetectionSignal, Incident


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _text(value: Any, *, max_length: int) -> str | None:
    return safe_text(value, max_length=max_length)


def _required_text(value: Any, *, max_length: int) -> str:
    normalized = _text(value, max_length=max_length)
    if normalized is None:
        raise ValueError("opensearch_document_identifier_invalid")
    return normalized


def _normalized_ip(value: Any) -> str | None:
    normalized = _text(value, max_length=64)
    if normalized is None:
        return None
    try:
        return str(ip_address(normalized))
    except ValueError:
        return None


class SafeSearchDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(pattern=r"^v[1-9][0-9]{0,5}$")
    entity_type: str
    entity_id: str = Field(min_length=1, max_length=256)
    document_version: int = Field(ge=1)
    indexed_at: datetime
    source_updated_at: datetime

    @field_validator("indexed_at", "source_updated_at", mode="before")
    @classmethod
    def normalize_timestamps(cls, value: datetime) -> datetime:
        if not isinstance(value, datetime):
            raise ValueError("opensearch_document_timestamp_invalid")
        return _utc(value)


class CanonicalEventSearchDocument(SafeSearchDocument):
    entity_type: Literal["canonical_event"] = "canonical_event"
    event_id: str
    timestamp: datetime
    observed_at: datetime | None = None
    source_name: str | None = None
    parser_name: str | None = None
    parser_version: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = Field(default=None, ge=0, le=65_535)
    dst_port: int | None = Field(default=None, ge=0, le=65_535)
    protocol: str | None = None
    action: str | None = None
    user: str | None = None
    safe_message_excerpt: str | None = None
    job_ids: tuple[str, ...] = ()
    incident_ids: tuple[str, ...] = ()
    context_incident_ids: tuple[str, ...] = ()

    @field_validator("timestamp", "observed_at", mode="before")
    @classmethod
    def normalize_event_timestamps(cls, value: datetime | None) -> datetime | None:
        return _utc(value) if isinstance(value, datetime) else value

    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def normalize_ips(cls, value: Any) -> str | None:
        return _normalized_ip(value)


class DetectionSignalSearchDocument(SafeSearchDocument):
    entity_type: Literal["detection_signal"] = "detection_signal"
    signal_id: str
    rule_id: str | None = None
    rule_name: str | None = None
    rule_version: str | None = None
    signal_type: str | None = None
    signal_family: str | None = None
    severity: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    created_at: datetime
    suppressed: bool
    suppression_reason: str | None = None
    mitre_techniques: tuple[str, ...] = ()
    target_entities: tuple[str, ...] = ()
    job_ids: tuple[str, ...] = ()
    incident_ids: tuple[str, ...] = ()

    @field_validator("first_seen", "last_seen", "created_at", mode="before")
    @classmethod
    def normalize_signal_timestamps(cls, value: datetime | None) -> datetime | None:
        return _utc(value) if isinstance(value, datetime) else value

    @field_validator("confidence")
    @classmethod
    def finite_confidence(cls, value: float | None) -> float | None:
        if value is not None and not math.isfinite(value):
            raise ValueError("opensearch_document_non_finite")
        return value


class IncidentSearchDocument(SafeSearchDocument):
    entity_type: Literal["incident"] = "incident"
    incident_id: str
    title: str | None = None
    incident_type: str | None = None
    incident_family: str | None = None
    status: str | None = None
    severity: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    version: int = Field(ge=1)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime
    primary_entity: str | None = None
    target_entities: tuple[str, ...] = ()
    mitre_techniques: tuple[str, ...] = ()
    job_ids: tuple[str, ...] = ()
    has_report: bool = False
    has_validated_evidence: bool = False

    @field_validator(
        "first_seen",
        "last_seen",
        "created_at",
        "updated_at",
        mode="before",
    )
    @classmethod
    def normalize_incident_timestamps(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        return _utc(value) if isinstance(value, datetime) else value

    @field_validator("confidence")
    @classmethod
    def finite_incident_confidence(cls, value: float | None) -> float | None:
        if value is not None and not math.isfinite(value):
            raise ValueError("opensearch_document_non_finite")
        return value


SearchDocument = (
    CanonicalEventSearchDocument
    | DetectionSignalSearchDocument
    | IncidentSearchDocument
)


def canonical_event_document(
    row: CanonicalEvent,
    *,
    schema_version: str,
    indexed_at: datetime,
    job_ids: tuple[str, ...] = (),
    incident_ids: tuple[str, ...] = (),
    context_incident_ids: tuple[str, ...] = (),
) -> CanonicalEventSearchDocument:
    row_timestamp = cast(datetime | None, row.timestamp)
    observed_at = cast(datetime | None, row.observed_at)
    timestamp = row_timestamp or observed_at or indexed_at
    event_id = _required_text(row.event_id, max_length=256)
    return CanonicalEventSearchDocument(
        schema_version=schema_version,
        entity_id=event_id,
        document_version=1,
        indexed_at=indexed_at,
        source_updated_at=timestamp,
        event_id=event_id,
        timestamp=timestamp,
        observed_at=observed_at,
        source_name=_text(row.source_name, max_length=256),
        parser_name=_text(row.parser_name, max_length=128),
        parser_version=_text(row.parser_version, max_length=64),
        src_ip=_normalized_ip(row.src_ip),
        dst_ip=_normalized_ip(row.dst_ip),
        src_port=cast(int | None, row.src_port),
        dst_port=cast(int | None, row.dst_port),
        protocol=_text(row.protocol, max_length=32),
        action=_text(row.action, max_length=64),
        user=_text(row.user, max_length=256),
        safe_message_excerpt=_text(row.safe_message_excerpt, max_length=1_024),
        job_ids=tuple(safe_string_list(job_ids)),
        incident_ids=tuple(safe_string_list(incident_ids)),
        context_incident_ids=tuple(safe_string_list(context_incident_ids)),
    )


def detection_signal_document(
    row: DetectionSignal,
    *,
    schema_version: str,
    indexed_at: datetime,
    job_ids: tuple[str, ...] = (),
    incident_ids: tuple[str, ...] = (),
) -> DetectionSignalSearchDocument:
    created_at = cast(datetime | None, row.created_at) or indexed_at
    signal_id = _required_text(row.signal_id, max_length=256)
    confidence = float(row.confidence) if row.confidence is not None else None
    return DetectionSignalSearchDocument(
        schema_version=schema_version,
        entity_id=signal_id,
        document_version=1,
        indexed_at=indexed_at,
        source_updated_at=created_at,
        signal_id=signal_id,
        rule_id=_text(row.rule_id, max_length=128),
        rule_name=_text(row.rule_name, max_length=256),
        rule_version=_text(row.rule_version, max_length=64),
        signal_type=_text(row.signal_type, max_length=128),
        signal_family=_text(row.signal_family, max_length=128),
        severity=_text(row.severity, max_length=32),
        confidence=confidence,
        first_seen=cast(datetime | None, row.first_seen),
        last_seen=cast(datetime | None, row.last_seen),
        created_at=created_at,
        suppressed=bool(row.suppressed),
        suppression_reason=_text(row.suppression_reason, max_length=256),
        mitre_techniques=tuple(safe_string_list(row.mitre_techniques)),
        target_entities=tuple(safe_string_list(row.target_entities)),
        job_ids=tuple(safe_string_list(job_ids)),
        incident_ids=tuple(safe_string_list(incident_ids)),
    )


def incident_document(
    row: Incident,
    *,
    schema_version: str,
    indexed_at: datetime,
    job_ids: tuple[str, ...] = (),
    has_report: bool = False,
    has_validated_evidence: bool = False,
) -> IncidentSearchDocument:
    created_at = cast(datetime | None, row.created_at)
    updated_at = cast(datetime | None, row.updated_at) or created_at or indexed_at
    incident_id = _required_text(row.incident_id, max_length=256)
    confidence = float(row.confidence) if row.confidence is not None else None
    version = max(1, int(row.version or 1))
    return IncidentSearchDocument(
        schema_version=schema_version,
        entity_id=incident_id,
        document_version=version,
        indexed_at=indexed_at,
        source_updated_at=updated_at,
        incident_id=incident_id,
        title=_text(row.title, max_length=512),
        incident_type=_text(row.incident_type, max_length=128),
        incident_family=_text(row.incident_family, max_length=128),
        status=_text(row.status, max_length=32),
        severity=_text(row.severity, max_length=32),
        confidence=confidence,
        version=version,
        first_seen=cast(datetime | None, row.first_seen),
        last_seen=cast(datetime | None, row.last_seen),
        created_at=created_at,
        updated_at=updated_at,
        primary_entity=_text(row.primary_entity, max_length=256),
        target_entities=tuple(safe_string_list(row.target_entities)),
        mitre_techniques=tuple(safe_string_list(row.mitre_techniques)),
        job_ids=tuple(safe_string_list(job_ids)),
        has_report=has_report,
        has_validated_evidence=has_validated_evidence,
    )


def deterministic_document_json(document: SearchDocument) -> str:
    return json.dumps(
        document.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
