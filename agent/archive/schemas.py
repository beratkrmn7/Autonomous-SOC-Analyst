from __future__ import annotations

from datetime import datetime, timezone
import json
import math
import re
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


ARCHIVE_RECORD_SCHEMA_VERSION: Literal[
    "retention-archive/v1"
] = "retention-archive/v1"
ARCHIVE_MANIFEST_SCHEMA_VERSION: Literal[
    "retention-archive-manifest/v1"
] = "retention-archive-manifest/v1"
ARCHIVE_SAFETY_PROFILE: Literal["safe-operational/v1"] = "safe-operational/v1"
ARCHIVE_ID_PATTERN = re.compile(r"^ARC-[0-9a-f]{32}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MAX_ARCHIVE_LINE_BYTES = 65_536
MAX_MANIFEST_BYTES = 1_048_576

ArchiveRole = Literal["retention_candidate", "dependency"]
ArchiveEntityType = Literal[
    "canonical_event",
    "detection_signal",
    "ingestion_job",
    "incident",
    "audit_event",
    "triage_run",
    "evidence_item",
    "report",
    "incident_event_association",
    "incident_signal_association",
    "job_event_association",
    "job_signal_association",
    "job_incident_association",
]

ROOT_ENTITY_TYPES = frozenset(
    {
        "canonical_event",
        "detection_signal",
        "ingestion_job",
        "incident",
        "audit_event",
    }
)
EXPECTED_PAYLOAD_FILES = (
    "canonical_events.ndjson.gz",
    "detection_signals.ndjson.gz",
    "ingestion_jobs.ndjson.gz",
    "incidents.ndjson.gz",
    "audit_events.ndjson.gz",
    "dependent_records.ndjson.gz",
)

_SENSITIVE_TEXT = re.compile(
    r"(?i)(?:authorization\s*:|bearer\s+[a-z0-9._~+/=-]+|"
    r"api[_ -]?key\s*[:=]|password\s*[:=]|"
    r"opensearch(?:[_ -]?url)?\s*[:=]|"
    r"soc_[a-z0-9_-]{20,}|(?:[a-z]:[\\/]|/(?:home|root|srv|tmp|var)/)|"
    r"(?:postgres(?:ql)?|mysql|mariadb|redis)://|sqlite:///|"
    r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+|"
    r"provider\s+prompt|prompt\s+secret|super[-_ ]?secret|"
    r"raw\s+exception\s+secret)"
)
_CONTROL_TEXT = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def safe_text(value: Any, *, max_length: int = 256) -> str | None:
    if value is None:
        return None
    normalized = _CONTROL_TEXT.sub(" ", str(value)).strip()
    if not normalized:
        return None
    if _SENSITIVE_TEXT.search(normalized):
        return "[redacted]"
    return normalized[:max_length]


def safe_string_list(value: Any, *, limit: int = 100) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    result: list[str] = []
    for item in value[:limit]:
        sanitized = safe_text(item)
        if sanitized is not None and sanitized not in result:
            result.append(sanitized)
    return result


def validate_archive_id(archive_id: str) -> str:
    if not ARCHIVE_ID_PATTERN.fullmatch(archive_id):
        raise ValueError("archive_id_invalid")
    return archive_id


def _reject_unsafe_strings(value: Any) -> None:
    if isinstance(value, str):
        if _CONTROL_TEXT.search(value) or _SENSITIVE_TEXT.search(value):
            raise ValueError("archive_data_unsafe")
        return
    if isinstance(value, dict):
        for nested in value.values():
            _reject_unsafe_strings(nested)
        return
    if isinstance(value, (list, tuple)):
        for nested in value:
            _reject_unsafe_strings(nested)
        return
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("archive_data_non_finite")


class ArchiveDataModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_safe_values(self) -> ArchiveDataModel:
        _reject_unsafe_strings(self.model_dump(mode="python"))
        return self


class CanonicalEventArchiveData(ArchiveDataModel):
    source_name: str | None = Field(default=None, max_length=256)
    parser_name: str | None = Field(default=None, max_length=128)
    parser_version: str | None = Field(default=None, max_length=64)
    timestamp: datetime
    observed_at: datetime | None = None
    source_line: int | None = Field(default=None, ge=0)
    src_ip: str | None = Field(default=None, max_length=64)
    dst_ip: str | None = Field(default=None, max_length=64)
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=32)
    action: str | None = Field(default=None, max_length=64)
    user: str | None = Field(default=None, max_length=256)


class DetectionSignalArchiveData(ArchiveDataModel):
    rule_id: str | None = Field(default=None, max_length=128)
    rule_name: str | None = Field(default=None, max_length=256)
    rule_version: str | None = Field(default=None, max_length=64)
    signal_family: str | None = Field(default=None, max_length=128)
    signal_type: str | None = Field(default=None, max_length=128)
    severity: str | None = Field(default=None, max_length=32)
    confidence: float | None = Field(default=None, ge=0, le=1)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    created_at: datetime
    suppressed: bool
    mitre_techniques: list[str] = Field(default_factory=list, max_length=100)
    target_entities: list[str] = Field(default_factory=list, max_length=100)


class IngestionJobArchiveData(ArchiveDataModel):
    source_name: str | None = Field(default=None, max_length=256)
    file_sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")
    pipeline_version: str | None = Field(default=None, max_length=64)
    analysis_mode: str | None = Field(default=None, max_length=64)
    status: str | None = Field(default=None, max_length=32)
    error_code: str | None = Field(default=None, max_length=128)
    input_format: str | None = Field(default=None, max_length=64)
    created_at: datetime | None = None
    updated_at: datetime | None = None
    queued_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime
    attempt_count: int = Field(default=0, ge=0)
    reused_count: int = Field(default=0, ge=0)
    total_records: int = Field(default=0, ge=0)
    parsed_records: int = Field(default=0, ge=0)
    failed_records: int = Field(default=0, ge=0)
    unsupported_records: int = Field(default=0, ge=0)
    semantically_invalid_records: int = Field(default=0, ge=0)
    skipped_records: int = Field(default=0, ge=0)
    bytes_read: int = Field(default=0, ge=0)
    duration_ms: int = Field(default=0, ge=0)
    cancel_requested_at: datetime | None = None
    cancelled_at: datetime | None = None
    cancel_reason_code: str | None = Field(default=None, max_length=128)


class IncidentArchiveData(ArchiveDataModel):
    title: str | None = Field(default=None, max_length=512)
    incident_type: str | None = Field(default=None, max_length=128)
    incident_family: str | None = Field(default=None, max_length=128)
    status: str | None = Field(default=None, max_length=32)
    severity: str | None = Field(default=None, max_length=32)
    confidence: float | None = Field(default=None, ge=0, le=1)
    version: int = Field(default=1, ge=1)
    merge_key: str | None = Field(default=None, max_length=256)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime
    primary_entity: str | None = Field(default=None, max_length=256)
    target_entities: list[str] = Field(default_factory=list, max_length=100)
    mitre_techniques: list[str] = Field(default_factory=list, max_length=100)


class AuditEventArchiveData(ArchiveDataModel):
    incident_id: str | None = Field(default=None, max_length=256)
    timestamp: datetime
    event_type: str | None = Field(default=None, max_length=128)
    entity_type: str | None = Field(default=None, max_length=128)
    entity_id: str | None = Field(default=None, max_length=256)
    action: str | None = Field(default=None, max_length=128)
    old_status: str | None = Field(default=None, max_length=64)
    new_status: str | None = Field(default=None, max_length=64)
    actor_type: str | None = Field(default=None, max_length=64)
    actor_id: str | None = Field(default=None, max_length=256)
    request_id: str | None = Field(default=None, max_length=128)


class TriageRunArchiveData(ArchiveDataModel):
    source_database_id: int = Field(ge=1)
    job_id: str | None = Field(default=None, max_length=256)
    incident_id: str | None = Field(default=None, max_length=256)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    status: str | None = Field(default=None, max_length=32)
    provider: str | None = Field(default=None, max_length=64)
    model: str | None = Field(default=None, max_length=128)
    prompt_version: str | None = Field(default=None, max_length=64)
    schema_version: str | None = Field(default=None, max_length=64)
    verdict: str | None = Field(default=None, max_length=64)
    severity: str | None = Field(default=None, max_length=32)
    confidence_score: float | None = Field(default=None, ge=0, le=1)
    incident_type: str | None = Field(default=None, max_length=128)
    cache_hit: bool
    iteration_count: int = Field(default=0, ge=0)
    search_count: int = Field(default=0, ge=0)
    tool_count: int = Field(default=0, ge=0)
    retry_count: int = Field(default=0, ge=0)
    latency_ms: int = Field(default=0, ge=0)
    estimated_cost: float = Field(default=0, ge=0)


class EvidenceItemArchiveData(ArchiveDataModel):
    job_id: str | None = Field(default=None, max_length=256)
    incident_id: str | None = Field(default=None, max_length=256)
    triage_run_id: int | None = Field(default=None, ge=1)
    event_id: str | None = Field(default=None, max_length=256)
    reason: str | None = Field(default=None, max_length=256)
    source: str | None = Field(default=None, max_length=128)
    validation_status: str | None = Field(default=None, max_length=64)
    rejection_reason: str | None = Field(default=None, max_length=256)


class ReportArchiveData(ArchiveDataModel):
    job_id: str | None = Field(default=None, max_length=256)
    incident_id: str | None = Field(default=None, max_length=256)
    triage_run_id: int | None = Field(default=None, ge=1)
    generated_at: datetime | None = None
    format: str | None = Field(default=None, max_length=32)
    content_sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")


class IncidentEventAssociationArchiveData(ArchiveDataModel):
    incident_id: str = Field(min_length=1, max_length=256)
    event_id: str = Field(min_length=1, max_length=256)
    is_context: bool


class IncidentSignalAssociationArchiveData(ArchiveDataModel):
    incident_id: str = Field(min_length=1, max_length=256)
    signal_id: str = Field(min_length=1, max_length=256)


class JobEventAssociationArchiveData(ArchiveDataModel):
    job_id: str = Field(min_length=1, max_length=256)
    event_id: str = Field(min_length=1, max_length=256)


class JobSignalAssociationArchiveData(ArchiveDataModel):
    job_id: str = Field(min_length=1, max_length=256)
    signal_id: str = Field(min_length=1, max_length=256)


class JobIncidentAssociationArchiveData(ArchiveDataModel):
    job_id: str = Field(min_length=1, max_length=256)
    incident_id: str = Field(min_length=1, max_length=256)


DATA_MODELS: dict[str, type[ArchiveDataModel]] = {
    "canonical_event": CanonicalEventArchiveData,
    "detection_signal": DetectionSignalArchiveData,
    "ingestion_job": IngestionJobArchiveData,
    "incident": IncidentArchiveData,
    "audit_event": AuditEventArchiveData,
    "triage_run": TriageRunArchiveData,
    "evidence_item": EvidenceItemArchiveData,
    "report": ReportArchiveData,
    "incident_event_association": IncidentEventAssociationArchiveData,
    "incident_signal_association": IncidentSignalAssociationArchiveData,
    "job_event_association": JobEventAssociationArchiveData,
    "job_signal_association": JobSignalAssociationArchiveData,
    "job_incident_association": JobIncidentAssociationArchiveData,
}


class ArchiveRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["retention-archive/v1"] = ARCHIVE_RECORD_SCHEMA_VERSION
    entity_type: ArchiveEntityType
    entity_id: str = Field(min_length=1, max_length=512)
    archive_role: ArchiveRole
    recorded_at: datetime
    data: dict[str, Any]

    @field_validator("recorded_at")
    @classmethod
    def validate_recorded_at(cls, value: datetime) -> datetime:
        return utc_datetime(value)

    @field_validator("entity_id")
    @classmethod
    def validate_entity_id(cls, value: str) -> str:
        _reject_unsafe_strings(value)
        return value

    @model_validator(mode="after")
    def validate_data_schema(self) -> ArchiveRecord:
        if self.archive_role == "retention_candidate" and (
            self.entity_type not in ROOT_ENTITY_TYPES
        ):
            raise ValueError("archive_candidate_entity_type_invalid")
        model = DATA_MODELS[self.entity_type].model_validate(self.data)
        object.__setattr__(
            self,
            "data",
            model.model_dump(mode="json", exclude_none=True),
        )
        return self


class ArchiveCutoffs(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    canonical_event: datetime
    detection_signal: datetime
    ingestion_job: datetime
    incident: datetime
    audit_event: datetime

    @field_validator("*")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return utc_datetime(value)


class ArchivePayloadManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    filename: str = Field(min_length=1, max_length=128)
    entity_types: tuple[ArchiveEntityType, ...] = Field(max_length=20)
    record_count: int = Field(ge=0)
    candidate_count: int = Field(ge=0)
    dependency_count: int = Field(ge=0)
    compressed_bytes: int = Field(ge=0)
    uncompressed_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    oldest_record_at: datetime | None = None
    newest_record_at: datetime | None = None

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value: str) -> str:
        if value not in EXPECTED_PAYLOAD_FILES:
            raise ValueError("archive_payload_filename_invalid")
        return value

    @field_validator("oldest_record_at", "newest_record_at")
    @classmethod
    def validate_optional_timestamp(cls, value: datetime | None) -> datetime | None:
        return utc_datetime(value) if value is not None else None

    @model_validator(mode="after")
    def validate_counts_and_range(self) -> ArchivePayloadManifest:
        if self.record_count != self.candidate_count + self.dependency_count:
            raise ValueError("archive_payload_count_mismatch")
        if self.record_count == 0:
            if self.oldest_record_at is not None or self.newest_record_at is not None:
                raise ValueError("archive_payload_empty_range_invalid")
        elif self.oldest_record_at is None or self.newest_record_at is None:
            raise ValueError("archive_payload_range_missing")
        elif self.oldest_record_at > self.newest_record_at:
            raise ValueError("archive_payload_range_invalid")
        return self


class ArchiveManifestV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[
        "retention-archive-manifest/v1"
    ] = ARCHIVE_MANIFEST_SCHEMA_VERSION
    archive_id: str
    policy_version: str = Field(min_length=1, max_length=32)
    created_at: datetime
    completed_at: datetime
    archive_as_of: datetime
    cutoffs: ArchiveCutoffs
    compression: Literal["gzip"] = "gzip"
    hash_algorithm: Literal["sha256"] = "sha256"
    archive_format: Literal["ndjson"] = "ndjson"
    producer_version: str = Field(min_length=1, max_length=64)
    payloads: tuple[ArchivePayloadManifest, ...] = Field(min_length=1, max_length=20)
    candidate_record_count: int = Field(ge=0)
    dependency_record_count: int = Field(ge=0)
    total_record_count: int = Field(ge=0)
    archive_safety_profile: Literal["safe-operational/v1"] = ARCHIVE_SAFETY_PROFILE
    contains_raw_logs: Literal[False] = False
    contains_credentials: Literal[False] = False

    expected_payload_files: ClassVar[tuple[str, ...]] = EXPECTED_PAYLOAD_FILES

    @field_validator("archive_id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        return validate_archive_id(value)

    @field_validator("created_at", "completed_at", "archive_as_of")
    @classmethod
    def validate_manifest_timestamp(cls, value: datetime) -> datetime:
        return utc_datetime(value)

    @model_validator(mode="after")
    def validate_manifest_totals(self) -> ArchiveManifestV1:
        filenames = tuple(payload.filename for payload in self.payloads)
        if filenames != self.expected_payload_files:
            raise ValueError("archive_manifest_payload_set_invalid")
        candidate_count = sum(payload.candidate_count for payload in self.payloads)
        dependency_count = sum(payload.dependency_count for payload in self.payloads)
        total_count = sum(payload.record_count for payload in self.payloads)
        if (
            candidate_count != self.candidate_record_count
            or dependency_count != self.dependency_record_count
            or total_count != self.total_record_count
            or total_count != candidate_count + dependency_count
        ):
            raise ValueError("archive_manifest_count_mismatch")
        if self.completed_at < self.created_at:
            raise ValueError("archive_manifest_time_order_invalid")
        return self


def canonical_json_bytes(model: BaseModel) -> bytes:
    return json.dumps(
        model.model_dump(mode="json", exclude_none=True),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
