from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from typing import Any, Literal

from agent.config import Settings
from agent.opensearch.models import OpenSearchIndexSettingsState


OpenSearchLogicalIndex = Literal[
    "canonical-events",
    "detection-signals",
    "incidents",
]
LOGICAL_INDEX_ORDER: tuple[OpenSearchLogicalIndex, ...] = (
    "canonical-events",
    "detection-signals",
    "incidents",
)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def mapping_without_declared_fingerprint(
    mapping: dict[str, Any],
) -> dict[str, Any]:
    normalized = deepcopy(mapping)
    metadata = normalized.get("_meta")
    if isinstance(metadata, dict):
        metadata.pop("mapping_fingerprint", None)
    return normalized


def mapping_fingerprint(mapping: dict[str, Any]) -> str:
    return _sha256(mapping_without_declared_fingerprint(mapping))


def settings_fingerprint(settings: dict[str, Any]) -> str:
    return _sha256(settings)


def definition_fingerprint(
    settings: dict[str, Any],
    mapping: dict[str, Any],
) -> str:
    return _sha256(
        {
            "settings": settings,
            "mappings": mapping_without_declared_fingerprint(mapping),
        }
    )


def _keyword(ignore_above: int = 256) -> dict[str, Any]:
    return {"type": "keyword", "ignore_above": ignore_above}


def _text_with_keyword(ignore_above: int = 256) -> dict[str, Any]:
    return {
        "type": "text",
        "fields": {"keyword": _keyword(ignore_above)},
    }


def _common_properties() -> dict[str, Any]:
    return {
        "schema_version": _keyword(16),
        "entity_type": _keyword(64),
        "entity_id": _keyword(),
        "document_version": {"type": "integer"},
        "indexed_at": {"type": "date"},
        "source_updated_at": {"type": "date"},
    }


def _event_properties() -> dict[str, Any]:
    return {
        **_common_properties(),
        "event_id": _keyword(),
        "timestamp": {"type": "date"},
        "observed_at": {"type": "date"},
        "source_name": _keyword(),
        "parser_name": _keyword(128),
        "parser_version": _keyword(64),
        "src_ip": {"type": "ip"},
        "dst_ip": {"type": "ip"},
        "src_port": {"type": "integer"},
        "dst_port": {"type": "integer"},
        "protocol": _keyword(32),
        "action": _keyword(64),
        "user": _keyword(),
        "safe_message_excerpt": {"type": "text"},
        "job_ids": _keyword(),
        "incident_ids": _keyword(),
        "context_incident_ids": _keyword(),
    }


def _signal_properties() -> dict[str, Any]:
    return {
        **_common_properties(),
        "signal_id": _keyword(),
        "rule_id": _keyword(128),
        "rule_name": _text_with_keyword(),
        "rule_version": _keyword(64),
        "signal_type": _keyword(128),
        "signal_family": _keyword(128),
        "severity": _keyword(32),
        "confidence": {"type": "float"},
        "first_seen": {"type": "date"},
        "last_seen": {"type": "date"},
        "created_at": {"type": "date"},
        "suppressed": {"type": "boolean"},
        "suppression_reason": {"type": "text"},
        "mitre_techniques": _keyword(128),
        "target_entities": _keyword(),
        "job_ids": _keyword(),
        "incident_ids": _keyword(),
    }


def _incident_properties() -> dict[str, Any]:
    return {
        **_common_properties(),
        "incident_id": _keyword(),
        "title": _text_with_keyword(),
        "incident_type": _keyword(128),
        "incident_family": _keyword(128),
        "status": _keyword(32),
        "severity": _keyword(32),
        "confidence": {"type": "float"},
        "version": {"type": "integer"},
        "first_seen": {"type": "date"},
        "last_seen": {"type": "date"},
        "created_at": {"type": "date"},
        "updated_at": {"type": "date"},
        "primary_entity": _keyword(),
        "target_entities": _keyword(),
        "mitre_techniques": _keyword(128),
        "job_ids": _keyword(),
        "has_report": {"type": "boolean"},
        "has_validated_evidence": {"type": "boolean"},
    }


@dataclass(frozen=True)
class OpenSearchIndexDefinition:
    logical_name: OpenSearchLogicalIndex
    schema_version: str
    physical_index_name: str
    read_alias: str
    write_alias: str
    settings: dict[str, Any]
    mapping: dict[str, Any]
    settings_fingerprint: str
    mapping_fingerprint: str
    fingerprint: str

    @property
    def expected_settings_state(self) -> OpenSearchIndexSettingsState:
        mapping_settings = self.settings["mapping"]
        return OpenSearchIndexSettingsState(
            number_of_shards=int(self.settings["number_of_shards"]),
            number_of_replicas=int(self.settings["number_of_replicas"]),
            total_fields_limit=int(mapping_settings["total_fields"]["limit"]),
        )

    def creation_body(self) -> dict[str, Any]:
        return {
            "settings": deepcopy(self.settings),
            "mappings": deepcopy(self.mapping),
        }


def build_index_definitions(
    settings: Settings,
) -> tuple[OpenSearchIndexDefinition, ...]:
    property_builders = {
        "canonical-events": _event_properties,
        "detection-signals": _signal_properties,
        "incidents": _incident_properties,
    }
    definitions: list[OpenSearchIndexDefinition] = []
    for logical_name in LOGICAL_INDEX_ORDER:
        index_settings: dict[str, Any] = {
            "number_of_shards": settings.opensearch_number_of_shards,
            "number_of_replicas": settings.opensearch_number_of_replicas,
            "mapping": {
                "total_fields": {
                    "limit": settings.opensearch_mapping_total_fields_limit,
                }
            },
        }
        base_mapping: dict[str, Any] = {
            "dynamic": "strict",
            "_meta": {
                "schema_version": settings.opensearch_schema_version,
                "logical_name": logical_name,
            },
            "properties": property_builders[logical_name](),
        }
        combined_fingerprint = definition_fingerprint(index_settings, base_mapping)
        declared_mapping = deepcopy(base_mapping)
        declared_mapping["_meta"]["mapping_fingerprint"] = combined_fingerprint
        prefix = settings.opensearch_index_prefix
        definitions.append(
            OpenSearchIndexDefinition(
                logical_name=logical_name,
                schema_version=settings.opensearch_schema_version,
                physical_index_name=(
                    f"{prefix}-{logical_name}-"
                    f"{settings.opensearch_schema_version}-000001"
                ),
                read_alias=f"{prefix}-{logical_name}-read",
                write_alias=f"{prefix}-{logical_name}-write",
                settings=index_settings,
                mapping=declared_mapping,
                settings_fingerprint=settings_fingerprint(index_settings),
                mapping_fingerprint=mapping_fingerprint(base_mapping),
                fingerprint=combined_fingerprint,
            )
        )
    return tuple(definitions)
