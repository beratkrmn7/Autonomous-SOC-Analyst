from __future__ import annotations

from dataclasses import replace

import pytest

from agent.config import Settings
from agent.opensearch.manager import (
    OpenSearchFoundationManager,
    OpenSearchHealthService,
)
from agent.opensearch.mappings import build_index_definitions
from agent.opensearch.mappings import mapping_fingerprint
from agent.opensearch.models import (
    OpenSearchAliasState,
    OpenSearchAliasTarget,
    OpenSearchClusterInfo,
    OpenSearchFoundationError,
    OpenSearchIndexSettingsState,
)
from tests.opensearch.fakes import (
    FakeOpenSearchGateway,
    ready_index_state,
    seed_ready_definition,
)


def settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "_env_file": None,
        "app_env": "test",
        "llm_enabled": False,
        "opensearch_enabled": True,
        "opensearch_index_prefix": "triage",
        "opensearch_schema_version": "v7",
    }
    values.update(overrides)
    return Settings(**values)


def test_definitions_have_stable_names_strict_mappings_and_fingerprints() -> None:
    definitions = build_index_definitions(settings())

    assert [definition.physical_index_name for definition in definitions] == [
        "triage-canonical-events-v7-000001",
        "triage-detection-signals-v7-000001",
        "triage-incidents-v7-000001",
    ]
    for definition in definitions:
        assert definition.mapping["dynamic"] == "strict"
        assert definition.mapping["_meta"] == {
            "schema_version": "v7",
            "logical_name": definition.logical_name,
            "mapping_fingerprint": definition.fingerprint,
        }
        assert definition.read_alias.endswith("-read")
        assert definition.write_alias.endswith("-write")
        assert len(definition.mapping_fingerprint) == 64
        assert len(definition.settings_fingerprint) == 64
        assert len(definition.fingerprint) == 64
        assert definition.creation_body() == definition.creation_body()


def test_mapping_types_are_explicit_and_sensitive_fields_are_absent() -> None:
    event, signal, incident = build_index_definitions(settings())
    event_fields = event.mapping["properties"]
    signal_fields = signal.mapping["properties"]
    incident_fields = incident.mapping["properties"]

    assert event_fields["src_ip"]["type"] == "ip"
    assert event_fields["dst_ip"]["type"] == "ip"
    assert event_fields["src_port"]["type"] == "integer"
    assert event_fields["timestamp"]["type"] == "date"
    assert event_fields["protocol"]["type"] == "keyword"
    assert signal_fields["severity"]["type"] == "keyword"
    assert signal_fields["confidence"]["type"] == "float"
    assert signal_fields["suppressed"]["type"] == "boolean"
    assert incident_fields["status"]["type"] == "keyword"
    assert incident_fields["title"]["type"] == "text"
    assert incident_fields["title"]["fields"]["keyword"]["type"] == "keyword"
    for fields in (event_fields, signal_fields, incident_fields):
        assert not any(value.get("type") in {"object", "nested", "flattened"} for value in fields.values())
        assert {
            "raw_log",
            "original_fields",
            "metrics",
            "authorization",
            "provider_prompt",
            "report_content",
            "evidence_quote",
        }.isdisjoint(fields)


def test_fingerprint_changes_for_a_field_type_and_names_follow_prefix() -> None:
    first = build_index_definitions(settings())[0]
    changed_mapping = first.creation_body()["mappings"]
    changed_mapping["properties"]["src_port"]["type"] = "long"
    assert mapping_fingerprint(changed_mapping) != first.mapping_fingerprint

    renamed = build_index_definitions(
        settings(opensearch_index_prefix="alternate", opensearch_schema_version="v8")
    )[0]
    assert renamed.physical_index_name == "alternate-canonical-events-v8-000001"
    assert renamed.read_alias == "alternate-canonical-events-read"
    assert renamed.write_alias == "alternate-canonical-events-write"


def test_initial_plan_is_read_only_and_reports_missing() -> None:
    gateway = FakeOpenSearchGateway()
    plan = OpenSearchFoundationManager(settings(), gateway).plan()

    assert [item.status for item in plan.items] == ["missing"] * 3
    assert gateway.create_calls == []
    assert gateway.alias_calls == []


def test_plan_reports_ready_without_writes() -> None:
    configured = settings()
    gateway = FakeOpenSearchGateway()
    for definition in build_index_definitions(configured):
        seed_ready_definition(gateway, definition)
    plan = OpenSearchFoundationManager(configured, gateway).plan()
    assert [item.status for item in plan.items] == ["ready"] * 3
    assert gateway.create_calls == []
    assert gateway.alias_calls == []


def test_bootstrap_creates_missing_resources_then_is_idempotent() -> None:
    configured = settings()
    gateway = FakeOpenSearchGateway()
    manager = OpenSearchFoundationManager(configured, gateway)

    first = manager.bootstrap()
    second = manager.bootstrap()

    assert first.created_index_count == 3
    assert first.created_alias_count == 6
    assert first.changed is True
    assert first.plan.all_ready is True
    assert len(gateway.alias_calls) == 1
    assert len(gateway.alias_calls[0]) == 6
    assert second.created_index_count == 0
    assert second.created_alias_count == 0
    assert second.changed is False
    assert len(gateway.create_calls) == 3
    assert len(gateway.alias_calls) == 1


def test_bootstrap_adds_only_missing_aliases() -> None:
    configured = settings()
    gateway = FakeOpenSearchGateway()
    definitions = build_index_definitions(configured)
    for definition in definitions:
        seed_ready_definition(gateway, definition)
    del gateway.aliases[definitions[0].read_alias]

    result = OpenSearchFoundationManager(configured, gateway).bootstrap()

    assert result.created_index_count == 0
    assert result.created_alias_count == 1
    assert gateway.alias_calls[0][0].alias_name == definitions[0].read_alias


@pytest.mark.parametrize(
    ("mutation", "expected_status"),
    [
        ("mapping", "mapping_drift"),
        ("settings", "settings_drift"),
        ("schema", "incompatible_schema"),
        ("declared", "mapping_drift"),
    ],
)
def test_plan_detects_index_drift_and_bootstrap_never_mutates_it(
    mutation: str,
    expected_status: str,
) -> None:
    configured = settings()
    gateway = FakeOpenSearchGateway()
    definitions = build_index_definitions(configured)
    for definition in definitions:
        seed_ready_definition(gateway, definition)
    definition = definitions[0]
    state = ready_index_state(definition)
    if mutation == "mapping":
        state = replace(state, mapping_fingerprint="0" * 64)
    elif mutation == "settings":
        state = replace(
            state,
            settings=OpenSearchIndexSettingsState(2, 0, 256),
        )
    elif mutation == "schema":
        state = replace(state, schema_version="v6")
    else:
        state = replace(state, declared_fingerprint=None)
    gateway.indices[definition.physical_index_name] = state
    manager = OpenSearchFoundationManager(configured, gateway)

    assert manager.plan().items[0].status == expected_status
    with pytest.raises(OpenSearchFoundationError) as caught:
        manager.bootstrap()
    assert caught.value.code == "opensearch_bootstrap_drift_detected"
    assert gateway.create_calls == []
    assert gateway.alias_calls == []


@pytest.mark.parametrize(
    ("targets", "expected_status"),
    [
        ((OpenSearchAliasTarget("unexpected-index", False),),
         "unexpected_alias_target"),
        ((OpenSearchAliasTarget("EXPECTED", True),), "alias_drift"),
    ],
)
def test_alias_drift_is_fail_closed(
    targets: tuple[OpenSearchAliasTarget, ...],
    expected_status: str,
) -> None:
    configured = settings()
    gateway = FakeOpenSearchGateway()
    definitions = build_index_definitions(configured)
    for definition in definitions:
        seed_ready_definition(gateway, definition)
    definition = definitions[0]
    normalized_targets = tuple(
        replace(
            target,
            index_name=(
                definition.physical_index_name
                if target.index_name == "EXPECTED"
                else target.index_name
            ),
        )
        for target in targets
    )
    gateway.aliases[definition.read_alias] = OpenSearchAliasState(
        definition.read_alias,
        normalized_targets,
    )
    manager = OpenSearchFoundationManager(configured, gateway)

    assert manager.plan().items[0].status == expected_status
    with pytest.raises(OpenSearchFoundationError):
        manager.bootstrap()
    assert gateway.alias_calls == []


def test_multiple_write_targets_are_detected_and_never_repaired() -> None:
    configured = settings()
    gateway = FakeOpenSearchGateway()
    definitions = build_index_definitions(configured)
    for definition in definitions:
        seed_ready_definition(gateway, definition)
    definition = definitions[0]
    gateway.aliases[definition.write_alias] = OpenSearchAliasState(
        definition.write_alias,
        (
            OpenSearchAliasTarget(definition.physical_index_name, True),
            OpenSearchAliasTarget(definition.physical_index_name, True),
        ),
    )
    manager = OpenSearchFoundationManager(configured, gateway)
    assert manager.plan().items[0].status == "alias_drift"
    with pytest.raises(OpenSearchFoundationError):
        manager.bootstrap()
    assert gateway.alias_calls == []


def test_create_failure_never_advances_to_alias_changes() -> None:
    gateway = FakeOpenSearchGateway(create_failure_code="simulated_create_failure")
    with pytest.raises(OpenSearchFoundationError) as caught:
        OpenSearchFoundationManager(settings(), gateway).bootstrap()
    assert caught.value.code == "simulated_create_failure"
    assert gateway.alias_calls == []


def test_health_reports_disabled_ready_missing_drift_and_incompatible_cluster() -> None:
    disabled = settings(opensearch_enabled=False)
    disabled_gateway = FakeOpenSearchGateway()
    assert OpenSearchHealthService(disabled, lambda: disabled_gateway).check().status == (
        "disabled"
    )
    assert disabled_gateway.closed is False

    configured = settings()
    missing_gateway = FakeOpenSearchGateway()
    missing = OpenSearchHealthService(configured, lambda: missing_gateway).check()
    assert missing.status == "degraded"
    assert missing.error_code == "opensearch_foundation_missing"
    assert missing_gateway.closed is True

    ready_gateway = FakeOpenSearchGateway()
    for definition in build_index_definitions(configured):
        seed_ready_definition(ready_gateway, definition)
    assert OpenSearchHealthService(configured, lambda: ready_gateway).check().status == (
        "healthy"
    )

    drift_gateway = FakeOpenSearchGateway()
    definitions = build_index_definitions(configured)
    for definition in definitions:
        seed_ready_definition(drift_gateway, definition)
    drift_gateway.indices[definitions[0].physical_index_name] = replace(
        ready_index_state(definitions[0]),
        mapping_fingerprint="f" * 64,
    )
    assert OpenSearchHealthService(configured, lambda: drift_gateway).check().status == (
        "incompatible"
    )

    old_gateway = FakeOpenSearchGateway(cluster=OpenSearchClusterInfo(4, 0))
    incompatible = OpenSearchHealthService(configured, lambda: old_gateway).check()
    assert incompatible.status == "incompatible"
    assert incompatible.error_code == "opensearch_cluster_version_incompatible"


@pytest.mark.parametrize(
    "error_code",
    [
        "opensearch_timeout",
        "opensearch_tls_failed",
        "opensearch_authentication_failed",
    ],
)
def test_health_sanitizes_gateway_failures(error_code: str) -> None:
    class FailingGateway(FakeOpenSearchGateway):
        def cluster_info(self) -> OpenSearchClusterInfo:
            raise OpenSearchFoundationError(error_code)

    result = OpenSearchHealthService(settings(), FailingGateway).check()
    assert result.status == "unavailable"
    assert result.error_code == error_code
    assert "exception" not in repr(result).lower()
