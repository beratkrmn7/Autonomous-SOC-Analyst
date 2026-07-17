from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress

from agent.config import Settings
from agent.opensearch.mappings import (
    OpenSearchIndexDefinition,
    build_index_definitions,
)
from agent.opensearch.models import (
    OpenSearchAliasAddAction,
    OpenSearchAliasState,
    OpenSearchBootstrapPlan,
    OpenSearchBootstrapResult,
    OpenSearchClusterInfo,
    OpenSearchFoundationError,
    OpenSearchGateway,
    OpenSearchHealthResult,
    OpenSearchIndexPlanItem,
    OpenSearchIndexState,
    OpenSearchPlanStatus,
    OpenSearchResourceStatus,
)


SUPPORTED_CLUSTER_MAJOR_VERSIONS = frozenset({1, 2, 3})


class OpenSearchFoundationManager:
    def __init__(
        self,
        settings: Settings,
        gateway: OpenSearchGateway,
    ) -> None:
        self._settings = settings
        self._gateway = gateway
        self._definitions = build_index_definitions(settings)

    def plan(self) -> OpenSearchBootstrapPlan:
        if not self._settings.opensearch_enabled:
            raise OpenSearchFoundationError("opensearch_disabled")
        items = tuple(self._plan_definition(item) for item in self._definitions)
        return OpenSearchBootstrapPlan(
            schema_version=self._settings.opensearch_schema_version,
            items=items,
        )

    def bootstrap(self) -> OpenSearchBootstrapResult:
        require_supported_cluster_version(self._gateway.cluster_info())
        initial_plan = self.plan()
        _require_safe_plan(initial_plan)

        definitions_by_name = {
            definition.physical_index_name: definition
            for definition in self._definitions
        }
        created_index_count = 0
        for item in initial_plan.items:
            if item.index_status == "missing":
                self._gateway.create_index(
                    definitions_by_name[item.physical_index_name]
                )
                created_index_count += 1

        alias_plan = self.plan()
        _require_safe_plan(alias_plan)
        actions = self._missing_alias_actions(alias_plan)
        if actions:
            self._gateway.add_aliases_atomically(actions)

        final_plan = self.plan()
        if not final_plan.all_ready:
            raise OpenSearchFoundationError("opensearch_bootstrap_postcondition_failed")
        return OpenSearchBootstrapResult(
            status="completed",
            schema_version=self._settings.opensearch_schema_version,
            created_index_count=created_index_count,
            created_alias_count=len(actions),
            changed=bool(created_index_count or actions),
            plan=final_plan,
        )

    def _plan_definition(
        self,
        definition: OpenSearchIndexDefinition,
    ) -> OpenSearchIndexPlanItem:
        index_state = self._gateway.index_state(definition.physical_index_name)
        read_state = self._gateway.alias_state(definition.read_alias)
        write_state = self._gateway.alias_state(definition.write_alias)

        index_status, incompatibility = _index_status(index_state, definition)
        read_status, read_unexpected = _alias_status(
            read_state,
            expected_index=definition.physical_index_name,
            expected_write=False,
        )
        write_status, write_unexpected = _alias_status(
            write_state,
            expected_index=definition.physical_index_name,
            expected_write=True,
        )
        status = _overall_status(
            index_status=index_status,
            incompatibility=incompatibility,
            read_status=read_status,
            write_status=write_status,
            has_unexpected_alias=read_unexpected or write_unexpected,
            index_state=index_state,
            definition=definition,
        )
        return OpenSearchIndexPlanItem(
            logical_name=definition.logical_name,
            physical_index_name=definition.physical_index_name,
            status=status,
            index_status=index_status,
            read_alias_status=read_status,
            write_alias_status=write_status,
        )

    def _missing_alias_actions(
        self,
        plan: OpenSearchBootstrapPlan,
    ) -> tuple[OpenSearchAliasAddAction, ...]:
        definitions = {
            definition.physical_index_name: definition
            for definition in self._definitions
        }
        actions: list[OpenSearchAliasAddAction] = []
        for item in plan.items:
            definition = definitions[item.physical_index_name]
            if item.read_alias_status == "missing":
                actions.append(
                    OpenSearchAliasAddAction(
                        alias_name=definition.read_alias,
                        index_name=definition.physical_index_name,
                        is_write_index=False,
                    )
                )
            if item.write_alias_status == "missing":
                actions.append(
                    OpenSearchAliasAddAction(
                        alias_name=definition.write_alias,
                        index_name=definition.physical_index_name,
                        is_write_index=True,
                    )
                )
        return tuple(actions)


class OpenSearchHealthService:
    def __init__(
        self,
        settings: Settings,
        gateway_factory: Callable[[], OpenSearchGateway],
    ) -> None:
        self._settings = settings
        self._gateway_factory = gateway_factory

    def check(self) -> OpenSearchHealthResult:
        if not self._settings.opensearch_enabled:
            return OpenSearchHealthResult(
                status="disabled",
                required=self._settings.opensearch_required,
                cluster_version=None,
                bootstrap_compatible=None,
            )

        gateway: OpenSearchGateway | None = None
        try:
            gateway = self._gateway_factory()
            cluster = gateway.cluster_info()
            cluster_version = f"{cluster.major_version}.{cluster.minor_version}"
            try:
                require_supported_cluster_version(cluster)
            except OpenSearchFoundationError as exc:
                return OpenSearchHealthResult(
                    status="incompatible",
                    required=self._settings.opensearch_required,
                    cluster_version=cluster_version,
                    bootstrap_compatible=False,
                    error_code=exc.code,
                )
            plan = OpenSearchFoundationManager(self._settings, gateway).plan()
            if plan.has_drift:
                return OpenSearchHealthResult(
                    status="incompatible",
                    required=self._settings.opensearch_required,
                    cluster_version=cluster_version,
                    bootstrap_compatible=False,
                    error_code="opensearch_foundation_drift",
                )
            if not plan.all_ready:
                return OpenSearchHealthResult(
                    status="degraded",
                    required=self._settings.opensearch_required,
                    cluster_version=cluster_version,
                    bootstrap_compatible=True,
                    error_code="opensearch_foundation_missing",
                )
            return OpenSearchHealthResult(
                status="healthy",
                required=self._settings.opensearch_required,
                cluster_version=cluster_version,
                bootstrap_compatible=True,
            )
        except OpenSearchFoundationError as exc:
            return OpenSearchHealthResult(
                status="unavailable",
                required=self._settings.opensearch_required,
                cluster_version=None,
                bootstrap_compatible=None,
                error_code=exc.code,
            )
        except Exception:
            return OpenSearchHealthResult(
                status="unavailable",
                required=self._settings.opensearch_required,
                cluster_version=None,
                bootstrap_compatible=None,
                error_code="opensearch_health_check_failed",
            )
        finally:
            if gateway is not None:
                with suppress(Exception):
                    gateway.close()


def _index_status(
    state: OpenSearchIndexState,
    definition: OpenSearchIndexDefinition,
) -> tuple[OpenSearchResourceStatus, bool]:
    if not state.exists:
        return "missing", False
    if (
        state.schema_version != definition.schema_version
        or state.logical_name != definition.logical_name
    ):
        return "incompatible", True
    if state.settings is None:
        return "incompatible", True
    return "ready", False


def _alias_status(
    state: OpenSearchAliasState,
    *,
    expected_index: str,
    expected_write: bool,
) -> tuple[OpenSearchResourceStatus, bool]:
    if not state.targets:
        return "missing", False
    if any(target.index_name != expected_index for target in state.targets):
        return "drift", True
    if len(state.targets) != 1:
        return "drift", False
    if state.targets[0].is_write_index is not expected_write:
        return "drift", False
    return "ready", False


def _overall_status(
    *,
    index_status: OpenSearchResourceStatus,
    incompatibility: bool,
    read_status: OpenSearchResourceStatus,
    write_status: OpenSearchResourceStatus,
    has_unexpected_alias: bool,
    index_state: OpenSearchIndexState,
    definition: OpenSearchIndexDefinition,
) -> OpenSearchPlanStatus:
    if incompatibility:
        return "incompatible_schema"
    if index_status == "ready":
        if index_state.mapping_fingerprint != definition.mapping_fingerprint:
            return "mapping_drift"
        if index_state.declared_fingerprint != definition.fingerprint:
            return "mapping_drift"
        if index_state.settings != definition.expected_settings_state:
            return "settings_drift"
    if has_unexpected_alias:
        return "unexpected_alias_target"
    if read_status == "drift" or write_status == "drift":
        return "alias_drift"
    if index_status == "missing":
        return "missing"
    if read_status == "missing" or write_status == "missing":
        return "alias_missing"
    return "ready"


def _require_safe_plan(plan: OpenSearchBootstrapPlan) -> None:
    if plan.has_drift:
        raise OpenSearchFoundationError("opensearch_bootstrap_drift_detected")


def require_supported_cluster_version(cluster: OpenSearchClusterInfo) -> None:
    if cluster.major_version not in SUPPORTED_CLUSTER_MAJOR_VERSIONS:
        raise OpenSearchFoundationError(
            "opensearch_cluster_version_incompatible"
        )
