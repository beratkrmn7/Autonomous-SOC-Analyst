from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    from agent.opensearch.mappings import OpenSearchIndexDefinition


OpenSearchHealthStatus = Literal[
    "disabled",
    "healthy",
    "degraded",
    "unavailable",
    "incompatible",
]
OpenSearchPlanStatus = Literal[
    "missing",
    "ready",
    "mapping_drift",
    "settings_drift",
    "alias_missing",
    "alias_drift",
    "unexpected_alias_target",
    "incompatible_schema",
]
OpenSearchResourceStatus = Literal["missing", "ready", "drift", "incompatible"]


class OpenSearchFoundationError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class OpenSearchClusterInfo:
    major_version: int
    minor_version: int


@dataclass(frozen=True)
class OpenSearchIndexSettingsState:
    number_of_shards: int
    number_of_replicas: int
    total_fields_limit: int


@dataclass(frozen=True)
class OpenSearchIndexState:
    name: str
    exists: bool
    schema_version: str | None = None
    logical_name: str | None = None
    declared_fingerprint: str | None = None
    mapping_fingerprint: str | None = None
    settings: OpenSearchIndexSettingsState | None = None


@dataclass(frozen=True)
class OpenSearchAliasTarget:
    index_name: str
    is_write_index: bool


@dataclass(frozen=True)
class OpenSearchAliasState:
    name: str
    targets: tuple[OpenSearchAliasTarget, ...]


@dataclass(frozen=True)
class OpenSearchAliasAddAction:
    alias_name: str
    index_name: str
    is_write_index: bool


class OpenSearchGateway(Protocol):
    def cluster_info(self) -> OpenSearchClusterInfo: ...

    def index_state(self, index_name: str) -> OpenSearchIndexState: ...

    def alias_state(self, alias_name: str) -> OpenSearchAliasState: ...

    def create_index(self, definition: OpenSearchIndexDefinition) -> None: ...

    def add_aliases_atomically(
        self,
        actions: tuple[OpenSearchAliasAddAction, ...],
    ) -> None: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class OpenSearchIndexPlanItem:
    logical_name: str
    physical_index_name: str
    status: OpenSearchPlanStatus
    index_status: OpenSearchResourceStatus
    read_alias_status: OpenSearchResourceStatus
    write_alias_status: OpenSearchResourceStatus


@dataclass(frozen=True)
class OpenSearchBootstrapPlan:
    schema_version: str
    items: tuple[OpenSearchIndexPlanItem, ...]

    @property
    def has_drift(self) -> bool:
        return any(
            item.status
            in {
                "mapping_drift",
                "settings_drift",
                "alias_drift",
                "unexpected_alias_target",
                "incompatible_schema",
            }
            for item in self.items
        )

    @property
    def all_ready(self) -> bool:
        return all(item.status == "ready" for item in self.items)


@dataclass(frozen=True)
class OpenSearchBootstrapResult:
    status: Literal["completed"]
    schema_version: str
    created_index_count: int
    created_alias_count: int
    changed: bool
    plan: OpenSearchBootstrapPlan


@dataclass(frozen=True)
class OpenSearchHealthResult:
    status: OpenSearchHealthStatus
    required: bool
    cluster_version: str | None
    bootstrap_compatible: bool | None
    error_code: str | None = None
