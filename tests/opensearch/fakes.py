from __future__ import annotations

from dataclasses import dataclass, field

from agent.opensearch.mappings import OpenSearchIndexDefinition
from agent.opensearch.models import (
    OpenSearchAliasAddAction,
    OpenSearchAliasState,
    OpenSearchAliasTarget,
    OpenSearchClusterInfo,
    OpenSearchFoundationError,
    OpenSearchIndexState,
)


@dataclass
class FakeOpenSearchGateway:
    cluster: OpenSearchClusterInfo = OpenSearchClusterInfo(3, 0)
    indices: dict[str, OpenSearchIndexState] = field(default_factory=dict)
    aliases: dict[str, OpenSearchAliasState] = field(default_factory=dict)
    create_calls: list[str] = field(default_factory=list)
    alias_calls: list[tuple[OpenSearchAliasAddAction, ...]] = field(
        default_factory=list
    )
    closed: bool = False
    create_failure_code: str | None = None
    alias_failure_code: str | None = None

    def cluster_info(self) -> OpenSearchClusterInfo:
        return self.cluster

    def index_state(self, index_name: str) -> OpenSearchIndexState:
        return self.indices.get(
            index_name,
            OpenSearchIndexState(name=index_name, exists=False),
        )

    def alias_state(self, alias_name: str) -> OpenSearchAliasState:
        return self.aliases.get(
            alias_name,
            OpenSearchAliasState(name=alias_name, targets=()),
        )

    def create_index(self, definition: OpenSearchIndexDefinition) -> None:
        if self.create_failure_code is not None:
            raise OpenSearchFoundationError(self.create_failure_code)
        self.create_calls.append(definition.physical_index_name)
        self.indices[definition.physical_index_name] = ready_index_state(
            definition
        )

    def add_aliases_atomically(
        self,
        actions: tuple[OpenSearchAliasAddAction, ...],
    ) -> None:
        if self.alias_failure_code is not None:
            raise OpenSearchFoundationError(self.alias_failure_code)
        self.alias_calls.append(actions)
        for action in actions:
            current = self.aliases.get(
                action.alias_name,
                OpenSearchAliasState(name=action.alias_name, targets=()),
            )
            self.aliases[action.alias_name] = OpenSearchAliasState(
                name=action.alias_name,
                targets=(
                    *current.targets,
                    OpenSearchAliasTarget(
                        index_name=action.index_name,
                        is_write_index=action.is_write_index,
                    ),
                ),
            )

    def close(self) -> None:
        self.closed = True


def ready_index_state(
    definition: OpenSearchIndexDefinition,
) -> OpenSearchIndexState:
    return OpenSearchIndexState(
        name=definition.physical_index_name,
        exists=True,
        schema_version=definition.schema_version,
        logical_name=definition.logical_name,
        declared_fingerprint=definition.fingerprint,
        mapping_fingerprint=definition.mapping_fingerprint,
        settings=definition.expected_settings_state,
    )


def seed_ready_definition(
    gateway: FakeOpenSearchGateway,
    definition: OpenSearchIndexDefinition,
) -> None:
    gateway.indices[definition.physical_index_name] = ready_index_state(definition)
    gateway.aliases[definition.read_alias] = OpenSearchAliasState(
        name=definition.read_alias,
        targets=(
            OpenSearchAliasTarget(
                index_name=definition.physical_index_name,
                is_write_index=False,
            ),
        ),
    )
    gateway.aliases[definition.write_alias] = OpenSearchAliasState(
        name=definition.write_alias,
        targets=(
            OpenSearchAliasTarget(
                index_name=definition.physical_index_name,
                is_write_index=True,
            ),
        ),
    )
