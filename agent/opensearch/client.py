from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast
from urllib.parse import urlsplit

from opensearchpy import OpenSearch, RequestsHttpConnection
from opensearchpy.exceptions import (
    AuthenticationException,
    AuthorizationException,
    ConnectionError as OpenSearchConnectionError,
    ConnectionTimeout,
    NotFoundError,
    RequestError,
    SSLError,
)

from agent.config import Settings
from agent.opensearch.mappings import (
    OpenSearchIndexDefinition,
    mapping_fingerprint,
)
from agent.opensearch.models import (
    OpenSearchAliasAddAction,
    OpenSearchAliasState,
    OpenSearchAliasTarget,
    OpenSearchClusterInfo,
    OpenSearchFoundationError,
    OpenSearchIndexSettingsState,
    OpenSearchIndexState,
)


class _IndicesClient(Protocol):
    def exists(self, *, index: str) -> bool: ...

    def get(self, *, index: str) -> Mapping[str, Any]: ...

    def get_alias(self, *, name: str) -> Mapping[str, Any]: ...

    def create(self, *, index: str, body: Mapping[str, Any]) -> object: ...

    def update_aliases(self, *, body: Mapping[str, Any]) -> object: ...


class _RawOpenSearchClient(Protocol):
    indices: _IndicesClient

    def info(self) -> Mapping[str, Any]: ...

    def close(self) -> object: ...


OpenSearchConstructor = Callable[..., _RawOpenSearchClient]


@dataclass(frozen=True)
class OpenSearchClientFactory:
    settings: Settings
    constructor: OpenSearchConstructor | None = None

    def create(self) -> OpenSearchGatewayAdapter:
        if not self.settings.opensearch_enabled:
            raise OpenSearchFoundationError("opensearch_disabled")

        client_constructor = self.constructor or cast(
            OpenSearchConstructor,
            OpenSearch,
        )
        hosts = []
        for configured_host in self.settings.opensearch_hosts:
            parsed = urlsplit(configured_host)
            use_ssl = parsed.scheme == "https"
            hosts.append(
                {
                    "host": parsed.hostname,
                    "port": parsed.port or (443 if use_ssl else 80),
                    "use_ssl": use_ssl,
                    "timeout": (
                        self.settings.opensearch_connect_timeout_seconds,
                        self.settings.opensearch_read_timeout_seconds,
                    ),
                }
            )

        kwargs: dict[str, Any] = {
            "hosts": hosts,
            "connection_class": RequestsHttpConnection,
            "verify_certs": self.settings.opensearch_verify_certs,
            "ssl_show_warn": True,
            "http_compress": True,
            "pool_maxsize": self.settings.opensearch_pool_maxsize,
            "max_retries": self.settings.opensearch_max_retries,
            "retry_on_timeout": True,
            "retry_on_status": (429, 502, 503, 504),
        }
        if self.settings.opensearch_username is not None:
            password = self.settings.opensearch_password
            if password is None:
                raise OpenSearchFoundationError("opensearch_auth_configuration_invalid")
            kwargs["http_auth"] = (
                self.settings.opensearch_username,
                password.get_secret_value(),
            )
        if self.settings.opensearch_ca_certs is not None:
            kwargs["ca_certs"] = self.settings.opensearch_ca_certs
        if self.settings.opensearch_client_cert is not None:
            kwargs["client_cert"] = self.settings.opensearch_client_cert
            kwargs["client_key"] = self.settings.opensearch_client_key

        try:
            return OpenSearchGatewayAdapter(client_constructor(**kwargs))
        except OpenSearchFoundationError:
            raise
        except Exception as exc:
            raise OpenSearchFoundationError(
                "opensearch_client_configuration_invalid"
            ) from exc


class OpenSearchGatewayAdapter:
    def __init__(self, client: _RawOpenSearchClient) -> None:
        self._client = client

    def cluster_info(self) -> OpenSearchClusterInfo:
        try:
            payload = self._client.info()
            version = _mapping_value(payload, "version")
            number = _string_value(version, "number")
            parts = number.split(".")
            if len(parts) < 2:
                raise ValueError
            return OpenSearchClusterInfo(
                major_version=int(parts[0]),
                minor_version=int(parts[1]),
            )
        except Exception as exc:
            raise _safe_error(exc, "opensearch_cluster_info_failed") from exc

    def index_state(self, index_name: str) -> OpenSearchIndexState:
        try:
            if not self._client.indices.exists(index=index_name):
                return OpenSearchIndexState(name=index_name, exists=False)
            payload = self._client.indices.get(index=index_name)
            index_payload = _mapping_value(payload, index_name)
            mappings = dict(_mapping_value(index_payload, "mappings"))
            metadata = mappings.get("_meta")
            safe_metadata = metadata if isinstance(metadata, Mapping) else {}
            settings_payload = _mapping_value(index_payload, "settings")
            index_settings = _mapping_value(settings_payload, "index")
            mapping_settings = _mapping_value(index_settings, "mapping")
            total_fields = _mapping_value(mapping_settings, "total_fields")
            return OpenSearchIndexState(
                name=index_name,
                exists=True,
                schema_version=_optional_string(safe_metadata.get("schema_version")),
                logical_name=_optional_string(safe_metadata.get("logical_name")),
                declared_fingerprint=_optional_string(
                    safe_metadata.get("mapping_fingerprint")
                ),
                mapping_fingerprint=mapping_fingerprint(mappings),
                settings=OpenSearchIndexSettingsState(
                    number_of_shards=_int_value(index_settings, "number_of_shards"),
                    number_of_replicas=_int_value(
                        index_settings,
                        "number_of_replicas",
                    ),
                    total_fields_limit=_int_value(total_fields, "limit"),
                ),
            )
        except Exception as exc:
            raise _safe_error(exc, "opensearch_index_inspection_failed") from exc

    def alias_state(self, alias_name: str) -> OpenSearchAliasState:
        try:
            payload = self._client.indices.get_alias(name=alias_name)
        except NotFoundError:
            return OpenSearchAliasState(name=alias_name, targets=())
        except Exception as exc:
            raise _safe_error(exc, "opensearch_alias_inspection_failed") from exc

        try:
            targets: list[OpenSearchAliasTarget] = []
            for index_name in sorted(payload):
                index_payload = _mapping_value(payload, index_name)
                aliases = _mapping_value(index_payload, "aliases")
                alias_payload = aliases.get(alias_name, {})
                if not isinstance(alias_payload, Mapping):
                    raise ValueError
                targets.append(
                    OpenSearchAliasTarget(
                        index_name=index_name,
                        is_write_index=alias_payload.get("is_write_index") is True,
                    )
                )
            return OpenSearchAliasState(name=alias_name, targets=tuple(targets))
        except Exception as exc:
            raise OpenSearchFoundationError(
                "opensearch_alias_response_invalid"
            ) from exc

    def create_index(self, definition: OpenSearchIndexDefinition) -> None:
        try:
            self._client.indices.create(
                index=definition.physical_index_name,
                body=definition.creation_body(),
            )
        except Exception as exc:
            raise _safe_error(exc, "opensearch_index_create_failed") from exc

    def add_aliases_atomically(
        self,
        actions: tuple[OpenSearchAliasAddAction, ...],
    ) -> None:
        if not actions:
            return
        body = {
            "actions": [
                {
                    "add": {
                        "index": action.index_name,
                        "alias": action.alias_name,
                        "is_write_index": action.is_write_index,
                    }
                }
                for action in actions
            ]
        }
        try:
            self._client.indices.update_aliases(body=body)
        except Exception as exc:
            raise _safe_error(exc, "opensearch_alias_create_failed") from exc

    def close(self) -> None:
        try:
            self._client.close()
        except Exception as exc:
            raise _safe_error(exc, "opensearch_client_close_failed") from exc


def _mapping_value(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    nested = value.get(key)
    if not isinstance(nested, Mapping):
        raise ValueError
    return nested


def _string_value(value: Mapping[str, Any], key: str) -> str:
    nested = value.get(key)
    if not isinstance(nested, str) or not nested:
        raise ValueError
    return nested


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _int_value(value: Mapping[str, Any], key: str) -> int:
    nested = value.get(key)
    if isinstance(nested, bool):
        raise ValueError
    return int(cast(str | int, nested))


def _safe_error(exc: Exception, fallback_code: str) -> OpenSearchFoundationError:
    if isinstance(exc, OpenSearchFoundationError):
        return exc
    if isinstance(exc, AuthenticationException):
        return OpenSearchFoundationError("opensearch_authentication_failed")
    if isinstance(exc, AuthorizationException):
        return OpenSearchFoundationError("opensearch_authorization_failed")
    if isinstance(exc, SSLError):
        return OpenSearchFoundationError("opensearch_tls_failed")
    if isinstance(exc, ConnectionTimeout):
        return OpenSearchFoundationError("opensearch_timeout")
    if isinstance(exc, OpenSearchConnectionError):
        return OpenSearchFoundationError("opensearch_unavailable")
    if isinstance(exc, RequestError):
        return OpenSearchFoundationError("opensearch_request_rejected")
    return OpenSearchFoundationError(fallback_code)
