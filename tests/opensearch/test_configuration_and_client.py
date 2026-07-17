from __future__ import annotations

from typing import Any

import pytest
from opensearchpy.exceptions import AuthenticationException, ConnectionTimeout
from pydantic import ValidationError

from agent.config import Settings
from agent.opensearch.client import (
    OpenSearchClientFactory,
    OpenSearchGatewayAdapter,
)
from agent.opensearch.models import OpenSearchFoundationError


def settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "_env_file": None,
        "app_env": "test",
        "llm_enabled": False,
        "opensearch_enabled": True,
    }
    values.update(overrides)
    return Settings(**values)


def test_dependency_is_official_client_only_and_default_is_disabled() -> None:
    requirements = open("requirements.txt", encoding="utf-8").read()
    assert "opensearch-py>=3.2,<4" in requirements
    assert "opensearch-dsl" not in requirements
    assert Settings(_env_file=None).opensearch_enabled is False


def test_enabled_requires_hosts_and_test_environment_allows_explicit_http() -> None:
    assert settings(opensearch_enabled=False, opensearch_hosts=[]).opensearch_hosts == []
    with pytest.raises(ValidationError, match="opensearch_hosts_required"):
        settings(opensearch_hosts=[])
    configured = settings(opensearch_hosts=["http://localhost:9200"])
    assert configured.opensearch_hosts == ["http://localhost:9200"]


@pytest.mark.parametrize(
    "host",
    [
        "ftp://search.example.test:9200",
        "https://user:pass@search.example.test:9200",
        "https://search.example.test/path",
        "https://search.example.test/?token=secret",
        "https://search.example.test/#fragment",
    ],
)
def test_hosts_reject_unsafe_url_components(host: str) -> None:
    with pytest.raises(ValidationError, match="opensearch_hosts_invalid"):
        settings(opensearch_hosts=[host])


@pytest.mark.parametrize(
    ("overrides", "error_code"),
    [
        ({"opensearch_required": True, "opensearch_enabled": False},
         "opensearch_required_requires_enabled"),
        ({"opensearch_username": "user"}, "opensearch_basic_auth_pair_required"),
        ({"opensearch_password": "secret"}, "opensearch_basic_auth_pair_required"),
        ({"opensearch_client_cert": "cert.pem"},
         "opensearch_client_certificate_pair_required"),
        ({"opensearch_index_prefix": "Bad_Prefix"},
         "opensearch_index_prefix_invalid"),
        ({"opensearch_schema_version": "latest"},
         "opensearch_schema_version_invalid"),
        ({"opensearch_bootstrap_on_startup": True},
         "opensearch_bootstrap_on_startup_unsupported"),
    ],
)
def test_settings_fail_closed_for_invalid_pairs_and_names(
    overrides: dict[str, object],
    error_code: str,
) -> None:
    with pytest.raises(ValidationError, match=error_code):
        settings(**overrides)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("opensearch_connect_timeout_seconds", 0),
        ("opensearch_connect_timeout_seconds", -1),
        ("opensearch_connect_timeout_seconds", 31),
        ("opensearch_read_timeout_seconds", 121),
        ("opensearch_max_retries", -1),
        ("opensearch_max_retries", 6),
        ("opensearch_number_of_shards", 0),
        ("opensearch_number_of_replicas", -1),
    ],
)
def test_numeric_settings_are_bounded(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        settings(**{field: value})


@pytest.mark.parametrize(
    "prefix",
    ["../escape", "bad/prefix", r"bad\prefix", "bad*prefix", "bad prefix"],
)
def test_prefix_rejects_traversal_and_opensearch_metacharacters(
    prefix: str,
) -> None:
    with pytest.raises(ValidationError, match="opensearch_index_prefix_invalid"):
        settings(opensearch_index_prefix=prefix)


def test_password_repr_is_redacted_and_environment_override_works(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = settings(opensearch_password="never-print", opensearch_username="u")
    assert "never-print" not in repr(configured)

    monkeypatch.setenv("OPENSEARCH_ENABLED", "true")
    monkeypatch.setenv("OPENSEARCH_HOSTS", '["http://127.0.0.1:9200"]')
    from_environment = Settings(_env_file=None, app_env="test")
    assert from_environment.opensearch_enabled is True
    assert from_environment.opensearch_hosts == ["http://127.0.0.1:9200"]


def _production_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "_env_file": None,
        "app_env": "production",
        "auth_mode": "api_key",
        "https_required": True,
        "trusted_hosts": ["api.example.test"],
        "llm_enabled": False,
        "rate_limiting_enabled": True,
        "rate_limit_backend": "redis",
        "rate_limit_key_secret": "production-rate-limit-secret-000001",
        "search_cursor_secret": "production-search-cursor-secret-000001",
        "opensearch_enabled": True,
    }
    values.update(overrides)
    return Settings(**values)


def test_production_requires_https_and_certificate_verification() -> None:
    with pytest.raises(ValidationError, match="production_opensearch_https_required"):
        _production_settings(opensearch_hosts=["http://search.example.test:9200"])
    with pytest.raises(
        ValidationError,
        match="production_opensearch_verify_certs_required",
    ):
        _production_settings(opensearch_verify_certs=False)


class _Indices:
    def exists(self, *, index: str) -> bool:
        return False


class _RawClient:
    indices = _Indices()

    def info(self) -> dict[str, object]:
        return {"version": {"number": "3.2.1"}}

    def close(self) -> None:
        return None


def test_client_is_lazy_and_forwards_bounded_secure_options() -> None:
    captured: dict[str, Any] = {}

    def constructor(**kwargs: Any) -> _RawClient:
        captured.update(kwargs)
        return _RawClient()

    configured = settings(
        opensearch_hosts=["https://search.example.test:9443"],
        opensearch_username="search-user",
        opensearch_password="private-password",
        opensearch_ca_certs="ca.pem",
        opensearch_client_cert="client.pem",
        opensearch_client_key="client-key.pem",
        opensearch_connect_timeout_seconds=2,
        opensearch_read_timeout_seconds=7,
        opensearch_max_retries=3,
        opensearch_pool_maxsize=17,
    )
    factory = OpenSearchClientFactory(configured, constructor)
    assert captured == {}

    gateway = factory.create()

    assert isinstance(gateway, OpenSearchGatewayAdapter)
    assert captured["hosts"] == [
        {
            "host": "search.example.test",
            "port": 9443,
            "use_ssl": True,
            "timeout": (2.0, 7.0),
        }
    ]
    assert captured["http_auth"] == ("search-user", "private-password")
    assert captured["verify_certs"] is True
    assert captured["ca_certs"] == "ca.pem"
    assert captured["client_cert"] == "client.pem"
    assert captured["client_key"] == "client-key.pem"
    assert captured["http_compress"] is True
    assert captured["retry_on_timeout"] is True
    assert captured["retry_on_status"] == (429, 502, 503, 504)
    assert captured["max_retries"] == 3
    assert captured["pool_maxsize"] == 17


def test_disabled_factory_never_constructs_a_client() -> None:
    called = False

    def constructor(**kwargs: Any) -> _RawClient:
        nonlocal called
        called = True
        return _RawClient()

    factory = OpenSearchClientFactory(
        settings(opensearch_enabled=False),
        constructor,
    )
    with pytest.raises(OpenSearchFoundationError) as caught:
        factory.create()
    assert caught.value.code == "opensearch_disabled"
    assert called is False


def test_constructor_failure_is_sanitized() -> None:
    def constructor(**kwargs: Any) -> _RawClient:
        raise RuntimeError("https://user:private-password@internal:9200")

    with pytest.raises(OpenSearchFoundationError) as caught:
        OpenSearchClientFactory(settings(), constructor).create()
    assert caught.value.code == "opensearch_client_configuration_invalid"
    assert "private-password" not in str(caught.value)


def test_adapter_close_delegates_to_client() -> None:
    class ClosingClient(_RawClient):
        closed = False

        def close(self) -> None:
            self.closed = True

    client = ClosingClient()
    OpenSearchGatewayAdapter(client).close()
    assert client.closed is True


@pytest.mark.parametrize(
    ("exc", "error_code"),
    [
        (ConnectionTimeout("timeout"), "opensearch_timeout"),
        (AuthenticationException(401, "private-password"),
         "opensearch_authentication_failed"),
    ],
)
def test_adapter_errors_are_sanitized(exc: Exception, error_code: str) -> None:
    class FailingClient(_RawClient):
        def info(self) -> dict[str, object]:
            raise exc

    with pytest.raises(OpenSearchFoundationError) as caught:
        OpenSearchGatewayAdapter(FailingClient()).cluster_info()
    assert caught.value.code == error_code
    assert "private-password" not in str(caught.value)
