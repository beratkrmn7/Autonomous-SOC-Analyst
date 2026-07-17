from __future__ import annotations

from io import StringIO
import json

import pytest

import agent.maintenance.opensearch as opensearch_cli
from agent.config import Settings
from agent.maintenance.opensearch import main
from agent.opensearch.mappings import build_index_definitions
from agent.opensearch.models import OpenSearchClusterInfo
from tests.opensearch.fakes import FakeOpenSearchGateway, seed_ready_definition


def settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "_env_file": None,
        "app_env": "test",
        "llm_enabled": False,
        "opensearch_enabled": True,
        "opensearch_username": "operator",
        "opensearch_password": "never-print-this-password",
    }
    values.update(overrides)
    return Settings(**values)


def test_check_disabled_is_safe_and_does_not_create_gateway() -> None:
    output = StringIO()
    called = False

    def gateway_factory() -> FakeOpenSearchGateway:
        nonlocal called
        called = True
        return FakeOpenSearchGateway()

    exit_code = main(
        ["check"],
        settings=settings(opensearch_enabled=False),
        gateway_factory=gateway_factory,
        stdout=output,
    )

    assert exit_code == 0
    assert json.loads(output.getvalue())["status"] == "disabled"
    assert called is False


def test_check_healthy_returns_zero_and_failure_is_nonzero() -> None:
    configured = settings()
    healthy_gateway = FakeOpenSearchGateway()
    for definition in build_index_definitions(configured):
        seed_ready_definition(healthy_gateway, definition)
    output = StringIO()
    assert main(
        ["check"],
        settings=configured,
        gateway_factory=lambda: healthy_gateway,
        stdout=output,
    ) == 0
    assert json.loads(output.getvalue())["status"] == "healthy"

    def fail() -> FakeOpenSearchGateway:
        raise RuntimeError(
            "https://operator:never-print-this-password@internal:9200"
        )

    error_output = StringIO()
    assert main(
        ["check"],
        settings=configured,
        gateway_factory=fail,
        stdout=error_output,
    ) == 1
    failure = error_output.getvalue()
    assert json.loads(failure)["error_code"] == "opensearch_health_check_failed"
    assert "never-print-this-password" not in failure


def test_plan_is_read_only_and_outputs_only_safe_contract() -> None:
    output = StringIO()
    gateway = FakeOpenSearchGateway()
    configured = settings(
        opensearch_hosts=["https://private-search.example.test:9200"],
        opensearch_ca_certs=r"C:\private\ca.pem",
        opensearch_client_cert=r"C:\private\client.pem",
        opensearch_client_key=r"C:\private\client-key.pem",
    )

    exit_code = main(
        ["plan"],
        settings=configured,
        gateway_factory=lambda: gateway,
        stdout=output,
    )

    payload = json.loads(output.getvalue())
    assert exit_code == 0
    assert payload["items"][0]["status"] == "missing"
    assert "never-print-this-password" not in output.getvalue()
    assert "operator" not in output.getvalue()
    assert "private-search.example.test" not in output.getvalue()
    assert r"C:\private" not in output.getvalue()
    assert gateway.create_calls == []
    assert gateway.alias_calls == []
    assert gateway.closed is True


def test_bootstrap_outputs_counts_and_second_run_is_noop() -> None:
    configured = settings()
    gateway = FakeOpenSearchGateway()
    first_output = StringIO()
    second_output = StringIO()

    first_code = main(
        ["bootstrap"],
        settings=configured,
        gateway_factory=lambda: gateway,
        stdout=first_output,
    )
    gateway.closed = False
    second_code = main(
        ["bootstrap"],
        settings=configured,
        gateway_factory=lambda: gateway,
        stdout=second_output,
    )

    assert first_code == second_code == 0
    assert json.loads(first_output.getvalue())["changed"] is True
    second = json.loads(second_output.getvalue())
    assert second["changed"] is False
    assert second["created_index_count"] == 0
    assert second["created_alias_count"] == 0


def test_bootstrap_drift_error_is_sanitized() -> None:
    configured = settings()
    gateway = FakeOpenSearchGateway()
    definitions = build_index_definitions(configured)
    for definition in definitions:
        seed_ready_definition(gateway, definition)
    gateway.indices[definitions[0].physical_index_name] = (
        gateway.indices[definitions[0].physical_index_name].__class__(
            name=definitions[0].physical_index_name,
            exists=True,
            schema_version="v999",
        )
    )
    error = StringIO()

    exit_code = main(
        ["bootstrap"],
        settings=configured,
        gateway_factory=lambda: gateway,
        stderr=error,
    )

    assert exit_code == 2
    assert json.loads(error.getvalue()) == {
        "error_code": "opensearch_bootstrap_drift_detected"
    }
    assert "never-print-this-password" not in error.getvalue()


def test_bootstrap_unsupported_cluster_is_sanitized_and_never_writes() -> None:
    output = StringIO()
    error = StringIO()
    gateway = FakeOpenSearchGateway(
        cluster=OpenSearchClusterInfo(4, 99)
    )

    exit_code = main(
        ["bootstrap"],
        settings=settings(),
        gateway_factory=lambda: gateway,
        stdout=output,
        stderr=error,
    )

    assert exit_code != 0
    assert output.getvalue() == ""
    assert json.loads(error.getvalue()) == {
        "error_code": "opensearch_cluster_version_incompatible"
    }
    assert "4.99" not in error.getvalue()
    assert "never-print-this-password" not in error.getvalue()
    assert gateway.create_calls == []
    assert gateway.alias_calls == []
    assert gateway.closed is True


@pytest.mark.parametrize("command", ["check", "plan", "bootstrap"])
def test_settings_failure_is_generic_for_every_command(
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    output = StringIO()
    error = StringIO()
    secret_host = "https://private-search.example.test:9200"

    def fail_settings() -> Settings:
        raise RuntimeError(secret_host)

    monkeypatch.setattr(opensearch_cli, "get_settings", fail_settings)
    exit_code = main([command], stdout=output, stderr=error)

    assert exit_code != 0
    assert output.getvalue() == ""
    assert json.loads(error.getvalue()) == {
        "error_code": "opensearch_configuration_invalid"
    }
    assert secret_host not in error.getvalue()
    assert "Traceback" not in error.getvalue()


def test_settings_failure_never_exposes_certificate_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate_path = r"C:\private\certificates\client.pem"

    def fail_settings() -> Settings:
        raise RuntimeError(certificate_path)

    monkeypatch.setattr(opensearch_cli, "get_settings", fail_settings)
    error = StringIO()
    assert main(["check"], stderr=error) != 0
    assert certificate_path not in error.getvalue()
    assert json.loads(error.getvalue()) == {
        "error_code": "opensearch_configuration_invalid"
    }


def test_client_factory_initialization_failure_is_generic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_path = r"C:\private\opensearch-ca.pem"

    def fail_factory(_configured: Settings) -> object:
        raise RuntimeError(private_path)

    monkeypatch.setattr(opensearch_cli, "OpenSearchClientFactory", fail_factory)
    error = StringIO()
    assert main(["plan"], settings=settings(), stderr=error) != 0
    assert json.loads(error.getvalue()) == {
        "error_code": "opensearch_configuration_invalid"
    }
    assert private_path not in error.getvalue()
    assert "Traceback" not in error.getvalue()


def test_gateway_is_closed_when_plan_fails() -> None:
    class FailingGateway(FakeOpenSearchGateway):
        def index_state(self, index_name: str):
            raise RuntimeError("https://private-search.example.test:9200")

    gateway = FailingGateway()
    error = StringIO()
    exit_code = main(
        ["plan"],
        settings=settings(),
        gateway_factory=lambda: gateway,
        stderr=error,
    )
    assert exit_code != 0
    assert gateway.closed is True
    assert json.loads(error.getvalue()) == {
        "error_code": "opensearch_maintenance_failed"
    }
    assert "private-search.example.test" not in error.getvalue()


def test_gateway_close_failure_does_not_override_success() -> None:
    class CloseFailingGateway(FakeOpenSearchGateway):
        def close(self) -> None:
            self.closed = True
            raise RuntimeError("private close failure")

    gateway = CloseFailingGateway()
    output = StringIO()
    assert main(
        ["plan"],
        settings=settings(),
        gateway_factory=lambda: gateway,
        stdout=output,
    ) == 0
    assert gateway.closed is True
    assert json.loads(output.getvalue())["items"][0]["status"] == "missing"


def test_check_close_failure_does_not_override_healthy_result() -> None:
    class CloseFailingGateway(FakeOpenSearchGateway):
        def close(self) -> None:
            self.closed = True
            raise RuntimeError("private close failure")

    configured = settings()
    gateway = CloseFailingGateway()
    for definition in build_index_definitions(configured):
        seed_ready_definition(gateway, definition)
    output = StringIO()
    assert main(
        ["check"],
        settings=configured,
        gateway_factory=lambda: gateway,
        stdout=output,
    ) == 0
    assert gateway.closed is True
    assert json.loads(output.getvalue())["status"] == "healthy"
