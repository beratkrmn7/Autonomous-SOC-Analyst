import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from agent.config import Settings
from server import create_app


def production_settings(**overrides) -> dict:
    values = {
        "app_env": "production",
        "auth_mode": "api_key",
        "https_required": True,
        "trusted_hosts": ["api.example.test"],
        "llm_enabled": False,
    }
    values.update(overrides)
    return values


def error_code(error: ValidationError) -> str:
    details = error.errors(include_input=False)[0]
    return str(details.get("ctx", {}).get("error", ""))


def test_production_disabled_authentication_fails_without_secret_input(
    secret_sentinels,
):
    with pytest.raises(ValidationError) as caught:
        Settings(**production_settings(
            auth_mode="disabled",
            database_url=secret_sentinels.database_url,
        ))

    assert "production_auth_mode_required" in error_code(caught.value)
    assert secret_sentinels.database_url not in str(caught.value)


def test_production_wildcard_trusted_host_fails():
    with pytest.raises(ValidationError) as caught:
        Settings(**production_settings(trusted_hosts=["*"]))
    assert "production_wildcard_trusted_host_forbidden" in error_code(
        caught.value
    )


def test_production_wildcard_cors_origin_fails():
    with pytest.raises(ValidationError) as caught:
        Settings(**production_settings(cors_allowed_origins=["*"]))
    assert "production_wildcard_cors_forbidden" in error_code(caught.value)


def test_production_insecure_oidc_configuration_fails():
    with pytest.raises(ValidationError) as caught:
        Settings(**production_settings(
            auth_mode="oidc",
            oidc_issuer="http://identity.example.test",
            oidc_audience="soc-api",
            oidc_discovery_url=(
                "http://identity.example.test/.well-known/openid-configuration"
            ),
            oidc_require_https=False,
        ))
    assert "production_oidc_https_required" in error_code(caught.value)


def test_production_docs_are_disabled_by_default():
    settings = Settings(**production_settings())
    assert settings.api_docs_enabled is False
    application = create_app(settings)

    with TestClient(
        application,
        base_url="https://api.example.test",
    ) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/redoc").status_code == 404
        assert client.get("/openapi.json").status_code == 404


def test_development_docs_are_available_when_enabled(app_factory):
    application = app_factory()
    with TestClient(application, base_url="http://localhost") as client:
        assert client.get("/docs").status_code == 200
        assert client.get("/redoc").status_code == 200
        assert client.get("/openapi.json").status_code == 200


def test_valid_production_configuration_starts():
    settings = Settings(**production_settings())
    application = create_app(settings)

    with TestClient(
        application,
        base_url="https://api.example.test",
    ) as client:
        response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "live"}


def test_wildcard_origin_with_credentials_is_always_rejected():
    with pytest.raises(ValidationError) as caught:
        Settings(
            app_env="development",
            cors_allowed_origins=["*"],
            cors_allow_credentials=True,
        )
    assert "cors_wildcard_credentials_forbidden" in error_code(caught.value)


def test_forwarded_headers_require_explicit_trusted_proxy_ips():
    with pytest.raises(ValidationError) as caught:
        Settings(forwarded_headers_enabled=True)
    assert "trusted_proxy_ips_required" in error_code(caught.value)


def test_docs_state_does_not_disable_endpoint_authentication(
    app_factory,
):
    settings = Settings(
        app_env="test",
        auth_mode="api_key",
        api_docs_enabled=False,
        llm_enabled=False,
    )
    application = app_factory(settings)

    with TestClient(application) as client:
        protected = client.get("/api/v1/incidents/")
        docs = client.get("/docs")

    assert protected.status_code == 401
    assert docs.status_code == 404
