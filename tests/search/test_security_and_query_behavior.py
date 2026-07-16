from __future__ import annotations

import inspect

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import event

from agent.api.deps import get_authenticated_principal, get_uow
from agent.application.authentication import (
    AuthenticatedPrincipal,
    ApiKeyAuthenticationService,
)
from agent.config import get_settings
from agent.config import Settings
from agent.persistence.search_repositories import SqlAlchemySearchRepository
from agent.persistence.unit_of_work import UnitOfWork
from agent.security.authorization import Role
from server import create_app
from tests.search.conftest import (
    make_session_factory,
    make_settings,
)


def bearer(value: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {value}"}


def authenticated_environment(tmp_path, role: Role):
    factory, engine = make_session_factory(tmp_path / f"{role.value}.db")
    settings = make_settings(auth_mode="api_key")
    generated = ApiKeyAuthenticationService(UnitOfWork(factory)).generate_credential(
        name=f"{role.value} search test",
        role=role,
    )
    application = create_app(settings)
    application.dependency_overrides[get_settings] = lambda: settings
    application.dependency_overrides[get_uow] = lambda: UnitOfWork(factory)
    return application, generated.api_key, engine


def test_unauthenticated_search_returns_401(tmp_path):
    application, _api_key, engine = authenticated_environment(tmp_path, Role.VIEWER)
    with TestClient(application) as client:
        response = client.get("/api/v1/search/incidents")
    engine.dispose()
    assert response.status_code == 401


def test_production_requires_explicit_cursor_secret():
    with pytest.raises(ValidationError) as caught:
        Settings(
            app_env="production",
            auth_mode="api_key",
            https_required=True,
            trusted_hosts=["api.example.test"],
            llm_enabled=False,
            rate_limiting_enabled=True,
            rate_limit_backend="redis",
            rate_limit_key_secret="production-rate-limit-secret-000001",
            search_cursor_secret=None,
        )
    assert "production_search_cursor_secret_required" in str(caught.value)


def test_search_cursor_secret_and_page_settings_are_validated():
    with pytest.raises(ValidationError) as caught:
        make_settings(search_cursor_secret="too-short")
    assert "search_cursor_secret_too_short" in str(caught.value)
    with pytest.raises(ValidationError) as caught:
        make_settings(search_default_page_size=51, search_max_page_size=50)
    assert "search_default_page_size_exceeds_maximum" in str(caught.value)


def test_authenticated_unauthorized_search_returns_403(tmp_path):
    factory, engine = make_session_factory(tmp_path / "unauthorized.db")
    settings = make_settings(auth_mode="api_key")
    application = create_app(settings)
    application.dependency_overrides[get_settings] = lambda: settings
    application.dependency_overrides[get_uow] = lambda: UnitOfWork(factory)
    application.dependency_overrides[get_authenticated_principal] = lambda: (
        AuthenticatedPrincipal(
            subject_type="test",
            subject_id="no-permissions",
            display_name="No permissions",
            authentication_method="test",
            roles=(),
            credential_id=None,
        )
    )
    with TestClient(application) as client:
        response = client.get("/api/v1/search/incidents")
    engine.dispose()
    assert response.status_code == 403


def test_viewer_can_search_all_resources(tmp_path):
    application, api_key, engine = authenticated_environment(tmp_path, Role.VIEWER)
    with TestClient(application) as client:
        for resource in ("incidents", "events", "signals", "jobs"):
            response = client.get(
                f"/api/v1/search/{resource}", headers=bearer(api_key)
            )
            assert response.status_code == 200, (resource, response.text)
    engine.dispose()


def test_file_digest_filter_is_internal_only(tmp_path):
    application, api_key, engine = authenticated_environment(tmp_path, Role.VIEWER)
    with TestClient(application) as client:
        response = client.get(
            "/api/v1/search/jobs",
            params={"file_sha256": "a" * 64},
            headers=bearer(api_key),
        )
    engine.dispose()
    assert response.status_code == 403


def test_search_uses_read_rate_limit(tmp_path):
    factory, engine = make_session_factory(tmp_path / "rate.db")
    settings = make_settings(rate_limit_reads=1, rate_limit_general_requests=100)
    application = create_app(settings)
    application.dependency_overrides[get_settings] = lambda: settings
    application.dependency_overrides[get_uow] = lambda: UnitOfWork(factory)
    with TestClient(application) as client:
        first = client.get("/api/v1/search/incidents")
        second = client.get("/api/v1/search/incidents")
    engine.dispose()
    assert first.status_code == 200
    assert second.status_code == 429


def test_sql_like_input_is_bound_as_data(seeded_env):
    response = seeded_env.client.get(
        "/api/v1/search/events", params={"source_name": "x' OR 1=1 --"}
    )
    assert response.status_code == 200
    assert response.json()["items"] == []


def test_responses_omit_secrets_raw_logs_and_internal_fields(seeded_env):
    event_response = seeded_env.client.get("/api/v1/search/events").json()
    job_response = seeded_env.client.get("/api/v1/search/jobs").json()
    serialized = f"{event_response}{job_response}"
    for forbidden in (
        "raw_record_hash",
        "original_fields",
        "idempotency_key",
        "staging",
        "worker_id",
        "file_sha256",
        "error_counts",
        "private-worker",
        "secret-idempotency",
    ):
        assert forbidden not in serialized


def test_search_preserves_request_and_security_headers(search_env):
    response = search_env.client.get(
        "/api/v1/search/incidents", headers={"X-Request-ID": "search-request-123"}
    )
    assert response.status_code == 200
    assert response.headers["x-request-id"] == "search-request-123"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_repository_has_no_unrestricted_all_path():
    source = inspect.getsource(SqlAlchemySearchRepository)
    assert ".all(" not in source
    assert ".limit(" in source
    assert "fetchmany" in source


def test_default_job_search_does_not_calculate_total(seeded_env):
    engine = seeded_env.session_factory.kw["bind"]
    statements = []

    def record(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", record)
    try:
        response = seeded_env.client.get("/api/v1/search/jobs")
    finally:
        event.remove(engine, "before_cursor_execute", record)
    assert response.status_code == 200
    selects = [statement for statement in statements if statement.lstrip().upper().startswith("SELECT")]
    assert len(selects) == 1
    assert "COUNT(" not in selects[0].upper()
