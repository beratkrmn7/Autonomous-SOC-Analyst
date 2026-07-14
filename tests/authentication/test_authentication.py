import datetime
import json
import logging
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

from agent.api.deps import get_authenticated_principal, get_uow
from agent.application.authentication import (
    AUTHENTICATION_ERROR,
    ApiKeyAuthenticationService,
    AuthenticatedPrincipal,
    AuthenticationRequiredError,
    hash_api_key,
)
from agent.config import Settings, get_settings
from agent.persistence.database import Base
from agent.persistence.orm_models import ApiCredential, AuditEvent
from agent.persistence.unit_of_work import UnitOfWork
from agent.security.api_keys import main as api_key_cli
from server import app


@pytest.fixture
def session_factory(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'authentication.db'}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    yield factory
    engine.dispose()


@pytest.fixture
def api_key_client(session_factory, monkeypatch):
    monkeypatch.setenv("AUTH_MODE", "api_key")
    get_settings.cache_clear()
    app.dependency_overrides[get_uow] = lambda: UnitOfWork(session_factory)
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()
    get_settings.cache_clear()


def generate_credential(session_factory, **kwargs):
    return ApiKeyAuthenticationService(
        UnitOfWork(session_factory)
    ).generate_credential(name="Test SOC integration", **kwargs)


def bearer(api_key):
    return {"Authorization": f"Bearer {api_key}"}


def assert_generic_unauthorized(response):
    assert response.status_code == 401
    assert response.json() == AUTHENTICATION_ERROR
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_key_generation_returns_high_entropy_key_once(session_factory):
    first = generate_credential(session_factory)
    second = generate_credential(session_factory)

    marker, prefix, secret = first.api_key.split("_", 2)
    assert marker == "soc"
    assert prefix == first.credential.key_prefix
    assert len(prefix) == 12
    assert len(secret) >= 43
    assert first.api_key != second.api_key
    assert not hasattr(first.credential, "api_key")
    listed = ApiKeyAuthenticationService(
        UnitOfWork(session_factory)
    ).list_credentials()
    assert all(not hasattr(credential, "api_key") for credential in listed)


def test_database_stores_only_prefix_and_hash(session_factory):
    generated = generate_credential(session_factory)
    session = session_factory()
    try:
        stored = session.get(ApiCredential, generated.credential.credential_id)
        assert stored is not None
        assert stored.key_prefix == generated.credential.key_prefix
        assert stored.key_hash == hash_api_key(generated.api_key)
        assert stored.key_hash != generated.api_key
        assert generated.api_key not in str(stored.__dict__)
        assert "api_key" not in {column.name for column in ApiCredential.__table__.columns}
    finally:
        session.close()


def test_valid_active_key_authenticates(session_factory):
    generated = generate_credential(session_factory)

    principal = ApiKeyAuthenticationService(
        UnitOfWork(session_factory)
    ).authenticate(generated.api_key)

    assert principal == AuthenticatedPrincipal(
        subject_type="api_client",
        subject_id=generated.credential.credential_id,
        display_name="Test SOC integration",
        authentication_method="api_key",
        roles=("service",),
        credential_id=generated.credential.credential_id,
    )


def test_missing_authorization_header_returns_generic_401(api_key_client):
    response = api_key_client.get(
        "/api/v1/incidents/", params={"api_key": "not-accepted"}
    )
    assert_generic_unauthorized(response)


@pytest.mark.parametrize(
    "authorization",
    ["", "Basic abc", "Bearer", "Bearer ", "Bearer one two"],
)
def test_malformed_bearer_header_returns_generic_401(
    api_key_client, authorization
):
    response = api_key_client.get(
        "/api/v1/incidents/", headers={"Authorization": authorization}
    )
    assert_generic_unauthorized(response)


def test_invalid_key_returns_same_generic_401(api_key_client):
    invalid_key = f"soc_deadbeefdead_{secrets.token_urlsafe(32)}"
    response = api_key_client.get(
        "/api/v1/incidents/",
        headers=bearer(invalid_key),
    )
    assert_generic_unauthorized(response)


def test_revoked_key_returns_same_generic_401(
    api_key_client, session_factory
):
    generated = generate_credential(session_factory)
    ApiKeyAuthenticationService(UnitOfWork(session_factory)).revoke_credential(
        generated.credential.credential_id
    )

    response = api_key_client.get(
        "/api/v1/incidents/", headers=bearer(generated.api_key)
    )

    assert_generic_unauthorized(response)


def test_expired_key_returns_same_generic_401(
    api_key_client, session_factory
):
    generated = generate_credential(
        session_factory,
        expires_at=datetime.datetime.now(
            datetime.timezone.utc
        ) - datetime.timedelta(minutes=1),
    )

    response = api_key_client.get(
        "/api/v1/incidents/", headers=bearer(generated.api_key)
    )

    assert_generic_unauthorized(response)
    session = session_factory()
    try:
        stored = session.get(ApiCredential, generated.credential.credential_id)
        assert stored is not None
        assert stored.status == "expired"
    finally:
        session.close()


def test_public_liveness_and_readiness_do_not_require_authentication(
    api_key_client,
):
    live = api_key_client.get("/health/live")
    ready = api_key_client.get("/health/ready")

    assert live.status_code == 200
    assert live.json() == {"status": "live"}
    assert ready.status_code in (200, 503)
    assert ready.json() != AUTHENTICATION_ERROR


def test_protected_endpoint_rejects_unauthenticated_request(api_key_client):
    assert_generic_unauthorized(api_key_client.get("/api/v1/incidents/"))


def test_legacy_analysis_endpoint_rejects_unauthenticated_request(
    api_key_client,
):
    assert_generic_unauthorized(api_key_client.post("/ingest/file"))


def test_protected_endpoint_accepts_valid_credential(
    api_key_client, session_factory
):
    generated = generate_credential(session_factory)

    response = api_key_client.get(
        "/api/v1/incidents/", headers=bearer(generated.api_key)
    )

    assert response.status_code == 200
    assert response.json() == []


def test_disabled_mode_returns_explicit_local_development_principal(
    session_factory,
):
    principal = get_authenticated_principal(
        authorization=None,
        auth_settings=Settings(auth_mode="disabled"),
        uow=UnitOfWork(session_factory),
    )

    assert principal.subject_type == "local_development"
    assert principal.authentication_method == "disabled"
    assert principal.credential_id is None
    assert "Local development" in principal.display_name


def test_last_used_at_updates_safely(session_factory):
    generated = generate_credential(session_factory)
    service = ApiKeyAuthenticationService(UnitOfWork(session_factory))

    service.authenticate(generated.api_key)
    session = session_factory()
    try:
        first = session.get(ApiCredential, generated.credential.credential_id)
        assert first is not None
        first_used_at = first.last_used_at
        first_version = first.version
    finally:
        session.close()

    service = ApiKeyAuthenticationService(UnitOfWork(session_factory))
    service.authenticate(generated.api_key)
    session = session_factory()
    try:
        second = session.get(ApiCredential, generated.credential.credential_id)
        assert second is not None
        assert first_used_at is not None
        assert second.last_used_at is not None
        assert second.last_used_at >= first_used_at
        assert second.version == first_version + 1
    finally:
        session.close()


def test_revoke_is_idempotent_and_audited_once(session_factory):
    generated = generate_credential(session_factory)
    first = ApiKeyAuthenticationService(
        UnitOfWork(session_factory)
    ).revoke_credential(generated.credential.credential_id)
    second = ApiKeyAuthenticationService(
        UnitOfWork(session_factory)
    ).revoke_credential(generated.credential.credential_id)

    assert first.status == second.status == "revoked"
    assert first.revoked_at == second.revoked_at
    session = session_factory()
    try:
        assert session.query(AuditEvent).filter_by(
            entity_id=generated.credential.credential_id,
            event_type="api_credential_revoked",
        ).count() == 1
    finally:
        session.close()


def test_secrets_never_appear_in_responses_audits_or_logs(
    api_key_client, session_factory, caplog
):
    generated = generate_credential(
        session_factory, description="Safe test credential"
    )
    session = session_factory()
    try:
        stored = session.get(ApiCredential, generated.credential.credential_id)
        assert stored is not None
        key_hash = stored.key_hash
    finally:
        session.close()
    ApiKeyAuthenticationService(UnitOfWork(session_factory)).revoke_credential(
        generated.credential.credential_id
    )

    with caplog.at_level(
        logging.WARNING, logger="agent.application.authentication"
    ):
        response = api_key_client.get(
            "/api/v1/incidents/", headers=bearer(generated.api_key)
        )

    assert_generic_unauthorized(response)
    session = session_factory()
    try:
        audit_text = json.dumps([
            {
                "details": event.details,
                "old_values": event.old_values_json,
                "new_values": event.new_values_json,
            }
            for event in session.query(AuditEvent).filter_by(
                entity_id=generated.credential.credential_id
            )
        ])
    finally:
        session.close()

    rendered = " ".join((response.text, audit_text, caplog.text))
    assert generated.api_key not in rendered
    assert key_hash not in rendered
    assert "Authorization" not in rendered
    assert caplog.messages == ["credential_revoked"]


def test_credential_cli_list_never_displays_secret_or_hash(
    session_factory, capsys
):
    generated = generate_credential(session_factory)
    session = session_factory()
    try:
        stored = session.get(ApiCredential, generated.credential.credential_id)
        assert stored is not None
        key_hash = stored.key_hash
    finally:
        session.close()

    exit_code = api_key_cli(
        ["list"], uow_factory=lambda: UnitOfWork(session_factory)
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    assert generated.credential.credential_id in output
    assert generated.credential.key_prefix in output
    assert generated.api_key not in output
    assert key_hash not in output


def test_api_credential_migration_upgrades_and_downgrades(
    tmp_path, monkeypatch
):
    db_path = tmp_path / "migration.db"
    database_url = f"sqlite:///{db_path}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)

    try:
        command.upgrade(config, "head")
        engine = create_engine(database_url)
        table_names = inspect(engine).get_table_names()
        columns = {
            column["name"]
            for column in inspect(engine).get_columns("api_credentials")
        }
        engine.dispose()
        assert "api_credentials" in table_names
        assert {
            "credential_id",
            "name",
            "key_prefix",
            "key_hash",
            "status",
            "version",
        }.issubset(columns)

        command.downgrade(config, "c4b31f7d2a9e")
        engine = create_engine(database_url)
        assert "api_credentials" not in inspect(engine).get_table_names()
        engine.dispose()
    finally:
        get_settings.cache_clear()


def test_concurrent_valid_authentications_all_succeed(session_factory):
    generated = generate_credential(session_factory)
    request_count = 5
    barrier = threading.Barrier(request_count)

    def authenticate():
        barrier.wait()
        return ApiKeyAuthenticationService(
            UnitOfWork(session_factory)
        ).authenticate(generated.api_key)

    with ThreadPoolExecutor(max_workers=request_count) as executor:
        futures = [executor.submit(authenticate) for _ in range(request_count)]
        principals = [future.result() for future in futures]

    assert all(
        isinstance(principal, AuthenticatedPrincipal)
        for principal in principals
    )
    session = session_factory()
    try:
        stored = session.get(ApiCredential, generated.credential.credential_id)
        assert stored is not None
        assert stored.last_used_at is not None
    finally:
        session.close()

    revoked = ApiKeyAuthenticationService(
        UnitOfWork(session_factory)
    ).revoke_credential(generated.credential.credential_id)
    assert revoked.status == "revoked"

    for _ in range(request_count):
        with pytest.raises(AuthenticationRequiredError):
            ApiKeyAuthenticationService(
                UnitOfWork(session_factory)
            ).authenticate(generated.api_key)


def test_concurrent_revoke_and_authentication_have_safe_outcomes(
    session_factory,
):
    generated = generate_credential(session_factory)
    barrier = threading.Barrier(2)

    def authenticate():
        barrier.wait()
        try:
            return ApiKeyAuthenticationService(
                UnitOfWork(session_factory)
            ).authenticate(generated.api_key)
        except AuthenticationRequiredError:
            return None

    def revoke():
        barrier.wait()
        return ApiKeyAuthenticationService(
            UnitOfWork(session_factory)
        ).revoke_credential(generated.credential.credential_id)

    with ThreadPoolExecutor(max_workers=2) as executor:
        authentication_future = executor.submit(authenticate)
        revocation_future = executor.submit(revoke)
        authentication_result = authentication_future.result()
        revocation_result = revocation_future.result()

    assert authentication_result is None or isinstance(
        authentication_result, AuthenticatedPrincipal
    )
    assert revocation_result.status == "revoked"
    with pytest.raises(AuthenticationRequiredError):
        ApiKeyAuthenticationService(UnitOfWork(session_factory)).authenticate(
            generated.api_key
        )
