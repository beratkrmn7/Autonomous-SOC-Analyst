import datetime
import json
import logging
import re

from fastapi import HTTPException
from fastapi.testclient import TestClient

import agent.api.health as health_module
from agent.api.deps import get_dispatcher, get_staging_store, get_uow
from agent.api.security import (
    DeploymentBoundaryMiddleware,
    INTERNAL_ERROR,
    REQUEST_TOO_LARGE_ERROR,
)
from agent.application.authentication import (
    AUTHENTICATION_ERROR,
    ApiKeyAuthenticationService,
    AuthenticatedPrincipal,
    AuthenticationRequiredError,
)
from agent.application.staging import LocalFileStagingStore
from agent.config import Settings
from agent.persistence.orm_models import AuditEvent, Incident, IngestionJob
from agent.persistence.unit_of_work import UnitOfWork
from agent.security.authorization import FORBIDDEN_ERROR, Role
from agent.security.oidc import OidcProviderError
from tests.api_security.helpers import make_settings


def assert_no_secrets(rendered: str, secret_sentinels) -> None:
    for secret in secret_sentinels.values:
        assert secret not in rendered


def generate_credential(session_factory, role: Role):
    return ApiKeyAuthenticationService(
        UnitOfWork(session_factory)
    ).generate_credential(
        name=f"API security {role.value}",
        role=role,
    )


def seed_incident(session_factory) -> str:
    incident_id = "inc-api-security"
    now = datetime.datetime.now(datetime.timezone.utc)
    session = session_factory()
    try:
        session.add(Incident(
            incident_id=incident_id,
            title="API security incident",
            incident_type="network",
            severity="medium",
            status="new",
            confidence=0.8,
            version=1,
            first_seen=now,
            last_seen=now,
            primary_entity="host:test",
        ))
        session.commit()
    finally:
        session.close()
    return incident_id


class AcceptingOidcService:
    def authenticate(self, token: str) -> AuthenticatedPrincipal:
        if token != "header.payload.signature":
            raise AuthenticationRequiredError()
        return AuthenticatedPrincipal(
            subject_type="human_user",
            subject_id="oidc-user-1",
            display_name="OIDC Viewer",
            authentication_method="oidc_jwt",
            roles=("viewer",),
            credential_id=None,
        )

    def check_provider(self) -> None:
        return None


class RejectingOidcService:
    def authenticate(self, token: str) -> AuthenticatedPrincipal:
        raise AuthenticationRequiredError()

    def check_provider(self) -> None:
        return None


def oidc_settings(auth_mode: str = "oidc") -> Settings:
    return make_settings(
        auth_mode=auth_mode,
        oidc_issuer="https://identity.example.test",
        oidc_audience="soc-api",
        oidc_discovery_url=(
            "https://identity.example.test/.well-known/openid-configuration"
        ),
        oidc_role_mapping={"soc-viewer": "viewer"},
    )


def test_oversized_json_request_returns_413(app_factory):
    application = app_factory(make_settings(
        max_request_body_bytes=1024,
        max_upload_bytes=1024,
    ))
    with TestClient(application) as client:
        response = client.post(
            "/analyze",
            content=b"{" + b"a" * 2048 + b"}",
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 413
    assert response.json() == REQUEST_TOO_LARGE_ERROR


def test_oversized_multipart_request_returns_413(app_factory):
    application = app_factory(make_settings(
        max_request_body_bytes=1024,
        max_upload_bytes=1024,
    ))
    with TestClient(application) as client:
        response = client.post(
            "/api/v1/analysis-jobs/file",
            files={"file": ("events.jsonl", b"x" * 2048, "application/json")},
        )
    assert response.status_code == 413
    assert response.json() == REQUEST_TOO_LARGE_ERROR


def test_chunked_streaming_body_cannot_bypass_limit(app_factory):
    application = app_factory(make_settings(
        max_request_body_bytes=1024,
        max_upload_bytes=1024,
    ))

    def chunks():
        yield b'{"raw_logs":"'
        yield b"x" * 700
        yield b"y" * 700
        yield b'"}'

    with TestClient(application) as client:
        response = client.post(
            "/analyze",
            content=chunks(),
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 413
    assert response.json() == REQUEST_TOO_LARGE_ERROR


def test_legacy_upload_endpoint_cannot_bypass_upload_limit(app_factory):
    application = app_factory(make_settings(
        max_request_body_bytes=4096,
        max_upload_bytes=1024,
    ))
    with TestClient(application) as client:
        response = client.post(
            "/ingest/file",
            files={"file": ("events.jsonl", b"x" * 1536, "application/json")},
        )
    assert response.status_code == 413
    assert response.json() == REQUEST_TOO_LARGE_ERROR


def test_unexpected_exception_returns_sanitized_internal_error(
    app_factory,
    secret_sentinels,
    caplog,
):
    application = app_factory()

    @application.get("/test-unexpected-error")
    def unexpected_error():
        raise RuntimeError(secret_sentinels.blob)

    with caplog.at_level(logging.ERROR, logger="agent.api.security"):
        with TestClient(application) as client:
            response = client.get("/test-unexpected-error")

    assert response.status_code == 500
    assert response.json() == INTERNAL_ERROR
    assert response.headers["x-content-type-options"] == "nosniff"
    rendered = f"{response.text} {dict(response.headers)} {caplog.text}"
    assert_no_secrets(rendered, secret_sentinels)
    record = next(
        item for item in caplog.records
        if item.getMessage() == "unhandled_request_error"
    )
    assert record.exception_type == "RuntimeError"
    assert record.request_id == response.headers["x-request-id"]
    assert record.exc_info is None


def test_expected_domain_error_retains_existing_code(app_factory):
    application = app_factory()

    @application.get("/test-domain-error")
    def domain_error():
        raise HTTPException(
            status_code=409,
            detail={
                "code": "invalid_incident_transition",
                "message": "The transition is not allowed.",
            },
        )

    with TestClient(application) as client:
        response = client.get("/test-domain-error")
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "invalid_incident_transition"


def test_analysis_conflict_contract_remains_machine_readable(
    app_factory,
    monkeypatch,
):
    from agent.application.analysis_service import AnalysisService
    from agent.application.errors import DuplicateAnalysisError

    def duplicate_analysis(*args, **kwargs):
        raise DuplicateAnalysisError("processing")

    monkeypatch.setattr(AnalysisService, "analyze_file", duplicate_analysis)
    application = app_factory()
    with TestClient(application) as client:
        response = client.post(
            "/detect/file",
            files={"file": ("events.jsonl", b"{}\n", "application/json")},
        )
    assert response.status_code == 409
    assert response.json()["detail"] == {
        "code": "analysis_already_in_progress",
        "message": "Analysis is already in progress.",
    }


def test_server_generates_request_id(app_factory):
    application = app_factory()
    with TestClient(application) as client:
        response = client.get("/health/live")
    request_id = response.headers["x-request-id"]
    assert re.fullmatch(r"[a-f0-9]{32}", request_id)


def test_safe_client_request_id_is_accepted(app_factory):
    application = app_factory()
    request_id = "client-request_2026.07:15"
    with TestClient(application) as client:
        response = client.get(
            "/health/live",
            headers={"X-Request-ID": request_id},
        )
    assert response.headers["x-request-id"] == request_id


def test_invalid_client_request_id_is_replaced(app_factory):
    application = app_factory()
    invalid_id = "contains spaces and is not trusted"
    with TestClient(application) as client:
        response = client.get(
            "/health/live",
            headers={"X-Request-ID": invalid_id},
        )
    assert response.headers["x-request-id"] != invalid_id
    assert re.fullmatch(r"[a-f0-9]{32}", response.headers["x-request-id"])


def test_request_id_newline_injection_is_replaced():
    crafted_scope = {
        "type": "http",
        "headers": [
            (b"x-request-id", b"safe\r\nX-Injected: secret"),
        ],
    }
    request_id = DeploymentBoundaryMiddleware._request_id(crafted_scope)
    assert "\r" not in request_id
    assert "\n" not in request_id
    assert re.fullmatch(r"[a-f0-9]{32}", request_id)


def test_authentication_failure_never_exposes_secrets(
    app_factory,
    session_factory,
    secret_sentinels,
    caplog,
):
    application = app_factory(make_settings(auth_mode="api_key"))
    with caplog.at_level(logging.WARNING):
        with TestClient(application) as client:
            response = client.get(
                "/api/v1/incidents/",
                headers={"Authorization": f"Bearer {secret_sentinels.api_key}"},
            )

    assert response.status_code == 401
    assert response.json() == AUTHENTICATION_ERROR
    rendered = f"{response.text} {dict(response.headers)} {caplog.text}"
    assert_no_secrets(rendered, secret_sentinels)
    session = session_factory()
    try:
        audits = json.dumps([
            event.details for event in session.query(AuditEvent).all()
        ])
    finally:
        session.close()
    assert_no_secrets(audits, secret_sentinels)


def test_authorization_failure_never_exposes_secrets(
    app_factory,
    session_factory,
    secret_sentinels,
    caplog,
):
    viewer = generate_credential(session_factory, Role.VIEWER)
    application = app_factory(make_settings(auth_mode="api_key"))
    with caplog.at_level(logging.WARNING):
        with TestClient(application) as client:
            response = client.get(
                "/api/v1/workers",
                headers={"Authorization": f"Bearer {viewer.api_key}"},
            )
    assert response.status_code == 403
    assert response.json() == FORBIDDEN_ERROR
    rendered = f"{response.text} {dict(response.headers)} {caplog.text}"
    assert_no_secrets(rendered, secret_sentinels)


def test_upload_failure_never_exposes_content_or_paths(
    app_factory,
    secret_sentinels,
    caplog,
):
    application = app_factory(make_settings(
        max_request_body_bytes=4096,
        max_upload_bytes=1024,
    ))
    with caplog.at_level(logging.WARNING):
        with TestClient(application) as client:
            response = client.post(
                "/ingest/file",
                files={
                    "file": (
                        "events.jsonl",
                        secret_sentinels.blob.encode() * 40,
                        "application/json",
                    )
                },
            )
    assert response.status_code == 413
    rendered = f"{response.text} {dict(response.headers)} {caplog.text}"
    assert_no_secrets(rendered, secret_sentinels)


def test_database_failure_is_sanitized(
    app_factory,
    secret_sentinels,
    caplog,
):
    class FailingSession:
        def execute(self, statement):
            raise RuntimeError(secret_sentinels.database_url)

    class FailingUnitOfWork:
        session = FailingSession()

    application = app_factory()
    application.dependency_overrides[get_uow] = lambda: FailingUnitOfWork()
    with caplog.at_level(logging.WARNING):
        with TestClient(application) as client:
            response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json()["components"]["database"] == "down"
    rendered = f"{response.text} {dict(response.headers)} {caplog.text}"
    assert_no_secrets(rendered, secret_sentinels)


def test_queue_publication_failure_is_sanitized_and_persists_safe_code(
    app_factory,
    session_factory,
    secret_sentinels,
    tmp_path,
    caplog,
):
    class FailingDispatcher:
        def enqueue(self, job_id: str) -> None:
            raise RuntimeError(secret_sentinels.redis_url)

    application = app_factory()
    application.dependency_overrides[get_staging_store] = lambda: (
        LocalFileStagingStore(str(tmp_path / "staging"))
    )
    application.dependency_overrides[get_dispatcher] = lambda: FailingDispatcher()
    with caplog.at_level(logging.WARNING):
        with TestClient(application) as client:
            response = client.post(
                "/api/v1/analysis-jobs/file",
                files={
                    "file": (
                        "events.jsonl",
                        secret_sentinels.blob.encode(),
                        "application/json",
                    )
                },
            )
    assert response.status_code == 503
    assert response.json()["error_code"] == "queue_publish_failed"
    rendered = f"{response.text} {dict(response.headers)} {caplog.text}"
    assert_no_secrets(rendered, secret_sentinels)

    session = session_factory()
    try:
        error_codes = [
            job.error_code for job in session.query(IngestionJob).all()
        ]
        audit_values = json.dumps([
            event.details for event in session.query(AuditEvent).all()
        ])
    finally:
        session.close()
    assert error_codes == ["queue_publish_failed"]
    assert_no_secrets(json.dumps(error_codes), secret_sentinels)
    assert_no_secrets(audit_values, secret_sentinels)


def test_oidc_provider_failure_is_sanitized(
    app_factory,
    secret_sentinels,
    monkeypatch,
    caplog,
):
    class FailingOidcProvider:
        def check_provider(self) -> None:
            raise OidcProviderError(secret_sentinels.oidc_url)

        def authenticate(self, token: str) -> AuthenticatedPrincipal:
            raise AuthenticationRequiredError()

    settings = oidc_settings()
    application = app_factory(
        settings,
        oidc_service=FailingOidcProvider(),
    )
    monkeypatch.setattr(health_module, "get_settings", lambda: settings)
    with caplog.at_level(logging.WARNING):
        with TestClient(application) as client:
            response = client.get("/health/ready")
    assert response.status_code == 503
    assert response.json()["components"]["identity_provider"] == "down"
    rendered = f"{response.text} {dict(response.headers)} {caplog.text}"
    assert_no_secrets(rendered, secret_sentinels)


def test_request_id_is_persisted_in_audit_without_request_secrets(
    app_factory,
    session_factory,
    secret_sentinels,
):
    analyst = generate_credential(session_factory, Role.ANALYST)
    incident_id = seed_incident(session_factory)
    request_id = "audit-request-2026"
    application = app_factory(make_settings(auth_mode="api_key"))
    with TestClient(application) as client:
        response = client.patch(
            f"/api/v1/incidents/{incident_id}/status",
            headers={
                "Authorization": f"Bearer {analyst.api_key}",
                "X-Request-ID": request_id,
            },
            json={
                "status": "triaged",
                "expected_version": 1,
                "details": {"secret": secret_sentinels.blob},
            },
        )
    assert response.status_code == 200
    assert response.headers["x-request-id"] == request_id

    session = session_factory()
    try:
        audit = session.query(AuditEvent).filter_by(
            event_type="status_transition"
        ).one()
        rendered = json.dumps({
            "request_id": audit.request_id,
            "details": audit.details,
            "old": audit.old_values_json,
            "new": audit.new_values_json,
        })
    finally:
        session.close()
    assert audit.request_id == request_id
    assert_no_secrets(rendered, secret_sentinels)


def test_api_key_authentication_still_works(app_factory, session_factory):
    viewer = generate_credential(session_factory, Role.VIEWER)
    application = app_factory(make_settings(auth_mode="api_key"))
    with TestClient(application) as client:
        response = client.get(
            "/api/v1/incidents/",
            headers={"Authorization": f"Bearer {viewer.api_key}"},
        )
    assert response.status_code == 200


def test_oidc_authentication_still_works(app_factory):
    application = app_factory(
        oidc_settings(),
        oidc_service=AcceptingOidcService(),
    )
    with TestClient(application) as client:
        response = client.get(
            "/api/v1/incidents/",
            headers={"Authorization": "Bearer header.payload.signature"},
        )
    assert response.status_code == 200


def test_hybrid_authentication_still_works(
    app_factory,
    session_factory,
):
    viewer = generate_credential(session_factory, Role.VIEWER)
    application = app_factory(
        oidc_settings("hybrid"),
        oidc_service=AcceptingOidcService(),
    )
    with TestClient(application) as client:
        api_key_response = client.get(
            "/api/v1/incidents/",
            headers={"Authorization": f"Bearer {viewer.api_key}"},
        )
        oidc_response = client.get(
            "/api/v1/incidents/",
            headers={"Authorization": "Bearer header.payload.signature"},
        )
    assert api_key_response.status_code == 200
    assert oidc_response.status_code == 200


def test_rbac_permission_boundary_still_works(
    app_factory,
    session_factory,
):
    viewer = generate_credential(session_factory, Role.VIEWER)
    admin = generate_credential(session_factory, Role.ADMIN)
    application = app_factory(make_settings(auth_mode="api_key"))
    with TestClient(application) as client:
        denied = client.get(
            "/api/v1/workers",
            headers={"Authorization": f"Bearer {viewer.api_key}"},
        )
        allowed = client.get(
            "/api/v1/workers",
            headers={"Authorization": f"Bearer {admin.api_key}"},
        )
    assert denied.status_code == 403
    assert allowed.status_code == 200


def test_public_health_routes_remain_public(app_factory):
    application = app_factory(make_settings(auth_mode="api_key"))
    with TestClient(application) as client:
        live = client.get("/health/live")
        ready = client.get("/health/ready")
    assert live.status_code == 200
    assert ready.status_code in {200, 503}
    assert live.headers["x-request-id"]
    assert ready.headers["x-request-id"]


def test_protected_routes_remain_protected(app_factory):
    application = app_factory(make_settings(auth_mode="api_key"))
    with TestClient(application) as client:
        response = client.get("/api/v1/incidents/")
    assert response.status_code == 401
    assert response.json() == AUTHENTICATION_ERROR


def test_oidc_authentication_failure_does_not_reflect_jwt(
    app_factory,
    secret_sentinels,
):
    application = app_factory(
        oidc_settings(),
        oidc_service=RejectingOidcService(),
    )
    with TestClient(application) as client:
        response = client.get(
            "/api/v1/incidents/",
            headers={"Authorization": secret_sentinels.authorization},
        )
    assert response.status_code == 401
    assert_no_secrets(
        f"{response.text} {dict(response.headers)}",
        secret_sentinels,
    )
