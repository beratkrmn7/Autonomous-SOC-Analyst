import datetime
import hashlib
import json
import re
import uuid
from unittest.mock import patch

import pytest
from alembic import command
from alembic.config import Config
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from agent.api.deps import get_dispatcher, get_staging_store, get_uow
from agent.application.authentication import (
    AUTHENTICATION_ERROR,
    ApiKeyAuthenticationService,
    local_development_principal,
)
from agent.config import get_settings
from agent.persistence.database import Base
from agent.persistence.orm_models import (
    ApiCredential,
    AuditEvent,
    Incident,
    IngestionJob,
    Report,
    WorkerHeartbeat,
)
from agent.persistence.unit_of_work import UnitOfWork
from agent.security.api_keys import main as api_key_cli
from agent.security.authorization import (
    FORBIDDEN_ERROR,
    ROLE_PERMISSIONS,
    Permission,
    Role,
    permissions_for_roles,
)
from server import app


class RecordingStagingStore:
    def __init__(self) -> None:
        self.staged_job_ids: list[str] = []
        self.removed_job_ids: list[str] = []

    def stage_file(self, stream, job_id: str, original_filename: str):
        content = stream.read()
        self.staged_job_ids.append(job_id)
        return f"memory://{job_id}", hashlib.sha256(content).hexdigest()

    def get_file_path(self, job_id: str) -> str:
        return f"memory://{job_id}"

    def remove_file(self, job_id: str) -> None:
        self.removed_job_ids.append(job_id)

    def move_file(self, src_job_id: str, dest_job_id: str) -> None:
        return None


class RecordingDispatcher:
    def __init__(self) -> None:
        self.enqueued_job_ids: list[str] = []

    def enqueue(self, job_id: str) -> None:
        self.enqueued_job_ids.append(job_id)


@pytest.fixture
def session_factory(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'authorization.db'}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    yield factory
    engine.dispose()


@pytest.fixture
def staging_store():
    return RecordingStagingStore()


@pytest.fixture
def dispatcher():
    return RecordingDispatcher()


@pytest.fixture
def api_key_client(session_factory, staging_store, dispatcher, monkeypatch):
    monkeypatch.setenv("AUTH_MODE", "api_key")
    get_settings.cache_clear()
    app.dependency_overrides[get_uow] = lambda: UnitOfWork(session_factory)
    app.dependency_overrides[get_staging_store] = lambda: staging_store
    app.dependency_overrides[get_dispatcher] = lambda: dispatcher
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()
    get_settings.cache_clear()


def generate_credential(session_factory, role: Role, **kwargs):
    return ApiKeyAuthenticationService(
        UnitOfWork(session_factory)
    ).generate_credential(
        name=f"{role.value} test credential",
        role=role,
        **kwargs,
    )


def bearer(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


def assert_forbidden(response) -> None:
    assert response.status_code == 403
    assert response.json() == FORBIDDEN_ERROR


def assert_unauthorized(response) -> None:
    assert response.status_code == 401
    assert response.json() == AUTHENTICATION_ERROR
    assert response.headers["WWW-Authenticate"] == "Bearer"


def create_incident(session_factory, *, status: str = "new") -> str:
    incident_id = f"inc-{uuid.uuid4().hex}"
    now = datetime.datetime.now(datetime.timezone.utc)
    session = session_factory()
    try:
        session.add(Incident(
            incident_id=incident_id,
            title="Authorization test incident",
            incident_type="network",
            severity="medium",
            status=status,
            confidence=0.8,
            version=1,
            first_seen=now,
            last_seen=now,
            primary_entity="host:test",
        ))
        session.add(Report(
            report_id=f"report-{uuid.uuid4().hex}",
            incident_id=incident_id,
            format="markdown",
            content="Safe report",
        ))
        session.commit()
    finally:
        session.close()
    return incident_id


def create_job(session_factory, *, status: str = "queued") -> str:
    job_id = str(uuid.uuid4())
    session = session_factory()
    try:
        session.add(IngestionJob(
            id=job_id,
            source_name="authorization-test",
            original_filename="safe.jsonl",
            status=status,
            attempt_count=0,
            queued_at=datetime.datetime.now(datetime.timezone.utc),
        ))
        session.commit()
    finally:
        session.close()
    return job_id


def create_worker(session_factory) -> str:
    worker_id = f"worker-{uuid.uuid4().hex}"
    now = datetime.datetime.now(datetime.timezone.utc)
    session = session_factory()
    try:
        session.add(WorkerHeartbeat(
            worker_id=worker_id,
            worker_type="analysis",
            status="idle",
            started_at=now,
            last_heartbeat_at=now,
            hostname_hash="safe-host-hash",
            version="test",
        ))
        session.commit()
    finally:
        session.close()
    return worker_id


def get_job(session_factory, job_id: str):
    session = session_factory()
    try:
        job = session.get(IngestionJob, job_id)
        assert job is not None
        session.expunge(job)
        return job
    finally:
        session.close()


def get_incident(session_factory, incident_id: str):
    session = session_factory()
    try:
        incident = session.get(Incident, incident_id)
        assert incident is not None
        session.expunge(incident)
        return incident
    finally:
        session.close()


def test_role_migration_backfills_existing_credentials_and_downgrades(
    tmp_path, monkeypatch
):
    db_path = tmp_path / "role-migration.db"
    database_url = f"sqlite:///{db_path}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    get_settings.cache_clear()
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", database_url)

    try:
        command.upgrade(config, "8a3f1c9d7e42")
        engine = create_engine(database_url)
        created_at = datetime.datetime.now(datetime.timezone.utc)
        with engine.begin() as connection:
            connection.execute(text("""
                INSERT INTO api_credentials (
                    credential_id, name, key_prefix, key_hash, status,
                    created_at, created_by_type, created_by_id, version
                ) VALUES (
                    :credential_id, :name, :key_prefix, :key_hash, :status,
                    :created_at, :created_by_type, :created_by_id, :version
                )
            """), {
                "credential_id": "cred_existing",
                "name": "Existing integration",
                "key_prefix": "existing1234",
                "key_hash": "a" * 64,
                "status": "active",
                "created_at": created_at,
                "created_by_type": "admin_cli",
                "created_by_id": "migration_test",
                "version": 1,
            })

        command.upgrade(config, "head")
        inspector = inspect(engine)
        assert "role" in {
            column["name"]
            for column in inspector.get_columns("api_credentials")
        }
        assert "ix_api_credentials_role" in {
            index["name"]
            for index in inspector.get_indexes("api_credentials")
        }
        with engine.connect() as connection:
            assert connection.execute(text(
                "SELECT role FROM api_credentials WHERE credential_id = "
                "'cred_existing'"
            )).scalar_one() == Role.SERVICE.value

        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(text(
                    "UPDATE api_credentials SET role = 'owner' "
                    "WHERE credential_id = 'cred_existing'"
                ))

        command.downgrade(config, "8a3f1c9d7e42")
        inspector = inspect(engine)
        assert "role" not in {
            column["name"]
            for column in inspector.get_columns("api_credentials")
        }
        with engine.connect() as connection:
            assert connection.execute(text(
                "SELECT COUNT(*) FROM api_credentials "
                "WHERE credential_id = 'cred_existing'"
            )).scalar_one() == 1
        engine.dispose()
    finally:
        get_settings.cache_clear()


@pytest.mark.parametrize("role", list(Role))
def test_cli_create_accepts_every_valid_role(
    session_factory, capsys, role
):
    exit_code = api_key_cli(
        ["create", "--name", f"{role.value} CLI", "--role", role.value],
        uow_factory=lambda: UnitOfWork(session_factory),
    )
    output = capsys.readouterr().out

    assert exit_code == 0
    assert f"Role: {role.value}" in output
    assert len(re.findall(r"soc_[A-Za-z0-9]+_[^\s]+", output)) == 1
    session = session_factory()
    try:
        assert session.query(ApiCredential).one().role == role.value
    finally:
        session.close()


def test_cli_create_defaults_to_service(session_factory, capsys):
    assert api_key_cli(
        ["create", "--name", "Default role CLI"],
        uow_factory=lambda: UnitOfWork(session_factory),
    ) == 0
    assert "Role: service" in capsys.readouterr().out


def test_cli_rejects_invalid_role(session_factory):
    with pytest.raises(SystemExit) as exc_info:
        api_key_cli(
            ["create", "--name", "Invalid CLI", "--role", "owner"],
            uow_factory=lambda: UnitOfWork(session_factory),
        )

    assert exc_info.value.code == 2
    session = session_factory()
    try:
        assert session.query(ApiCredential).count() == 0
    finally:
        session.close()


def test_cli_list_displays_role_without_key_or_hash(session_factory, capsys):
    generated = generate_credential(session_factory, Role.ADMIN)
    session = session_factory()
    try:
        key_hash = session.get(
            ApiCredential, generated.credential.credential_id
        ).key_hash
    finally:
        session.close()

    assert api_key_cli(
        ["list"], uow_factory=lambda: UnitOfWork(session_factory)
    ) == 0
    output = capsys.readouterr().out

    assert "\trole\t" in output
    assert "\tadmin\t" in output
    assert generated.api_key not in output
    assert key_hash not in output


@pytest.mark.parametrize("role", list(Role))
def test_authenticated_principal_contains_persisted_role(
    session_factory, role
):
    generated = generate_credential(session_factory, role)
    principal = ApiKeyAuthenticationService(
        UnitOfWork(session_factory)
    ).authenticate(generated.api_key)

    assert principal.roles == (role.value,)


def test_viewer_permission_matrix_is_exact():
    assert ROLE_PERMISSIONS[Role.VIEWER] == {
        Permission.JOB_READ,
        Permission.INCIDENT_READ,
        Permission.REPORT_READ,
    }


def test_service_permission_matrix_is_exact():
    assert ROLE_PERMISSIONS[Role.SERVICE] == {
        Permission.JOB_SUBMIT,
        Permission.JOB_READ,
        Permission.INCIDENT_READ,
        Permission.REPORT_READ,
    }


def test_analyst_permission_matrix_is_exact():
    assert ROLE_PERMISSIONS[Role.ANALYST] == {
        Permission.JOB_SUBMIT,
        Permission.JOB_READ,
        Permission.JOB_CANCEL,
        Permission.INCIDENT_READ,
        Permission.INCIDENT_STATUS_UPDATE,
        Permission.INCIDENT_AUDIT_READ,
        Permission.REPORT_READ,
    }


def test_admin_has_every_defined_permission():
    assert ROLE_PERMISSIONS[Role.ADMIN] == frozenset(Permission)


def test_unknown_role_grants_no_permissions():
    assert permissions_for_roles(("owner",)) == frozenset()


def test_unauthenticated_protected_request_returns_401(api_key_client):
    assert_unauthorized(api_key_client.get("/api/v1/incidents/"))


def test_authenticated_unauthorized_request_returns_generic_403(
    api_key_client, session_factory
):
    viewer = generate_credential(session_factory, Role.VIEWER)
    headers = bearer(viewer.api_key)
    headers["X-Role"] = Role.ADMIN.value
    assert_forbidden(api_key_client.get(
        "/api/v1/workers", headers=headers
    ))


def test_all_health_endpoints_remain_public(api_key_client):
    for path in ("/health", "/ready", "/health/live", "/health/ready"):
        response = api_key_client.get(path)
        assert response.status_code in (200, 503)
        assert response.json() != AUTHENTICATION_ERROR
        assert response.json() != FORBIDDEN_ERROR


def test_viewer_can_read_incidents_and_reports(
    api_key_client, session_factory
):
    incident_id = create_incident(session_factory)
    viewer = generate_credential(session_factory, Role.VIEWER)
    headers = bearer(viewer.api_key)

    assert api_key_client.get(
        "/api/v1/incidents/", headers=headers
    ).status_code == 200
    assert api_key_client.get(
        f"/api/v1/incidents/{incident_id}", headers=headers
    ).status_code == 200
    assert api_key_client.get(
        f"/api/v1/incidents/{incident_id}/report", headers=headers
    ).status_code == 200
    assert api_key_client.get(
        f"/incident/{incident_id}/report", headers=headers
    ).status_code == 200


def test_denied_viewer_submission_has_no_side_effects(
    api_key_client, session_factory, staging_store, dispatcher
):
    viewer = generate_credential(session_factory, Role.VIEWER)
    response = api_key_client.post(
        "/api/v1/analysis-jobs/file",
        headers=bearer(viewer.api_key),
        files={"file": ("safe.jsonl", b"{}\n", "application/json")},
    )

    assert_forbidden(response)
    assert staging_store.staged_job_ids == []
    assert dispatcher.enqueued_job_ids == []
    session = session_factory()
    try:
        assert session.query(IngestionJob).count() == 0
    finally:
        session.close()


@pytest.mark.parametrize("role", [Role.VIEWER, Role.SERVICE])
def test_unauthorized_roles_cannot_cancel_jobs(
    api_key_client, session_factory, role
):
    job_id = create_job(session_factory)
    credential = generate_credential(session_factory, role)

    response = api_key_client.post(
        f"/api/v1/analysis-jobs/{job_id}/cancel",
        headers=bearer(credential.api_key),
        json={"actor_id": "attacker"},
    )

    assert_forbidden(response)
    job = get_job(session_factory, job_id)
    assert job.status == "queued"
    assert job.cancel_requested_at is None
    assert job.attempt_count == 0
    session = session_factory()
    try:
        assert session.query(AuditEvent).filter_by(entity_id=job_id).count() == 0
    finally:
        session.close()


@pytest.mark.parametrize("role", [Role.VIEWER, Role.SERVICE])
def test_unauthorized_roles_cannot_update_incident_status(
    api_key_client, session_factory, role
):
    incident_id = create_incident(session_factory)
    credential = generate_credential(session_factory, role)

    response = api_key_client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        headers=bearer(credential.api_key),
        json={
            "status": "triaged",
            "expected_version": 1,
            "actor_type": "admin",
            "actor_id": "attacker",
        },
    )

    assert_forbidden(response)
    incident = get_incident(session_factory, incident_id)
    assert incident.status == "new"
    assert incident.version == 1
    session = session_factory()
    try:
        assert session.query(AuditEvent).filter_by(
            entity_id=incident_id
        ).count() == 0
    finally:
        session.close()


def test_service_can_submit_and_read_job_results(
    api_key_client, session_factory, staging_store, dispatcher
):
    service = generate_credential(session_factory, Role.SERVICE)
    headers = bearer(service.api_key)
    response = api_key_client.post(
        "/api/v1/analysis-jobs/file",
        headers=headers,
        files={"file": ("safe.jsonl", b"{}\n", "application/json")},
    )

    assert response.status_code == 202
    job_id = response.json()["job_id"]
    assert staging_store.staged_job_ids == [job_id]
    assert dispatcher.enqueued_job_ids == [job_id]
    session = session_factory()
    try:
        job = session.get(IngestionJob, job_id)
        assert job is not None
        job.status = "completed"
        session.commit()
    finally:
        session.close()

    assert api_key_client.get(
        f"/api/v1/analysis-jobs/{job_id}", headers=headers
    ).status_code == 200
    assert api_key_client.get(
        f"/api/v1/analysis-jobs/{job_id}/result", headers=headers
    ).status_code == 200


def test_analyst_mutations_use_authenticated_identity_and_cannot_list_workers(
    api_key_client, session_factory
):
    incident_id = create_incident(session_factory)
    job_id = create_job(session_factory)
    analyst = generate_credential(session_factory, Role.ANALYST)
    headers = bearer(analyst.api_key)

    status_response = api_key_client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        headers=headers,
        json={
            "status": "triaged",
            "expected_version": 1,
            "actor_type": "admin",
            "actor_id": "attacker",
            "details": {"actor_id": "attacker", "raw": "must not persist"},
        },
    )
    cancel_response = api_key_client.post(
        f"/api/v1/analysis-jobs/{job_id}/cancel",
        headers=headers,
        json={"actor_type": "admin", "actor_id": "attacker"},
    )

    assert status_response.status_code == 200
    assert cancel_response.status_code == 200
    assert_forbidden(api_key_client.get(
        "/api/v1/workers", headers=headers
    ))
    assert get_incident(session_factory, incident_id).status == "triaged"
    job = get_job(session_factory, job_id)
    assert job.status == "cancelled"
    assert job.cancel_requested_by == analyst.credential.credential_id

    session = session_factory()
    try:
        status_audit = session.query(AuditEvent).filter_by(
            entity_id=incident_id,
            event_type="status_transition",
        ).one()
        cancellation_audit = session.query(AuditEvent).filter_by(
            entity_id=job_id,
            event_type="job_cancellation_requested",
        ).one()
        for audit in (status_audit, cancellation_audit):
            assert audit.actor_type == "api_client"
            assert audit.actor_id == analyst.credential.credential_id
            assert "attacker" not in json.dumps(audit.details)
            assert "must not persist" not in json.dumps(audit.details)
    finally:
        session.close()


def test_admin_can_list_workers_and_perform_all_protected_mutations(
    api_key_client, session_factory
):
    worker_id = create_worker(session_factory)
    incident_id = create_incident(session_factory)
    job_id = create_job(session_factory)
    admin = generate_credential(session_factory, Role.ADMIN)
    headers = bearer(admin.api_key)

    workers = api_key_client.get("/api/v1/workers", headers=headers)
    submission = api_key_client.post(
        "/api/v1/analysis-jobs/file",
        headers=headers,
        files={"file": ("admin.jsonl", b"admin\n", "application/json")},
    )
    status_update = api_key_client.patch(
        f"/api/v1/incidents/{incident_id}/status",
        headers=headers,
        json={"status": "triaged", "expected_version": 1},
    )
    cancellation = api_key_client.post(
        f"/api/v1/analysis-jobs/{job_id}/cancel", headers=headers
    )

    assert workers.status_code == 200
    assert workers.json()["items"][0]["worker_id"] == worker_id
    assert submission.status_code == 202
    assert status_update.status_code == 200
    assert cancellation.status_code == 200


@pytest.mark.parametrize("credential_state", ["revoked", "expired"])
def test_revoked_or_expired_credentials_return_401_not_403(
    api_key_client, session_factory, credential_state
):
    kwargs = {}
    if credential_state == "expired":
        kwargs["expires_at"] = (
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(minutes=1)
        )
    credential = generate_credential(session_factory, Role.ADMIN, **kwargs)
    if credential_state == "revoked":
        ApiKeyAuthenticationService(
            UnitOfWork(session_factory)
        ).revoke_credential(credential.credential.credential_id)

    assert_unauthorized(api_key_client.get(
        "/api/v1/workers", headers=bearer(credential.api_key)
    ))


def test_denial_never_exposes_or_audits_secrets(
    api_key_client, session_factory
):
    viewer = generate_credential(session_factory, Role.VIEWER)
    session = session_factory()
    try:
        stored = session.get(ApiCredential, viewer.credential.credential_id)
        assert stored is not None
        key_hash = stored.key_hash
        audit_count_before = session.query(AuditEvent).count()
    finally:
        session.close()

    with patch("agent.api.deps.logger.warning") as denial_warning:
        response = api_key_client.get(
            "/api/v1/workers", headers=bearer(viewer.api_key)
        )

    assert_forbidden(response)
    denial_warning.assert_called_once_with(
        "authorization_denied",
        extra={
            "subject_id": viewer.credential.credential_id,
            "permission": Permission.WORKER_READ.value,
            "request_id": None,
        },
    )
    rendered_denial = " ".join((
        response.text,
        str(denial_warning.call_args),
    ))
    assert viewer.api_key not in rendered_denial
    assert viewer.credential.key_prefix not in rendered_denial
    assert key_hash not in rendered_denial
    assert "Authorization" not in rendered_denial

    session = session_factory()
    try:
        assert session.query(AuditEvent).count() == audit_count_before
        audit_values = json.dumps([
            {
                "details": event.details,
                "old_values": event.old_values_json,
                "new_values": event.new_values_json,
            }
            for event in session.query(AuditEvent).all()
        ])
    finally:
        session.close()
    assert viewer.api_key not in audit_values
    assert key_hash not in audit_values
    assert "Authorization" not in audit_values


PUBLIC_OPERATIONAL_ROUTES = {
    ("GET", "/health"),
    ("GET", "/ready"),
    ("GET", "/health/live"),
    ("GET", "/health/ready"),
}

EXPECTED_ROUTE_PERMISSIONS = {
    ("POST", "/analyze"): Permission.JOB_SUBMIT,
    ("POST", "/ingest/file"): Permission.JOB_SUBMIT,
    ("POST", "/detect/file"): Permission.JOB_SUBMIT,
    ("POST", "/analyze/file"): Permission.JOB_SUBMIT,
    ("GET", "/incident/{incident_id}/report"): Permission.REPORT_READ,
    ("POST", "/api/v1/analysis-jobs/file"): Permission.JOB_SUBMIT,
    ("POST", "/api/v1/analysis-jobs/{job_id}/cancel"): Permission.JOB_CANCEL,
    ("GET", "/api/v1/analysis-jobs/{job_id}"): Permission.JOB_READ,
    ("GET", "/api/v1/analysis-jobs/{job_id}/result"): Permission.JOB_READ,
    ("GET", "/api/v1/incidents/"): Permission.INCIDENT_READ,
    ("GET", "/api/v1/incidents/{incident_id}"): Permission.INCIDENT_READ,
    ("PATCH", "/api/v1/incidents/{incident_id}/status"):
        Permission.INCIDENT_STATUS_UPDATE,
    ("GET", "/api/v1/incidents/{incident_id}/signals"):
        Permission.INCIDENT_READ,
    ("GET", "/api/v1/incidents/{incident_id}/events"):
        Permission.INCIDENT_READ,
    ("GET", "/api/v1/incidents/{incident_id}/triage-runs"):
        Permission.INCIDENT_READ,
    ("GET", "/api/v1/incidents/{incident_id}/evidence"):
        Permission.INCIDENT_READ,
    ("GET", "/api/v1/incidents/{incident_id}/report"):
        Permission.REPORT_READ,
    ("GET", "/api/v1/incidents/{incident_id}/timeline"):
        Permission.INCIDENT_AUDIT_READ,
    ("GET", "/api/v1/workers"): Permission.WORKER_READ,
}


def iter_application_routes(router, prefix: str = ""):
    for route in router.routes:
        if isinstance(route, APIRoute):
            yield prefix + route.path, route
            continue
        include_context = getattr(route, "include_context", None)
        if include_context is not None:
            yield from iter_application_routes(
                include_context.included_router,
                prefix + include_context.prefix,
            )


def route_permissions(route: APIRoute) -> set[Permission]:
    permissions: set[Permission] = set()
    dependencies = list(route.dependant.dependencies)
    while dependencies:
        dependency = dependencies.pop()
        required_permission = getattr(
            dependency.call, "required_permission", None
        )
        if required_permission is not None:
            permissions.add(required_permission)
        dependencies.extend(dependency.dependencies)
    return permissions


def test_actual_route_table_has_explicit_complete_permission_coverage():
    actual_routes: dict[tuple[str, str], APIRoute] = {}
    for path, route in iter_application_routes(app):
        for method in route.methods:
            actual_routes[(method, path)] = route

    assert set(actual_routes) == (
        PUBLIC_OPERATIONAL_ROUTES | set(EXPECTED_ROUTE_PERMISSIONS)
    )
    for route_key, route in actual_routes.items():
        permissions = route_permissions(route)
        if route_key in PUBLIC_OPERATIONAL_ROUTES:
            assert permissions == set()
        else:
            assert permissions == {EXPECTED_ROUTE_PERMISSIONS[route_key]}


def test_framework_documentation_routes_are_the_only_other_public_routes():
    framework_paths = {
        route.path
        for route in app.routes
        if not isinstance(route, APIRoute)
        and getattr(route, "include_context", None) is None
    }
    assert framework_paths == {
        "/openapi.json",
        "/docs",
        "/docs/oauth2-redirect",
        "/redoc",
    }


def test_disabled_mode_uses_explicit_local_admin_principal():
    principal = local_development_principal()
    assert principal.subject_type == "local_development"
    assert principal.authentication_method == "disabled"
    assert principal.credential_id is None
    assert principal.roles == (Role.ADMIN.value,)
    assert permissions_for_roles(principal.roles) == frozenset(Permission)
