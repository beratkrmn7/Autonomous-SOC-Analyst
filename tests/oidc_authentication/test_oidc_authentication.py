import copy
import datetime
import hashlib
import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import agent.api.health as health_module
from agent.api.deps import (
    get_dispatcher,
    get_optional_oidc_authentication_service,
    get_staging_store,
    get_uow,
)
from agent.application.authentication import (
    AUTHENTICATION_ERROR,
    ApiKeyAuthenticationService,
    AuthenticationRequiredError,
)
from agent.application.oidc_authentication import OidcJwtAuthenticationService
from agent.config import Settings, get_settings
from agent.persistence.database import Base
from agent.persistence.orm_models import AuditEvent, Incident, IngestionJob
from agent.persistence.unit_of_work import UnitOfWork
from agent.security.authorization import FORBIDDEN_ERROR, Role
from agent.security.oidc import (
    OidcConfiguration,
    OidcMetadataProvider,
    OidcProviderError,
    OidcSigningKeyResolver,
)
from server import app


ISSUER = "https://identity.example.test"
AUDIENCE = "soc-api"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
JWKS_URL = f"{ISSUER}/jwks"
ROLE_MAPPING = {
    "soc-viewer": "viewer",
    "soc-analyst": "analyst",
    "soc-service": "service",
    "soc-admin": "admin",
}


class FakeOidcHttpClient:
    def __init__(self, responses):
        self.responses = responses
        self.calls: list[str] = []
        self._lock = threading.Lock()

    def get_json(
        self,
        url: str,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ):
        with self._lock:
            self.calls.append(url)
            response = self.responses[url]
            if isinstance(response, list):
                selected = response.pop(0) if len(response) > 1 else response[0]
            else:
                selected = response
        if isinstance(selected, Exception):
            raise selected
        return copy.deepcopy(selected)


class RecordingStagingStore:
    def __init__(self):
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
    def __init__(self):
        self.enqueued_job_ids: list[str] = []

    def enqueue(self, job_id: str) -> None:
        self.enqueued_job_ids.append(job_id)


@dataclass(frozen=True)
class RsaMaterial:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey
    jwk: dict


@dataclass(frozen=True)
class OidcBundle:
    settings: Settings
    configuration: OidcConfiguration
    http_client: FakeOidcHttpClient
    service: OidcJwtAuthenticationService
    material: RsaMaterial


@pytest.fixture(scope="module")
def rsa_material():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(public_key, as_dict=True)
    jwk.update({"kid": "key-1", "alg": "RS256", "use": "sig"})
    return RsaMaterial(private_key, public_key, jwk)


@pytest.fixture(scope="module")
def alternate_rsa_material():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(public_key, as_dict=True)
    jwk.update({"kid": "other-key", "alg": "RS256", "use": "sig"})
    return RsaMaterial(private_key, public_key, jwk)


def make_settings(auth_mode="oidc", **overrides) -> Settings:
    values = {
        "auth_mode": auth_mode,
        "oidc_issuer": ISSUER,
        "oidc_audience": AUDIENCE,
        "oidc_discovery_url": DISCOVERY_URL,
        "oidc_allowed_algorithms": ["RS256"],
        "oidc_role_mapping": ROLE_MAPPING,
        "oidc_require_https": True,
    }
    values.update(overrides)
    return Settings(**values)


def build_bundle(
    material: RsaMaterial,
    *,
    settings: Settings | None = None,
    discovery_document=None,
    jwks_document=None,
) -> OidcBundle:
    settings = settings or make_settings()
    configuration = OidcConfiguration.from_settings(settings)
    if discovery_document is None:
        discovery_document = {
            "issuer": configuration.issuer,
            "jwks_uri": JWKS_URL,
        }
    if jwks_document is None:
        jwks_document = {"keys": [material.jwk]}
    http_client = FakeOidcHttpClient({
        configuration.discovery_url: discovery_document,
        JWKS_URL: jwks_document,
    })
    metadata_provider = OidcMetadataProvider(configuration, http_client)
    key_resolver = OidcSigningKeyResolver(
        configuration,
        metadata_provider,
        http_client,
    )
    service = OidcJwtAuthenticationService(configuration, key_resolver)
    return OidcBundle(
        settings,
        configuration,
        http_client,
        service,
        material,
    )


@pytest.fixture
def oidc_bundle(rsa_material):
    return build_bundle(rsa_material)


def make_token(
    bundle: OidcBundle,
    *,
    private_key=None,
    key_id="key-1",
    algorithm="RS256",
    token_type="at+jwt",
    subject="human-123",
    roles=None,
    claims=None,
    include_token_use=True,
) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "iss": bundle.configuration.issuer,
        "aud": bundle.configuration.audience,
        "sub": subject,
        "exp": now + datetime.timedelta(minutes=5),
        "nbf": now - datetime.timedelta(seconds=1),
        "preferred_username": "SOC Analyst",
        "roles": roles if roles is not None else ["soc-analyst"],
    }
    if include_token_use:
        payload["token_use"] = "access"
    if claims:
        payload.update(claims)
    if subject is None:
        payload.pop("sub", None)
    headers = {"kid": key_id, "typ": token_type}
    return jwt.encode(
        payload,
        private_key or bundle.material.private_key,
        algorithm=algorithm,
        headers=headers,
    )


def assert_rejected(service: OidcJwtAuthenticationService, token: str) -> None:
    with pytest.raises(AuthenticationRequiredError):
        service.authenticate(token)


def assert_generic_401(response) -> None:
    assert response.status_code == 401
    assert response.json() == AUTHENTICATION_ERROR
    assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.fixture
def session_factory(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'oidc.db'}",
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
def client_factory(session_factory, staging_store, dispatcher, monkeypatch):
    @contextmanager
    def factory(
        settings: Settings,
        oidc_service: OidcJwtAuthenticationService | None,
    ):
        app.dependency_overrides[get_settings] = lambda: settings
        app.dependency_overrides[get_uow] = lambda: UnitOfWork(session_factory)
        app.dependency_overrides[get_staging_store] = lambda: staging_store
        app.dependency_overrides[get_dispatcher] = lambda: dispatcher
        app.dependency_overrides[
            get_optional_oidc_authentication_service
        ] = lambda: oidc_service
        monkeypatch.setattr(health_module, "get_settings", lambda: settings)
        with TestClient(app) as client:
            yield client
        app.dependency_overrides.clear()

    return factory


def seed_incident(session_factory) -> str:
    incident_id = f"inc-{uuid.uuid4().hex}"
    now = datetime.datetime.now(datetime.timezone.utc)
    session = session_factory()
    try:
        session.add(Incident(
            incident_id=incident_id,
            title="OIDC test incident",
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


def test_oidc_and_hybrid_require_issuer_and_audience():
    for auth_mode in ("oidc", "hybrid"):
        with pytest.raises(ValidationError):
            Settings(
                auth_mode=auth_mode,
                oidc_issuer=None,
                oidc_audience=AUDIENCE,
            )
        with pytest.raises(ValidationError):
            Settings(
                auth_mode=auth_mode,
                oidc_issuer=ISSUER,
                oidc_audience=None,
            )


def test_invalid_role_mapping_is_rejected():
    with pytest.raises(ValidationError):
        make_settings(oidc_role_mapping={"soc-owner": "owner"})


def test_symmetric_or_none_algorithm_configuration_is_rejected():
    for algorithms in (["HS256"], ["none"], []):
        with pytest.raises(ValidationError):
            make_settings(oidc_allowed_algorithms=algorithms)


def test_access_token_indicator_cannot_be_disabled():
    with pytest.raises(ValidationError):
        make_settings(oidc_require_access_token_indicator=False)


def test_discovery_issuer_mismatch_fails_closed(rsa_material):
    bundle = build_bundle(
        rsa_material,
        discovery_document={"issuer": "https://attacker.test", "jwks_uri": JWKS_URL},
    )
    with pytest.raises(OidcProviderError):
        bundle.service.check_provider()


@pytest.mark.parametrize(
    "document",
    [{}, {"issuer": ISSUER}, {"issuer": 123, "jwks_uri": JWKS_URL}],
)
def test_malformed_discovery_document_fails_closed(rsa_material, document):
    bundle = build_bundle(rsa_material, discovery_document=document)
    with pytest.raises(OidcProviderError):
        bundle.service.check_provider()


def test_insecure_jwks_url_is_rejected_when_https_required(rsa_material):
    bundle = build_bundle(
        rsa_material,
        discovery_document={"issuer": ISSUER, "jwks_uri": "http://idp.test/jwks"},
    )
    with pytest.raises(OidcProviderError):
        bundle.service.check_provider()


def test_discovery_and_jwks_responses_are_cached(oidc_bundle):
    token = make_token(oidc_bundle)
    oidc_bundle.service.authenticate(token)
    oidc_bundle.service.authenticate(token)

    assert oidc_bundle.http_client.calls.count(DISCOVERY_URL) == 1
    assert oidc_bundle.http_client.calls.count(JWKS_URL) == 1


def test_unknown_kid_refreshes_jwks_exactly_once_and_supports_rotation(
    rsa_material, alternate_rsa_material
):
    settings = make_settings()
    configuration = OidcConfiguration.from_settings(settings)
    rotated_jwk = dict(alternate_rsa_material.jwk)
    rotated_jwk["kid"] = "rotated-key"
    http_client = FakeOidcHttpClient({
        DISCOVERY_URL: {"issuer": ISSUER, "jwks_uri": JWKS_URL},
        JWKS_URL: [
            {"keys": [rsa_material.jwk]},
            {"keys": [rsa_material.jwk, rotated_jwk]},
        ],
    })
    metadata_provider = OidcMetadataProvider(configuration, http_client)
    resolver = OidcSigningKeyResolver(
        configuration, metadata_provider, http_client
    )

    assert resolver.resolve("rotated-key", "RS256") is not None
    assert http_client.calls.count(JWKS_URL) == 2
    assert http_client.calls.count(DISCOVERY_URL) == 1


def test_at_jwt_access_token_without_token_use_claim_authenticates(oidc_bundle):
    principal = oidc_bundle.service.authenticate(make_token(
        oidc_bundle,
        token_type="at+jwt",
        include_token_use=False,
    ))
    assert principal.authentication_method == "oidc_jwt"


def test_generic_jwt_with_configured_access_token_use_authenticates(oidc_bundle):
    principal = oidc_bundle.service.authenticate(make_token(
        oidc_bundle,
        token_type="JWT",
        claims={"token_use": "access"},
    ))
    assert principal.authentication_method == "oidc_jwt"


def test_generic_jwt_without_token_use_claim_is_rejected(oidc_bundle):
    token = make_token(
        oidc_bundle,
        token_type="JWT",
        include_token_use=False,
    )
    assert_rejected(oidc_bundle.service, token)


def test_id_token_claims_do_not_establish_access_token_status(oidc_bundle):
    token = make_token(
        oidc_bundle,
        token_type="JWT",
        include_token_use=False,
        claims={
            "nonce": "id-token-nonce",
            "email": "analyst@example.test",
        },
    )
    assert_rejected(oidc_bundle.service, token)


def test_invalid_signature_returns_generic_authentication_failure(
    oidc_bundle, alternate_rsa_material
):
    token = make_token(oidc_bundle, private_key=alternate_rsa_material.private_key)
    assert_rejected(oidc_bundle.service, token)


@pytest.mark.parametrize(
    ("claims", "subject"),
    [
        ({"iss": "https://wrong-issuer.test"}, "human-123"),
        ({"aud": "wrong-audience"}, "human-123"),
        (
            {"exp": datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)},
            "human-123",
        ),
        (
            {"nbf": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)},
            "human-123",
        ),
        ({}, None),
    ],
)
def test_invalid_registered_claims_return_generic_authentication_failure(
    oidc_bundle, claims, subject
):
    assert_rejected(
        oidc_bundle.service,
        make_token(oidc_bundle, claims=claims, subject=subject),
    )


def test_alg_none_is_rejected(oidc_bundle):
    now = datetime.datetime.now(datetime.timezone.utc)
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "human-123",
            "exp": now + datetime.timedelta(minutes=5),
        },
        key="",
        algorithm="none",
        headers={"kid": "key-1", "typ": "at+jwt"},
    )
    assert_rejected(oidc_bundle.service, token)


def test_hs256_asymmetric_key_confusion_is_rejected(oidc_bundle):
    public_der = oidc_bundle.material.public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "human-123",
            "exp": now + datetime.timedelta(minutes=5),
        },
        key=public_der,
        algorithm="HS256",
        headers={"kid": "key-1", "typ": "at+jwt"},
    )
    assert_rejected(oidc_bundle.service, token)


def test_algorithm_outside_server_allowlist_is_rejected(oidc_bundle):
    token = make_token(oidc_bundle, algorithm="RS512")
    assert_rejected(oidc_bundle.service, token)


@pytest.mark.parametrize("token", ["not-a-jwt", "a.b", "a..c", "..."])
def test_malformed_jwt_returns_generic_authentication_failure(oidc_bundle, token):
    assert_rejected(oidc_bundle.service, token)


def test_unknown_signing_key_returns_generic_authentication_failure(oidc_bundle):
    token = make_token(oidc_bundle, key_id="unknown-key")
    assert_rejected(oidc_bundle.service, token)
    assert oidc_bundle.http_client.calls.count(JWKS_URL) == 2


def test_id_token_marker_is_not_accepted_as_access_token(oidc_bundle):
    token = make_token(oidc_bundle, claims={"token_use": "id"})
    assert_rejected(oidc_bundle.service, token)


def test_missing_access_token_indicator_returns_generic_401_without_leaks(
    oidc_bundle,
    client_factory,
):
    secret_claim = "private-id-claim-value"
    token = make_token(
        oidc_bundle,
        token_type="JWT",
        include_token_use=False,
        claims={"nonce": secret_claim},
    )
    with patch(
        "agent.application.oidc_authentication.logger.warning"
    ) as warning:
        with client_factory(oidc_bundle.settings, oidc_bundle.service) as client:
            response = client.get(
                "/api/v1/incidents/",
                headers={"Authorization": f"Bearer {token}"},
            )

    assert_generic_401(response)
    warning.assert_called_once_with("oidc_authentication_failed")
    rendered = " ".join((response.text, str(warning.call_args)))
    assert token not in rendered
    assert secret_claim not in rendered
    assert "nonce" not in rendered


@pytest.mark.parametrize(
    ("external_role", "internal_role"),
    [
        ("soc-viewer", "viewer"),
        ("soc-analyst", "analyst"),
        ("soc-admin", "admin"),
    ],
)
def test_external_roles_map_to_internal_roles(
    oidc_bundle, external_role, internal_role
):
    principal = oidc_bundle.service.authenticate(
        make_token(oidc_bundle, roles=[external_role])
    )
    assert principal.roles == (internal_role,)


def test_multiple_mapped_roles_are_deduplicated(oidc_bundle):
    principal = oidc_bundle.service.authenticate(make_token(
        oidc_bundle,
        roles=["soc-viewer", "soc-analyst", "soc-analyst"],
    ))
    assert principal.roles == ("viewer", "analyst")


def test_unknown_external_role_authenticates_without_permissions(oidc_bundle):
    principal = oidc_bundle.service.authenticate(
        make_token(oidc_bundle, roles=["soc-owner"])
    )
    assert principal.roles == ()


def test_oidc_principal_uses_verified_subject_and_bounded_display_name(oidc_bundle):
    principal = oidc_bundle.service.authenticate(make_token(
        oidc_bundle,
        subject="stable-subject-42",
        claims={"preferred_username": "A" * 500, "email": "admin@example.test"},
    ))
    assert principal.subject_type == "human_user"
    assert principal.subject_id == "stable-subject-42"
    assert principal.credential_id is None
    assert len(principal.display_name) == 120
    assert principal.display_name != "admin@example.test"


def test_missing_display_name_falls_back_safely(oidc_bundle):
    principal = oidc_bundle.service.authenticate(make_token(
        oidc_bundle,
        claims={"preferred_username": ""},
    ))
    assert principal.display_name == "OIDC user"


def test_api_key_mode_preserves_existing_behavior(
    session_factory, client_factory
):
    settings = Settings(auth_mode="api_key")
    generated = ApiKeyAuthenticationService(
        UnitOfWork(session_factory)
    ).generate_credential(name="Existing API integration", role=Role.VIEWER)
    with client_factory(settings, None) as client:
        response = client.get(
            "/api/v1/incidents/",
            headers={"Authorization": f"Bearer {generated.api_key}"},
        )
    assert response.status_code == 200


def test_oidc_mode_rejects_api_keys(
    oidc_bundle, session_factory, client_factory
):
    generated = ApiKeyAuthenticationService(
        UnitOfWork(session_factory)
    ).generate_credential(name="API integration", role=Role.VIEWER)
    with client_factory(oidc_bundle.settings, oidc_bundle.service) as client:
        response = client.get(
            "/api/v1/incidents/",
            headers={"Authorization": f"Bearer {generated.api_key}"},
        )
    assert_generic_401(response)


def test_hybrid_mode_accepts_api_keys_and_oidc_tokens(
    rsa_material, session_factory, client_factory
):
    bundle = build_bundle(rsa_material, settings=make_settings("hybrid"))
    generated = ApiKeyAuthenticationService(
        UnitOfWork(session_factory)
    ).generate_credential(name="Hybrid integration", role=Role.VIEWER)
    token = make_token(bundle, roles=["soc-viewer"])

    with client_factory(bundle.settings, bundle.service) as client:
        api_key_response = client.get(
            "/api/v1/incidents/",
            headers={"Authorization": f"Bearer {generated.api_key}"},
        )
        oidc_response = client.get(
            "/api/v1/incidents/",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert api_key_response.status_code == 200
    assert oidc_response.status_code == 200


def test_hybrid_mode_rejects_malformed_bearer_credentials(
    rsa_material, client_factory
):
    bundle = build_bundle(rsa_material, settings=make_settings("hybrid"))
    with client_factory(bundle.settings, bundle.service) as client:
        response = client.get(
            "/api/v1/incidents/",
            headers={"Authorization": "Bearer malformed-credential"},
        )
    assert_generic_401(response)


def test_disabled_mode_remains_explicit_local_development(
    client_factory
):
    with client_factory(Settings(auth_mode="disabled"), None) as client:
        response = client.get("/api/v1/workers")
    assert response.status_code == 200


def test_valid_token_with_permission_accesses_protected_endpoint(
    oidc_bundle, client_factory
):
    token = make_token(oidc_bundle, roles=["soc-viewer"])
    with client_factory(oidc_bundle.settings, oidc_bundle.service) as client:
        response = client.get(
            "/api/v1/incidents/",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 200


def test_valid_token_without_permission_returns_generic_403(
    oidc_bundle, client_factory
):
    token = make_token(oidc_bundle, roles=["soc-viewer"])
    with client_factory(oidc_bundle.settings, oidc_bundle.service) as client:
        response = client.get(
            "/api/v1/workers",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 403
    assert response.json() == FORBIDDEN_ERROR


def test_oidc_mutation_audit_uses_verified_subject_and_ignores_spoofing(
    oidc_bundle, session_factory, client_factory
):
    incident_id = seed_incident(session_factory)
    token = make_token(
        oidc_bundle,
        subject="verified-human-77",
        roles=["soc-analyst"],
    )
    with client_factory(oidc_bundle.settings, oidc_bundle.service) as client:
        response = client.patch(
            f"/api/v1/incidents/{incident_id}/status",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Actor-Id": "attacker",
            },
            json={
                "status": "triaged",
                "expected_version": 1,
                "actor_type": "admin",
                "actor_id": "attacker",
                "details": {"actor_id": "attacker"},
            },
        )

    assert response.status_code == 200
    session = session_factory()
    try:
        audit = session.query(AuditEvent).filter_by(
            entity_id=incident_id,
            event_type="status_transition",
        ).one()
        assert audit.actor_type == "human_user"
        assert audit.actor_id == "verified-human-77"
        rendered = json.dumps({
            "details": audit.details,
            "old": audit.old_values_json,
            "new": audit.new_values_json,
        })
        assert "attacker" not in rendered
        assert token not in rendered
    finally:
        session.close()


def test_failed_jwt_submission_has_no_side_effects(
    oidc_bundle,
    alternate_rsa_material,
    session_factory,
    staging_store,
    dispatcher,
    client_factory,
):
    invalid_token = make_token(
        oidc_bundle,
        private_key=alternate_rsa_material.private_key,
        roles=["soc-analyst"],
    )
    with client_factory(oidc_bundle.settings, oidc_bundle.service) as client:
        response = client.post(
            "/api/v1/analysis-jobs/file",
            headers={"Authorization": f"Bearer {invalid_token}"},
            files={"file": ("safe.jsonl", b"{}\n", "application/json")},
        )

    assert_generic_401(response)
    assert staging_store.staged_job_ids == []
    assert dispatcher.enqueued_job_ids == []
    session = session_factory()
    try:
        assert session.query(IngestionJob).count() == 0
    finally:
        session.close()


def test_provider_outage_without_cache_fails_closed(
    rsa_material,
    session_factory,
    staging_store,
    dispatcher,
    client_factory,
):
    settings = make_settings()
    configuration = OidcConfiguration.from_settings(settings)
    http_client = FakeOidcHttpClient({
        DISCOVERY_URL: OidcProviderError("network_secret"),
    })
    provider = OidcMetadataProvider(configuration, http_client)
    resolver = OidcSigningKeyResolver(configuration, provider, http_client)
    service = OidcJwtAuthenticationService(configuration, resolver)
    token_bundle = build_bundle(rsa_material)
    token = make_token(token_bundle, roles=["soc-analyst"])

    with client_factory(settings, service) as client:
        response = client.post(
            "/api/v1/analysis-jobs/file",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": ("safe.jsonl", b"{}\n", "application/json")},
        )

    assert_generic_401(response)
    assert staging_store.staged_job_ids == []
    assert dispatcher.enqueued_job_ids == []
    session = session_factory()
    try:
        assert session.query(IngestionJob).count() == 0
    finally:
        session.close()


def test_jwt_and_authorization_header_never_appear_in_denials_logs_or_audit(
    oidc_bundle,
    alternate_rsa_material,
    session_factory,
    client_factory,
):
    token = make_token(
        oidc_bundle,
        private_key=alternate_rsa_material.private_key,
    )
    with patch(
        "agent.application.oidc_authentication.logger.warning"
    ) as warning:
        with client_factory(oidc_bundle.settings, oidc_bundle.service) as client:
            response = client.get(
                "/api/v1/incidents/",
                headers={"Authorization": f"Bearer {token}"},
            )

    assert_generic_401(response)
    warning.assert_called_once_with("oidc_authentication_failed")
    rendered = " ".join((response.text, str(warning.call_args)))
    assert token not in rendered
    assert "Authorization" not in rendered
    assert "signature" not in rendered.lower()
    session = session_factory()
    try:
        audit_values = json.dumps([
            event.details for event in session.query(AuditEvent).all()
        ])
    finally:
        session.close()
    assert token not in audit_values
    assert "Authorization" not in audit_values


def test_discovery_and_jwks_up_reports_identity_provider_up(
    oidc_bundle, client_factory
):
    with client_factory(oidc_bundle.settings, oidc_bundle.service) as client:
        live = client.get("/health/live")
        ready = client.get("/health/ready")

    assert live.status_code == 200
    assert live.json() == {"status": "live"}
    assert ready.status_code == 200
    assert ready.json()["components"]["identity_provider"] == "up"
    rendered = ready.text
    assert ISSUER not in rendered
    assert JWKS_URL not in rendered


def test_readiness_reports_provider_outage_without_details(
    rsa_material, client_factory
):
    settings = make_settings()
    configuration = OidcConfiguration.from_settings(settings)
    http_client = FakeOidcHttpClient({
        DISCOVERY_URL: OidcProviderError("network secret https://private.test"),
    })
    provider = OidcMetadataProvider(configuration, http_client)
    resolver = OidcSigningKeyResolver(configuration, provider, http_client)
    service = OidcJwtAuthenticationService(configuration, resolver)

    with client_factory(settings, service) as client:
        ready = client.get("/health/ready")

    assert ready.status_code == 503
    assert ready.json()["components"]["identity_provider"] == "down"
    assert "network secret" not in ready.text
    assert ISSUER not in ready.text


def test_discovery_up_and_jwks_down_reports_identity_provider_down(
    rsa_material, client_factory
):
    bundle = build_bundle(
        rsa_material,
        jwks_document=OidcProviderError(
            f"network secret while fetching {JWKS_URL}"
        ),
    )

    with client_factory(bundle.settings, bundle.service) as client:
        ready = client.get("/health/ready")

    assert ready.status_code == 503
    assert ready.json()["components"]["identity_provider"] == "down"
    assert "network secret" not in ready.text
    assert ISSUER not in ready.text
    assert JWKS_URL not in ready.text


def test_cached_valid_jwks_supports_readiness_until_cache_expiry(
    oidc_bundle, client_factory
):
    with client_factory(oidc_bundle.settings, oidc_bundle.service) as client:
        first = client.get("/health/ready")
        oidc_bundle.http_client.responses[DISCOVERY_URL] = OidcProviderError(
            "discovery network exception"
        )
        oidc_bundle.http_client.responses[JWKS_URL] = OidcProviderError(
            "jwks network exception"
        )
        cached = client.get("/health/ready")

    assert first.status_code == 200
    assert cached.status_code == 200
    assert cached.json()["components"]["identity_provider"] == "up"
    assert oidc_bundle.http_client.calls.count(DISCOVERY_URL) == 1
    assert oidc_bundle.http_client.calls.count(JWKS_URL) == 1


def test_concurrent_valid_jwt_validation_is_safe(oidc_bundle):
    token = make_token(oidc_bundle, roles=["soc-analyst"])
    request_count = 8
    barrier = threading.Barrier(request_count)

    def authenticate():
        barrier.wait()
        return oidc_bundle.service.authenticate(token)

    with ThreadPoolExecutor(max_workers=request_count) as executor:
        principals = list(executor.map(lambda _: authenticate(), range(request_count)))

    assert all(principal.subject_id == "human-123" for principal in principals)
    assert all(principal.roles == ("analyst",) for principal in principals)
    assert oidc_bundle.http_client.calls.count(DISCOVERY_URL) == 1
    assert oidc_bundle.http_client.calls.count(JWKS_URL) == 1
