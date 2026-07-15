import re

from fastapi import HTTPException
from fastapi.testclient import TestClient

from agent.api.deps import get_authenticated_principal
from agent.application.authentication import AuthenticatedPrincipal
from tests.api_security.helpers import make_settings


SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": (
        "camera=(), geolocation=(), microphone=(), payment=(), usb=()"
    ),
    "cache-control": "no-store",
}


def assert_security_headers(response) -> None:
    for name, expected in SECURITY_HEADERS.items():
        assert response.headers[name] == expected
    assert "default-src" in response.headers["content-security-policy"]
    assert re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}",
        response.headers["x-request-id"],
    )


def test_trusted_host_with_port_succeeds(app_factory):
    application = app_factory(make_settings(trusted_hosts=["localhost"]))
    with TestClient(
        application,
        base_url="http://localhost:8443",
    ) as client:
        response = client.get("/health/live")
    assert response.status_code == 200


def test_untrusted_host_is_rejected_without_reflection(
    app_factory,
    secret_sentinels,
):
    application = app_factory(make_settings(trusted_hosts=["localhost"]))
    untrusted_host = "attacker-secret.example"
    with TestClient(application, base_url="http://localhost") as client:
        response = client.get(
            "/health/live",
            headers={"Host": untrusted_host},
        )

    assert response.status_code == 400
    assert response.json()["code"] == "invalid_host"
    rendered = f"{response.text} {dict(response.headers)}"
    assert untrusted_host not in rendered
    for secret in secret_sentinels.values:
        assert secret not in rendered
    assert_security_headers(response)


def test_spoofed_forwarded_proto_is_ignored_by_default(app_factory):
    application = app_factory(make_settings(https_required=True))
    with TestClient(application, base_url="http://localhost") as client:
        response = client.get(
            "/health/live",
            headers={"X-Forwarded-Proto": "https"},
        )
    assert response.status_code == 400
    assert response.json()["code"] == "https_required"
    assert "strict-transport-security" not in response.headers


def test_https_required_insecure_request_is_rejected_without_redirect(
    app_factory,
):
    application = app_factory(make_settings(https_required=True))
    with TestClient(
        application,
        base_url="http://localhost",
        follow_redirects=False,
    ) as client:
        response = client.post("/ingest/file", content=b"request-body")
    assert response.status_code == 400
    assert response.json()["code"] == "https_required"
    assert "location" not in response.headers


def test_trusted_proxy_may_supply_normalized_https_scheme(app_factory):
    settings = make_settings(
        https_required=True,
        forwarded_headers_enabled=True,
        trusted_proxy_ips=["127.0.0.1"],
    )
    application = app_factory(settings)
    with TestClient(
        application,
        base_url="http://localhost",
        client=("127.0.0.1", 50000),
    ) as client:
        response = client.get(
            "/health/live",
            headers={"X-Forwarded-Proto": "https"},
        )
    assert response.status_code == 200
    assert response.headers["strict-transport-security"] == "max-age=86400"


def test_untrusted_proxy_cannot_supply_forwarded_scheme(app_factory):
    settings = make_settings(
        https_required=True,
        forwarded_headers_enabled=True,
        trusted_proxy_ips=["127.0.0.1"],
    )
    application = app_factory(settings)
    with TestClient(
        application,
        base_url="http://localhost",
        client=("192.0.2.10", 50000),
    ) as client:
        response = client.get(
            "/health/live",
            headers={"X-Forwarded-Proto": "https"},
        )
    assert response.status_code == 400
    assert response.json()["code"] == "https_required"


def test_health_endpoints_follow_host_and_https_policy(app_factory):
    application = app_factory(make_settings(
        https_required=True,
        trusted_hosts=["health.example.test"],
    ))
    with TestClient(
        application,
        base_url="https://health.example.test",
    ) as client:
        live = client.get("/health/live")
        untrusted = client.get(
            "/health/ready",
            headers={"Host": "untrusted.example.test"},
        )
    assert live.status_code == 200
    assert untrusted.status_code == 400
    assert untrusted.json()["code"] == "invalid_host"


def test_no_origin_header_behaves_normally(app_factory):
    application = app_factory(make_settings(
        cors_allowed_origins=["https://console.example.test"]
    ))
    with TestClient(application) as client:
        response = client.get("/health/live")
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_allowlisted_origin_receives_expected_cors_headers(app_factory):
    origin = "https://console.example.test"
    application = app_factory(make_settings(cors_allowed_origins=[origin]))
    with TestClient(application) as client:
        response = client.get("/health/live", headers={"Origin": origin})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == origin
    assert response.headers["vary"] == "Origin"


def test_unknown_origin_receives_no_permissive_cors_headers(app_factory):
    application = app_factory(make_settings(
        cors_allowed_origins=["https://console.example.test"]
    ))
    with TestClient(application) as client:
        response = client.get(
            "/health/live",
            headers={"Origin": "https://attacker.example"},
        )
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers
    assert "access-control-allow-credentials" not in response.headers


def test_authorization_preflight_works_for_allowlisted_origin(app_factory):
    origin = "https://console.example.test"
    application = app_factory(make_settings(cors_allowed_origins=[origin]))
    with TestClient(application) as client:
        response = client.options(
            "/api/v1/incidents/",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization",
            },
        )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == origin
    assert "Authorization" in response.headers["access-control-allow-headers"]


def test_preflight_rejects_unknown_origin_method_and_header(app_factory):
    origin = "https://console.example.test"
    application = app_factory(make_settings(cors_allowed_origins=[origin]))
    attempts = (
        {
            "Origin": "https://attacker.example",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization",
        },
        {
            "Origin": origin,
            "Access-Control-Request-Method": "DELETE",
            "Access-Control-Request-Headers": "Authorization",
        },
        {
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-Untrusted-Header",
        },
    )
    with TestClient(application) as client:
        responses = [
            client.options("/api/v1/incidents/", headers=headers)
            for headers in attempts
        ]
    assert all(response.status_code == 400 for response in responses)
    assert "access-control-allow-origin" not in responses[0].headers


def test_health_does_not_expose_wildcard_cors(app_factory):
    application = app_factory(make_settings(cors_allowed_origins=[]))
    with TestClient(application) as client:
        response = client.get(
            "/health/live",
            headers={"Origin": "https://attacker.example"},
        )
    assert "access-control-allow-origin" not in response.headers


def test_security_headers_exist_on_200(app_factory):
    application = app_factory()
    with TestClient(application) as client:
        response = client.get("/health/live")
    assert response.status_code == 200
    assert_security_headers(response)


def test_security_headers_exist_on_401(app_factory):
    application = app_factory(make_settings(auth_mode="api_key"))
    with TestClient(application) as client:
        response = client.get("/api/v1/incidents/")
    assert response.status_code == 401
    assert_security_headers(response)


def test_security_headers_exist_on_403(app_factory):
    application = app_factory()
    application.dependency_overrides[get_authenticated_principal] = lambda: (
        AuthenticatedPrincipal(
            subject_type="human_user",
            subject_id="viewer-1",
            display_name="Viewer",
            authentication_method="test",
            roles=("viewer",),
            credential_id=None,
        )
    )
    with TestClient(application) as client:
        response = client.get("/api/v1/workers")
    assert response.status_code == 403
    assert_security_headers(response)


def test_security_headers_exist_on_404(app_factory):
    application = app_factory()
    with TestClient(application) as client:
        response = client.get("/does-not-exist")
    assert response.status_code == 404
    assert_security_headers(response)


def test_security_headers_exist_on_409(app_factory):
    application = app_factory()

    @application.get("/test-conflict")
    def conflict():
        raise HTTPException(
            status_code=409,
            detail={"code": "invalid_incident_transition"},
        )

    with TestClient(application) as client:
        response = client.get("/test-conflict")
    assert response.status_code == 409
    assert_security_headers(response)


def test_security_headers_exist_on_422(app_factory):
    application = app_factory()
    with TestClient(application) as client:
        response = client.post("/analyze", json={})
    assert response.status_code == 422
    assert_security_headers(response)


def test_hsts_appears_only_for_required_https(app_factory):
    http_application = app_factory(make_settings(https_required=False))
    https_application = app_factory(make_settings(https_required=True))
    with TestClient(http_application, base_url="http://localhost") as client:
        plain = client.get("/health/live")
    with TestClient(https_application, base_url="https://localhost") as client:
        secure = client.get("/health/live")

    assert "strict-transport-security" not in plain.headers
    assert secure.headers["strict-transport-security"] == "max-age=86400"
