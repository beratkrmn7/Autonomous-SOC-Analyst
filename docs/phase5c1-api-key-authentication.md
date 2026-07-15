# Phase 5C.1 API-key authentication foundation

Phase 5C.1 adds database-backed API keys for machine-to-machine integrations.
It does not complete the broader Phase 5C security roadmap.

## Authentication modes

`AUTH_MODE` accepts two validated values:

- `disabled` returns an explicit local-development admin principal. This mode
  is for local development and tests only; it bypasses authentication and RBAC.
- `api_key` requires a valid active API key for application endpoints.

The mode is server configuration. Request headers, query parameters, request
bodies, and URLs cannot select or override it. Production fail-closed startup
enforcement is planned for Phase 5C.4.

`GET /health/live` and `GET /health/ready` remain public for health checks.
Versioned `/api/v1` routes and legacy analysis/report routes require
authentication when `AUTH_MODE=api_key`.

## Create a credential

Run the administrative CLI in the configured application environment:

```shell
python -m agent.security.api_keys create --name "SOC Integration"
```

An optional UTC expiration can be supplied:

```shell
python -m agent.security.api_keys create --name "SIEM Export" \
  --expires-at "2027-01-01T00:00:00Z"
```

The command displays the full API key exactly once. Store it immediately in an
approved secret manager. The database stores only its public prefix and a
deterministic SHA-256 hash; the complete key cannot be retrieved later.

## Use a credential

Send the key only in the standard Bearer header:

```text
Authorization: Bearer soc_<public-prefix>_<random-secret>
```

Keys in URLs, query parameters, cookies, request bodies, or alternative headers
are not accepted. Missing, malformed, invalid, expired, and revoked credentials
all receive the same generic HTTP 401 response and `WWW-Authenticate: Bearer`.

## List and revoke credentials

List safe credential metadata:

```shell
python -m agent.security.api_keys list
```

The list never includes the full key or its hash. Revoke by stable credential
identifier:

```shell
python -m agent.security.api_keys revoke cred_<identifier>
```

Revocation is idempotent. Expired credentials and revoked credentials cannot
authenticate. Creation and revocation create sanitized audit events without
keys, hashes, Authorization headers, request bodies, or database credentials.

## Current scope and roadmap

Phase 5C.2 now persists strict API credential roles and enforces centralized
endpoint permissions. See [Phase 5C.2 role-based access control](phase5c2-rbac.md)
for the role matrix, credential creation syntax, and 401/403 behavior.
Human-user JWT/OIDC authentication remains planned for Phase 5C.3. Password
authentication, user registration, OAuth login, rate limiting, and login UI are
not implemented.
