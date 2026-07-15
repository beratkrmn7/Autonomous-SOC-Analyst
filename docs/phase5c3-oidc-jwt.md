# Phase 5C.3 external OIDC/JWT authentication

Phase 5C.3 makes the API an OpenID Connect resource server for human SOC
users. An external identity provider issues access tokens; this application
only receives and validates them. It does not issue tokens, store passwords,
redirect browsers to login, or maintain user sessions.

The existing Phase 5C.2 permission matrix remains the sole authorization
policy after authentication.

## Authentication modes

`AUTH_MODE` accepts exactly four values:

- `disabled`: local-development authentication and RBAC bypass using the
  explicit local-development admin principal.
- `api_key`: database-backed API keys only.
- `oidc`: externally issued OIDC JWT access tokens only.
- `hybrid`: both existing API keys and external OIDC JWT access tokens.

In hybrid mode, Bearer credentials beginning with `soc_` use API-key
authentication. JWT-shaped credentials use OIDC validation. A request cannot
select or override the configured mode through a header, query parameter,
body, or token claim.

## External provider responsibilities

The external provider is responsible for authenticating the user, issuing
short-lived access tokens, rotating signing keys, and managing users and
external role assignments. Access tokens must target this API's configured
audience. An ID token intended for a client application is not an API access
token and should fail audience or access-token validation.

The application validates:

- asymmetric signature and signing-key `kid`;
- the server-configured algorithm allowlist;
- exact issuer;
- API audience;
- expiration and optional not-before time;
- required stable subject claim;
- supported token type and access-token marker when present.

`sub` is the stable human identity. Email, username, domain, scopes, claim
ordering, and group-name similarity never create roles or admin privileges.

## Discovery, JWKS, and key rotation

The server obtains `issuer` and `jwks_uri` from OpenID Connect Discovery. The
discovered issuer must exactly equal `OIDC_ISSUER`. Discovery and JWKS URLs must
use HTTPS unless the HTTPS requirement is explicitly disabled for a controlled
local test environment.

Discovery metadata and JWKS documents use bounded responses, strict HTTP
timeouts, thread-safe TTL caches, and no redirects. They are not fetched for
every request. If a token contains an unknown `kid`, the server refreshes JWKS
once and retries key selection once, which supports normal provider signing-key
rotation.

Malformed metadata, malformed keys, issuer mismatch, unknown keys, or provider
network errors fail closed with the generic authentication response. Discovery
and JWKS URLs are server configuration or trusted discovery output; requests
cannot supply them.

## External role mapping

`OIDC_ROLE_MAPPING` is the explicit mapping from trusted external role values
to the existing internal roles:

```json
{
  "soc-viewer": "viewer",
  "soc-analyst": "analyst",
  "soc-service": "service",
  "soc-admin": "admin"
}
```

Only `viewer`, `analyst`, `service`, and `admin` are valid internal mapping
targets. Multiple mapped roles are deduplicated. Unknown external roles grant
no permissions. A valid token with no mapped role authenticates successfully
but receives the existing generic 403 on operations it cannot perform.

Successful OIDC authentication produces the existing immutable principal:

```text
subject_type = human_user
subject_id = verified sub
authentication_method = oidc_jwt
credential_id = null
roles = mapped internal roles
```

The configured display-name claim is cosmetic, bounded, and falls back safely;
it never replaces `sub` as the stable identity.

## Example configuration

The following uses non-secret placeholders:

```dotenv
AUTH_MODE=hybrid
OIDC_ISSUER=https://identity.example.test/tenant
OIDC_AUDIENCE=soc-api
OIDC_DISCOVERY_URL=https://identity.example.test/tenant/.well-known/openid-configuration
OIDC_ALLOWED_ALGORITHMS=["RS256"]
OIDC_CLOCK_SKEW_SECONDS=30
OIDC_HTTP_TIMEOUT_SECONDS=5
OIDC_METADATA_CACHE_TTL_SECONDS=300
OIDC_JWKS_CACHE_TTL_SECONDS=300
OIDC_ROLES_CLAIM=roles
OIDC_ROLE_MAPPING={"soc-viewer":"viewer","soc-analyst":"analyst","soc-service":"service","soc-admin":"admin"}
OIDC_DISPLAY_NAME_CLAIM=preferred_username
OIDC_REQUIRE_HTTPS=true
```

When `AUTH_MODE` is `oidc` or `hybrid`, issuer and audience are mandatory and
the role mapping and asymmetric algorithm allowlist are validated at startup.
Do not place provider client secrets, real tenant identifiers, private keys, or
tokens in this configuration.

## Failure and readiness behavior

Missing, malformed, invalid, expired, wrongly signed, wrongly issued, and
provider-unavailable credentials all return HTTP 401 with the same response:

```json
{
  "code": "authentication_required",
  "message": "Valid authentication credentials are required."
}
```

The response includes `WWW-Authenticate: Bearer`. It does not disclose claims,
keys, URLs, failure causes, or configuration. A valid principal without an
operation's permission receives the existing generic HTTP 403 response.

Provider outages fail closed. With no valid cached metadata/key, protected
business logic does not execute and the server does not fall back to disabled
or API-key mode. Hybrid mode still accepts an actual API key independently.

`GET /health/live` remains independent of OIDC, the database, and Redis.
`GET /health/ready` reports only `identity_provider: up` or
`identity_provider: down` in OIDC/hybrid mode. It never returns the issuer,
discovery URL, JWKS URL, token, or network exception.

## Audit and token handling

Authenticated mutations automatically use `human_user` and the verified `sub`
as their audit actor. Actor values supplied by requests are ignored. JWTs,
Authorization headers, signatures, JWKS keys, and raw claim documents are not
persisted or logged.

Phase 5C.3 validates self-contained JWT access tokens. A valid token normally
remains usable until expiration unless the provider changes its key or trusted
configuration. There is no revocation endpoint, introspection, logout, refresh
token, or session database. Configure short-lived access tokens at the
external provider.

## Current boundaries and roadmap

There is no login UI, authorization-code callback, token issuance, password
authentication, user registration, browser session, SAML, SCIM, or user
database. Multi-tenancy and per-resource ownership also remain unimplemented.
Phase 5C.4 is reserved for production fail-closed enforcement and API security
hardening; Phase 5C.3 does not start that work.
