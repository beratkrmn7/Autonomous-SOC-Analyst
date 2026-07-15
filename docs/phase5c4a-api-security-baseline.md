# Phase 5C.4A: API security baseline

Phase 5C.4A hardens the HTTP deployment boundary around the existing API-key,
OIDC/JWT, hybrid authentication, RBAC, and audit identity implementation. It
does not complete Phase 5C and does not add rate limiting.

## Production startup requirements

`APP_ENV` is explicit and accepts only `development`, `test`, or `production`.
The service does not infer production from debug or logging flags.

In production, settings validation fails startup unless all of these
conditions hold:

- `AUTH_MODE` is `api_key`, `oidc`, or `hybrid`; disabled authentication is
  rejected and no development credential is created;
- `HTTPS_REQUIRED=true`;
- security response headers remain enabled;
- trusted hosts and CORS origins contain no wildcard;
- a wildcard CORS origin is never combined with credentials;
- OIDC and hybrid mode retain HTTPS-only issuer and discovery validation;
- forwarded headers, when enabled, have an explicit trusted proxy IP list.

Configuration failures use stable internal error codes. Pydantic input values
are hidden from rendered validation errors so database URLs, broker URLs,
credentials, hashes, and other private configuration are not printed. The
service never falls back to development mode after validation fails.

Production example:

```dotenv
APP_ENV=production
AUTH_MODE=api_key
SECURITY_HEADERS_ENABLED=true
TRUSTED_HOSTS=["api.example.test"]
CORS_ALLOWED_ORIGINS=["https://console.example.test"]
CORS_ALLOW_CREDENTIALS=false
HTTPS_REQUIRED=true
FORWARDED_HEADERS_ENABLED=false
TRUSTED_PROXY_IPS=[]
API_DOCS_ENABLED=false
```

## Trusted hosts

Every HTTP request, including health requests, is checked against
`TRUSTED_HOSTS`. Host matching uses the validated server configuration only.
The request port is parsed separately and must be a valid TCP port; it does not
change the hostname comparison. Invalid or untrusted hosts receive a safe 400
response that does not reflect the supplied Host value.

`X-Forwarded-Host` and `Forwarded` never redefine the trusted host. Wildcard
hosts are forbidden in production.

## CORS

The default `CORS_ALLOWED_ORIGINS` list is empty. CORS methods are limited to:

- `GET`
- `POST`
- `PATCH`
- `OPTIONS`

Allowed request headers are `Accept`, `Authorization`, `Content-Type`,
`If-Match`, and `X-Request-ID`. `DELETE` is not enabled because the application
has no DELETE route. An origin receives an allow-origin response only when it
is explicitly configured. Credentials are disabled by default, and wildcard
origin plus credentials is rejected during validation.

CORS is a browser policy only. Authentication and RBAC still run normally on
protected operations.

## HTTPS and trusted reverse proxies

Direct TLS termination uses:

```dotenv
HTTPS_REQUIRED=true
FORWARDED_HEADERS_ENABLED=false
```

In this mode, arbitrary `X-Forwarded-Proto`, `X-Forwarded-Host`, and
`Forwarded` values are ignored. Insecure API requests are rejected with a safe
400 response; they are not redirected, so file-upload POST bodies are never
lost to a redirect.

For a reverse proxy deployment, use:

```dotenv
HTTPS_REQUIRED=true
FORWARDED_HEADERS_ENABLED=true
TRUSTED_PROXY_IPS=["192.0.2.10"]
```

Only a connection whose ASGI client IP exactly matches `TRUSTED_PROXY_IPS` may
supply a single normalized `X-Forwarded-Proto` value of `http` or `https`.
Other forwarded host/scheme formats remain untrusted. The deployment proxy
must remove client-supplied forwarding headers, set the normalized scheme, and
preserve the real proxy source address. Forwarded-header trust remains disabled
by default.

## Security response headers

When `SECURITY_HEADERS_ENABLED=true`, the boundary sets one authoritative value
for:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- a restrictive `Permissions-Policy`
- `Cache-Control: no-store`
- a deny-by-default Content Security Policy

The Swagger and ReDoc paths receive a separate CSP limited to the CDN assets
used by FastAPI's generated documentation. API responses use `default-src
'none'` with framing, base URI, and form submission disabled.

Headers apply to successful responses and to 401, 403, 404, 409, 413, 422, and
sanitized 500 responses. HSTS is emitted only when `HTTPS_REQUIRED=true`, the
effective request scheme is HTTPS, and `HSTS_MAX_AGE_SECONDS` is greater than
zero. The default max age is a conservative one day.

## API documentation exposure

Documentation is enabled by default in development and test environments. In
production, omission of `API_DOCS_ENABLED` disables `/docs`, `/redoc`, and
`/openapi.json`. Production operators may explicitly enable it, but doing so
does not alter authentication or RBAC on API operations. Hiding documentation
is not an authentication mechanism.

## Request and upload limits

`MAX_REQUEST_BODY_BYTES` bounds the complete HTTP request body and defaults to
52 MiB. `MAX_UPLOAD_BYTES` bounds the file content and preserves the existing
50 MiB upload limit. The request limit must be at least the upload limit so
multipart framing has bounded overhead.

The boundary rejects an oversized declared `Content-Length` before parsing and
also counts bytes delivered through the ASGI receive stream. Consequently,
chunked requests, multipart uploads, the v1 background-job endpoint, and
legacy upload endpoints cannot bypass the limit. Uploads remain chunked and
spooled; the application does not read an oversized upload fully into memory.

All request and upload limit failures return HTTP 413:

```json
{
  "code": "request_too_large",
  "message": "The request exceeds the allowed size."
}
```

The response never includes a local staging path, filename content, or raw
request data.

## Request IDs and safe errors

Every request receives `X-Request-ID`. A client value is accepted only when it
matches a 1-to-64 character allowlist of letters, digits, `.`, `_`, `:`, and
`-`, beginning with an alphanumeric character. Missing, oversized, malformed,
or control-character values are replaced with a server-generated 32-character
hexadecimal ID. Request IDs are correlation data only and never participate in
authentication or authorization.

The final ID is returned in the response, included in sanitized operational
error logs, and stored on incident-transition and request-driven job
cancellation audit events.

Unexpected exceptions return HTTP 500:

```json
{
  "code": "internal_error",
  "message": "The request could not be completed."
}
```

Operational error logs contain the fixed event category, request ID, and safe
exception class name only. Raw exception messages and stack traces are not
logged at the HTTP boundary. Existing expected domain responses, including
`authentication_required`, `forbidden`, `invalid_incident_transition`,
`job_not_cancellable`, and `analysis_already_in_progress`, retain their codes
and status behavior.

## Secret redaction

The security tests use synthetic sentinels resembling API keys, JWTs,
Authorization headers, database and Redis URLs, OIDC URLs, and Windows/Linux
paths. Controlled authentication, authorization, upload, database, queue,
OIDC, and unexpected failures verify that those values do not appear in
responses, response headers, captured logs, audit values, or persisted job
error codes. Repository fixtures contain no real secrets.

## Middleware order

The effective request order is:

1. request ID validation or generation;
2. trusted Host validation;
3. direct or trusted-proxy HTTPS policy;
4. declared and streamed request-size enforcement;
5. configured CORS processing;
6. FastAPI exception handling and route parsing;
7. authentication and RBAC dependencies;
8. endpoint execution.

The outer deployment boundary sanitizes unexpected inner exceptions and wraps
all generated responses with the request ID and security headers. This ensures
that early Host, HTTPS, and size failures and inner application errors receive
the same response protections. The app factory installs one route table per
application instance and is used by isolated security tests.

## Health endpoints

`GET /health/live` and `GET /health/ready` remain public. They still pass
through trusted-host validation, HTTPS policy, request-size handling, request
ID generation, CORS, security headers, and error sanitization. Health responses
do not include internal hostnames, URLs, credential state, provider exception
messages, or configuration values.

## Rate limiting roadmap

Phase 5C.4A does not implement rate limiting, quotas, brute-force counters,
lockout, CAPTCHA, or Redis-backed abuse controls. Those controls belong to
Phase 5C.4B. Phase 5C must not be considered complete until that later work and
its review are finished.
