# Phase 5C.2 role-based access control

Phase 5C.2 adds centralized role-based authorization on top of the Phase 5C.1
API-key authentication foundation. Authentication identifies the caller;
authorization decides whether that authenticated principal may perform the
requested operation.

This phase does not complete the broader Phase 5C security roadmap.

## Credential roles and permissions

Each API credential has exactly one persisted role. The accepted roles are
strictly limited to `viewer`, `service`, `analyst`, and `admin`. Permissions
are defined centrally and are not stored separately on credentials.

| Permission | viewer | service | analyst | admin |
| --- | --- | --- | --- | --- |
| `job.submit` | No | Yes | Yes | Yes |
| `job.read` | Yes | Yes | Yes | Yes |
| `job.cancel` | No | No | Yes | Yes |
| `incident.read` | Yes | Yes | Yes | Yes |
| `incident.status.update` | No | No | Yes | Yes |
| `incident.audit.read` | No | No | Yes | Yes |
| `report.read` | Yes | Yes | Yes | Yes |
| `worker.read` | No | No | No | Yes |
| `audit.read` | No | No | No | Yes |

Role names do not imply an ordering, and permissions are not inferred through
string comparison or database-defined inheritance.

## Create and administer role-bearing credentials

Create a credential with an explicit role:

```shell
python -m agent.security.api_keys create \
  --name "SIEM Integration" \
  --role service
```

The allowed `--role` values are `viewer`, `service`, `analyst`, and `admin`.
If `--role` is omitted, the credential receives the `service` role. The full
API key is displayed exactly once; list output includes the role but never the
full key or key hash.

There is no HTTP credential-management endpoint. A role cannot be selected or
changed through a request header or body. To change a credential's role,
revoke the old credential and create a replacement with the intended role.

Existing credentials are preserved and backfilled to `service` by migration
`c7d9e2a4b6f1`.

## Authentication and authorization failures

Missing, malformed, invalid, revoked, and expired API keys return the same
generic HTTP 401 response:

```json
{
  "code": "authentication_required",
  "message": "Valid authentication credentials are required."
}
```

An authenticated principal without the required permission returns HTTP 403:

```json
{
  "code": "forbidden",
  "message": "You do not have permission to perform this action."
}
```

The denial does not disclose required roles, the permission map, key prefixes,
key hashes, Authorization headers, or database details. Authorization executes
before endpoint business logic, so denied requests do not stage analysis
files, create or cancel jobs, change incidents, increment attempts, publish
tasks, or create mutation audit events.

## Endpoint permission policy

The following health endpoints remain public:

- `GET /health`
- `GET /ready`
- `GET /health/live`
- `GET /health/ready`

Framework documentation routes (`/openapi.json`, `/docs`,
`/docs/oauth2-redirect`, and `/redoc`) remain public for now.

Versioned API permissions are:

| Endpoint | Permission |
| --- | --- |
| `POST /api/v1/analysis-jobs/file` | `job.submit` |
| `GET /api/v1/analysis-jobs/{job_id}` | `job.read` |
| `GET /api/v1/analysis-jobs/{job_id}/result` | `job.read` |
| `POST /api/v1/analysis-jobs/{job_id}/cancel` | `job.cancel` |
| `GET /api/v1/incidents/` | `incident.read` |
| `GET /api/v1/incidents/{incident_id}` | `incident.read` |
| Incident signals, events, evidence, and triage runs | `incident.read` |
| `GET /api/v1/incidents/{incident_id}/report` | `report.read` |
| `GET /api/v1/incidents/{incident_id}/timeline` | `incident.audit.read` |
| `PATCH /api/v1/incidents/{incident_id}/status` | `incident.status.update` |
| `GET /api/v1/workers` | `worker.read` |

There is currently no global audit endpoint, so Phase 5C.2 does not create one.

Legacy routes remain available but are not authorization bypasses:

| Endpoint | Permission |
| --- | --- |
| `POST /analyze` | `job.submit` |
| `POST /ingest/file` | `job.submit` |
| `POST /detect/file` | `job.submit` |
| `POST /analyze/file` | `job.submit` |
| `GET /incident/{incident_id}/report` | `report.read` |

## Mutation audit identity

Incident status changes and job cancellation requests derive their audit actor
from the authenticated principal:

```text
actor_type = principal.subject_type
actor_id = principal.subject_id
```

Actor fields supplied in request bodies or headers are ignored. API keys,
Authorization headers, key hashes, request bodies, and raw log content are not
stored in mutation audit records.

## Disabled local-development mode

`AUTH_MODE=disabled` bypasses both authentication and RBAC for local
development. It returns an explicit principal whose `subject_type` is
`local_development`, whose authentication method is `disabled`, and whose role
is `admin`. Mutations in this mode use that explicit local-development identity
in audit records.

This bypass never applies when `AUTH_MODE=api_key`. Production fail-closed
startup enforcement remains planned for Phase 5C.4.

## Current boundaries and roadmap

Phase 5C.2 implements operation-level permissions only. Tenant isolation,
multi-tenancy, and per-resource or per-job ownership are not implemented.
Consequently, a service credential may submit and read jobs but cannot cancel
jobs or change incident status; an analyst can perform those mutations across
currently visible resources.

JWT validation, OIDC discovery, OAuth login, passwords, browser sessions, and
human-user authentication are not implemented. Phase 5C.3 is the planned
JWT/OIDC human-identity phase. Rate limiting, credential HTTP management, and
field-level authorization also remain out of scope.
