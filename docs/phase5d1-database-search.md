# Phase 5D.1 database search and filtering

Phase 5D.1 provides bounded database search for structured operational metadata. It covers
incidents, canonical events, detection signals, and ingestion/analysis jobs. It does not search
raw logs, report bodies, evidence quotes, arbitrary JSON, credentials, or authorization data.

## Endpoints and access

| Endpoint | Permission | Rate limit |
| --- | --- | --- |
| `GET /api/v1/search/incidents` | `incident.read` | read |
| `GET /api/v1/search/events` | `incident.read` | read |
| `GET /api/v1/search/signals` | `incident.read` | read |
| `GET /api/v1/search/jobs` | `job.read` | read |

All endpoints require the existing authentication and centralized RBAC system. Viewer, analyst,
service, and admin access follows their existing read permissions; search is not admin-only. The
job file SHA-256 filter is additionally limited to service and admin callers and the digest is
never returned.

The existing request-ID, deployment-boundary, security-header, and read-rate-limit behavior
applies to every search request.

## Filter semantics

Different fields use AND semantics. Repeated values for the same multi-value field use OR
semantics. A request with `status=new&status=needs_review&severity=high`, for example, finds high
severity incidents whose status is either `new` or `needs_review`. Multi-value filters accept at
most 20 values. Empty exact-match filters are rejected rather than interpreted as wildcards.

Supported incident filters:

- one or more `status` and `severity` values
- exact `incident_type`, `incident_family`, and `primary_entity`
- `min_confidence` and `max_confidence`, from 0 through 1
- `first_seen_from`/`first_seen_to`, `last_seen_from`/`last_seen_to`, and
  `created_at_from`/`created_at_to`
- exact `mitre_technique` JSON-array membership on SQLite and PostgreSQL
- associated `job_id`
- `has_report` and `has_validated_evidence`
- bounded, escaped `title_prefix` matching (prefix only, not arbitrary full text)

Supported event filters:

- exact `event_id`, `source_name`, `parser_name`, `src_ip`, `dst_ip`, `protocol`, `action`, and
  safely stored `user`
- exact `src_port` and `dst_port`
- `timestamp_from` and `timestamp_to`
- associated `job_id` or `incident_id`
- `is_context` when `incident_id` is present

IPv4 and IPv6 input is validated and normalized before an exact comparison. CIDR and range
search are not part of this database adapter.

Supported signal filters:

- exact `signal_id`, `rule_id`, `rule_name`, `signal_type`, and `signal_family`
- one or more `severity` values
- `min_confidence` and `max_confidence`, from 0 through 1
- exact `suppressed` state
- `first_seen_from`/`first_seen_to` and `last_seen_from`/`last_seen_to`
- associated `job_id` or `incident_id`
- exact `mitre_technique` JSON-array membership on SQLite and PostgreSQL

Supported job filters:

- exact `job_id`, `analysis_mode`, `source_name`, `pipeline_version`, and `error_code`
- one or more `status` values
- `reused` or `min_reused_count`
- `created_at_from`/`created_at_to`, `queued_at_from`/`queued_at_to`, and
  `completed_at_from`/`completed_at_to`
- exact `cancelled` state and `min_attempt_count`
- exact `file_sha256` for service/admin callers only

## Dates and sorting

Dates must be RFC 3339/ISO-8601 values with an explicit timezone and are normalized to UTC.
Invalid dates and ranges whose `from` value is after `to` are rejected.

Default ordering is descending and deterministic:

- incidents: `created_at`, then `incident_id`
- events: `timestamp`, then `event_id`
- signals: `created_at`, then `signal_id`
- jobs: `created_at`, then `id`

`direction=asc` reverses both parts of the ordering. Allowed incident sorts are `created_at`,
`first_seen`, `last_seen`, `severity`, and `confidence`. Events allow only `timestamp`. Signals
allow `created_at`, `first_seen`, `last_seen`, `severity`, and `confidence`. Jobs allow
`created_at`, `completed_at`, and `status`. Sort fields are fixed allowlists; request values never
become SQL column names.

## Cursor pagination and limits

`page_size` defaults to `SEARCH_DEFAULT_PAGE_SIZE` (50) and cannot exceed
`SEARCH_MAX_PAGE_SIZE` (200). Queries fetch at most one row beyond that bound to determine
`has_more`; they do not load all matches or calculate a total count.

Responses have this shape:

```json
{
  "items": [],
  "next_cursor": "opaque-url-safe-value",
  "has_more": false
}
```

When `has_more` is true, send `next_cursor` unchanged as the next request's `cursor`. A cursor is
bound to its resource, sort, and direction. It is a bounded URL-safe signed JSON envelope whose
HMAC prevents undetected modification. Tampered, malformed, cross-resource, or cross-sort cursors
return HTTP 400. `SEARCH_CURSOR_SECRET` must contain at least 32 bytes and must be configured
explicitly in production; development uses a process-local ephemeral secret when it is omitted.

Total counts are intentionally unavailable in this phase. A future optional total can be added
only with an explicit expensive-query contract; ordinary pagination does not issue `COUNT(*)`.

## Safe request and response example

```http
GET /api/v1/search/incidents?status=new&status=needs_review&severity=high&page_size=2
Authorization: Bearer <credential>
```

```json
{
  "items": [
    {
      "incident_id": "inc_example",
      "title": "Network probe activity",
      "incident_type": "network_probe",
      "incident_family": "network",
      "severity": "high",
      "confidence": 0.91,
      "status": "needs_review",
      "first_seen": "2026-01-15T09:00:00Z",
      "last_seen": "2026-01-15T09:04:00Z",
      "created_at": "2026-01-15T09:05:00Z",
      "primary_entity": "192.0.2.10",
      "signal_count": 2,
      "event_count": 8,
      "has_report": false
    }
  ],
  "next_cursor": null,
  "has_more": false
}
```

Incident results contain only summary fields and association counts. Event results contain safe
canonical fields and `safe_message_excerpt`, never the original record. Signal results omit
metrics and unrestricted JSON. Job results omit idempotency keys, file hashes, paths, worker and
queue data, parser/error JSON, and raw errors.

## Current limits and roadmap

Database search is intended for indexed structured metadata and operational use. It has no raw-log
full-text, substring, regex, saved-search, bulk-export, or analytical aggregation capability.

Phase 5D.2 is the retention, deletion, and archival roadmap; none of that lifecycle behavior is
implemented here. Phase 5D.3 is the OpenSearch roadmap for raw-event full text and very large-scale
analytical search. The application search interface allows a later adapter without adding an
OpenSearch dependency or making scale claims in Phase 5D.1.
