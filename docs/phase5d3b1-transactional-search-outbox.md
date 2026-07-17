# Phase 5D.3B.1: Transactional Search Outbox Foundation

## Scope

This phase records safe OpenSearch upserts in the primary database transaction. It does
not contact OpenSearch and does not add a worker, scheduler, retry loop, replay API,
backfill, tombstone, or retention-to-index synchronization.

## Transaction boundary

Canonical events, detection signals, incidents, their associations, and corresponding
`search_index_outbox` rows use the same SQLAlchemy session and commit. A source failure
rolls back the outbox; an outbox validation or insert failure rolls back the source. The
repository never commits and never performs a full-session rollback.

## Stable snapshots and versions

- `indexed_at` is derived from the persisted source timestamp for the logical document
  version. Delivery timestamps such as `available_at` remain outbox metadata and do not
  affect the payload checksum.
- Canonical event and detection signal source fields are immutable. Their projection
  version is `1 +` the number of persisted job/incident relationship memberships. The
  relationships are sorted in the document, and existing source rows are locked before
  adding memberships on PostgreSQL. A changed relationship projection therefore gets a
  monotonically higher version instead of conflicting under version 1.
- Incidents retain `Incident.version` as their optimistic concurrency and search
  document version. Adding a job relationship to an existing incident increments that
  version; lifecycle transitions continue to increment it. No-op and rejected
  transitions do neither.
- A different checksum for the same entity, schema, operation, and document version is
  always a fail-closed `opensearch_outbox_deduplication_conflict`.

## JSON and checksum contract

The JSON column stores `document.model_dump(mode="json")` as an object, not a serialized
JSON string. `canonical_payload_bytes()` is the canonical UTF-8 representation used for
the byte limit, and `calculate_payload_sha256()` is the checksum entry point. Serialization
sorts keys, uses compact separators, preserves Unicode, and rejects NaN/Infinity. Stored
objects can be passed directly to strict Pydantic search-document validation; unknown
fields remain forbidden.

## Bounded enqueue and concurrent deduplication

`enqueue_many_upserts()` consumes an iterable in bounded chunks (250 by default, 1,000
maximum). Each all-new chunk uses one dedup pre-check, one dialect-specific SQLite or
PostgreSQL `INSERT ... ON CONFLICT DO NOTHING`, and one post-race checksum verification
query. It neither accumulates the full input nor flushes per row.

The database unique constraint is the final concurrency arbiter. A concurrent identical
payload is reused; a concurrent different payload fails closed after reading the winning
row. No savepoint or error path leaves the source session invalid.

## Claim and lease foundation

Claimant ID, batch limit, and lease duration are validated before SQL. Claims use a
bounded candidate subquery and one atomic `UPDATE ... RETURNING`; PostgreSQL additionally
uses `FOR UPDATE SKIP LOCKED`. Pending/due-retry rows and expired processing leases are
eligible, active leases are excluded, and returned rows must match the actual claimant.

Typed settings provide enqueue chunk size, claim batch size, lease duration, maximum
claim batch size, and maximum payload bytes. Phase 5D.3B.2 will consume these foundations
from a worker.

## Security guarantees

Only explicit Phase 5D.3A safe-document fields are stored. Raw log fields, arbitrary
metrics/errors, evidence quotes, full reports, credentials, connection URLs, certificate
paths, provider prompt secrets, and raw exception text are excluded or redacted. Outbox
errors contain a stable code only; payload sizes, limits, payloads, and exception messages
are not exposed through logs or API errors.

## Migration

Alembic revision `02a14b4d18bf` follows `5d2c9a7e4b10` and remains the single head. Its
downgrade removes only `search_index_outbox`; retention hold, archive, and cleanup tables
remain intact.
