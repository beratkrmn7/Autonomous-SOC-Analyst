# Phase 5D.2C — Bounded and resumable retention cleanup

## Purpose and safety boundary

This phase adds destructive database cleanup behind the Phase 5D.2B archive
integrity boundary. Cleanup is not an age-only purge. A root record can be
deleted only when it is a `retention_candidate` in a fully verified archive and
the current database retention predicate still accepts it.

The operational archive is a safe, allow-listed continuity artifact. It is not
a raw forensic backup and does not contain raw logs or credentials.

## Verification and archive stability

Before a cleanup run is claimed, the service requires the database archive run
to be `verified`, checks its storage key and known manifest checksum, validates
the typed manifest, reads every gzip payload to EOF, validates every typed
NDJSON record, verifies all checksums/counts, and rejects unsupported safety
profiles or schemas. No application record deletion starts before this full
verification succeeds.

The verified manifest checksum plus each relative payload filename, SHA-256,
and compressed size are persisted as the cleanup run's immutable snapshot.
Before every destructive batch, the service checks the exact file set, rejects
symlinks and unexpected entries, rechecks the manifest and sidecar checksum,
and compares every payload size with the snapshot. Drift stops the next batch;
previously committed batches remain intact.

During an execution, the verified archive is streamed into a permission-
restricted temporary SQLite index containing only entity type, entity ID, role,
and UTC cursor. It contains no record body and is deleted when that execution
completes or fails. It is rebuilt after full verification on resume.

## Authorization and current eligibility

Only `archive_role=retention_candidate` root records enter the cleanup cursor.
A `dependency` record never authorizes direct root deletion. Dependency
membership is used only to authorize child and association cleanup for an
already approved root.

Every batch recomputes current cutoffs from the configured retention policy and
reuses `RetentionRepository.candidate_spec`. This rechecks status, active
incident/job relationships, and legal holds at cleanup time. A hold added after
archive creation protects the record; an expired or released hold follows the
same current predicate as retention planning.

The foreign-key-derived root order is:

1. audit events;
2. terminal incidents;
3. completed ingestion jobs;
4. unreferenced detection signals;
5. unreferenced canonical events.

For incidents and jobs, reports are deleted before evidence, evidence before
triage runs, and association tables before the root. Audit-event links are never
detached to make an incident deletion possible. An incident is eligible for
deletion only after the audit-event phase and only when no audit event still
references it. Events and signals are deleted only after all remaining
incident/job associations (and event evidence references) are absent. A newly
created or unarchived dependency protects its root. The incident delete also
has an atomic `NOT EXISTS` audit guard. A concurrent audit insert that lands
after that statement-level check is left to the database foreign key; any
collision rolls the batch back rather than weakening the linkage.

## Batches, lease, resume, and idempotency

`RETENTION_CLEANUP_BATCH_SIZE` defaults to `500` and is constrained to
`1..5000`. `RETENTION_CLEANUP_LEASE_SECONDS` defaults to `300` and is
constrained to `30..86400`.

Each root batch is a separate database transaction. Deletions, actual counts,
the `(recorded_at, entity_id)` cursor, and lease renewal commit together. A
failed batch rolls back in full. Candidate IDs are held only for the bounded
current batch; no OFFSET pagination or application database membership table is
used.

An optimistic `UPDATE ... WHERE status/owner/version/lease` claim is portable
across SQLite and production databases. An active lease rejects another
executor. An expired lease or failed run can be claimed and resumed. A worker
that loses its owner/version/lease guard cannot commit deletion or progress.

Progress has one row per cleanup run and root entity type, not one row per
record. Completed phases are skipped, missing roots increment `missing_count`
without incrementing deleted count, and a completed run is a safe no-op on a
second execution.

## Operation

The command requires byte-for-byte archive ID confirmation and performs ID
validation before settings, filesystem, or database initialization:

```console
python -m agent.maintenance.cleanup execute \
  --archive-id ARC-0123456789abcdef0123456789abcdef \
  --confirm-archive-id ARC-0123456789abcdef0123456789abcdef
```

Success prints only the cleanup/archive IDs, status, safe aggregate counts,
completed phases, and resume state. Failure prints only:

```text
Retention cleanup failed safely.
```

The service records summary-only `retention_cleanup_started`,
`retention_cleanup_resumed`, `retention_cleanup_completed`, and
`retention_cleanup_failed` audit events. It never writes deleted ID lists,
absolute paths, raw exceptions, URLs, SQL, tokens, or record bodies to cleanup
metadata, audit details, or CLI output.

Archive files and the archive run are never deleted or modified. This phase
adds no public HTTP endpoint, scheduler, Celery task, restore command, or UI.
OpenSearch coordination and tombstones remain Phase 5D.3 work.
