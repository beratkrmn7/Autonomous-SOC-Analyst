# Phase 5D.2A retention planning

Phase 5D.2A defines a versioned retention policy and a read-only planner. It
does not delete, archive, stage, or index data. The planner deliberately uses
database aggregates and correlated `EXISTS` checks so candidate identifiers
are never loaded into application memory.

## Policy

The `v1` defaults are:

| Entity | Environment variable | Days |
| --- | --- | ---: |
| Canonical event | `RETENTION_CANONICAL_EVENT_DAYS` | 30 |
| Detection signal | `RETENTION_DETECTION_SIGNAL_DAYS` | 90 |
| Completed ingestion job | `RETENTION_COMPLETED_JOB_DAYS` | 90 |
| Terminal incident | `RETENTION_TERMINAL_INCIDENT_DAYS` | 365 |
| Audit event | `RETENTION_AUDIT_EVENT_DAYS` | 365 |

`RETENTION_POLICY_VERSION` defaults to `v1`. Day values must be positive
integers. Incident age is measured from `updated_at`; job age is measured from
`completed_at`. Only jobs whose status is `completed` and incidents whose
status is explicitly `resolved` or `closed` can be candidates.

## Protection rules

Canonical events and detection signals remain protected when they are linked
to any non-completed job or any incident outside `resolved`/`closed`. This
includes queued, processing, retry-queued and cancel-requested work, plus
`new`, `triaged`, `needs_review`, `assigned`, `investigating`, `confirmed`,
`false_positive`, and `reopened` incidents. A completed job linked to an active
incident is also protected. Evidence items, triage runs, reports, and
association rows are never independent candidates.

## Legal holds

The `retention_holds` table provides a typed, queryable exemption. A hold names
one supported entity type and entity ID, includes a bounded operational reason,
and may be indefinite (`expires_at` is null) or time-bound. `released_at`
deactivates a hold without erasing its record. Active hold lookup is backed by
the composite `entity_type`, `entity_id`, `released_at`, `expires_at` index.
Reasons must contain only approved, safe operational context—never credentials,
raw log records, or other secrets. The planner reports hold counts but never
reasons or identifiers.

## Dry-run CLI

Run the default safe mode explicitly:

```console
python -m agent.maintenance.retention --dry-run
```

The output contains the policy version, generation time, cutoff, candidate
count, candidate date range, active-relationship protection count, and legal
hold protection count for each entity. It does not include a database URL,
staging path, raw logs, secrets, or entity identifiers. No audit event is
written because the operation is read-only. Omitting the flag is also a
dry-run. `--execute` is rejected before database access.

## Deferred to Phase 5D.2B

Archive storage, batch manifests, transactional deletion order, execution
approval, per-batch auditing, retries, restoration, OpenSearch coordination,
and staging cleanup are intentionally not implemented. Failed/cancelled jobs
also remain protected until execution semantics are designed in Phase 5D.2B.
