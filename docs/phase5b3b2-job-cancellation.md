# Phase 5B.3B2: Safe Job Cancellation

Phase 5B.3B2 adds database-backed cooperative cancellation for background analysis
jobs. The database is the source of truth; queue delivery alone never authorizes
analysis.

## Queued cancellation

`POST /api/v1/analysis-jobs/{job_id}/cancel` conditionally changes a `queued` job
directly to `cancelled`. The same committed transition records the controlled
reason `user_requested`, the server-controlled actor `api_client`, request and
completion timestamps, and clears worker, retry, and lease fields.

The staged upload is removed only after the cancellation transaction commits. A
cleanup failure is logged as the safe category `staging_cleanup_failed` and does
not restore the job to `queued`.

## Processing cancellation

A `processing` job changes first to `cancel_requested`. Its staged upload remains
available until the worker observes cancellation at a safe checkpoint. The worker
then rolls back the current analysis transaction, marks the job `cancelled` in a
new transaction, clears worker, retry, and lease fields, and removes the staged
upload.

Cancellation is cooperative. If an external provider request is already in
progress, it is allowed to return or fail normally; cancellation is observed at
the next safe checkpoint. The API does not claim instantaneous interruption.

## Safe checkpoints

The shared analysis path checks the database:

1. before reading the staged file;
2. after ingestion;
3. after detection and correlation;
4. immediately before triage/provider execution;
5. after triage; and
6. before final persistence and report generation.

Each check uses a fresh, short-lived database session. Cancellation raises a
dedicated control-flow exception so the active UnitOfWork rolls back incidents,
triage runs, evidence, and reports together.

## Race behavior

Worker claiming and queued cancellation both use conditional database updates.
Only a row still in `queued` can be claimed or immediately cancelled:

- if cancellation commits first, the job is `cancelled` and no worker can claim it;
- if claiming commits first, the job is `processing` and cancellation changes it
  to `cancel_requested`;
- final completion is conditional on the job still being `processing`, preventing
  a cancellation winner from being overwritten as `completed`.

Duplicate Celery deliveries consult the database. A `cancelled` job is ignored
without incrementing attempts or running analysis. This phase does not revoke
Celery messages.

## Idempotency and audit

Repeated cancellation requests return the existing cancellation state. The
winning request creates at most one `job_cancellation_requested` audit event, and
the finishing transition creates at most one `job_cancelled` event. Completed and
failed jobs are unchanged and return `409 job_not_cancellable`.

## Current limitations

- Cancellation is not instantaneous during an active external provider call.
- There is no hard process, thread, or operating-system termination.
- There is no Celery revoke, pause/resume, batch cancellation, authentication, or
  role-based authorization in this phase.
- Cancellation does not perform firewall, endpoint, or other active-response
  actions.
