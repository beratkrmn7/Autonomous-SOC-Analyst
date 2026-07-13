# Phase 5B.1: Background Job Foundation

This phase introduces a local, database-backed background worker queue to move file analysis out of the HTTP request lifecycle.

## Overview

The new flow operates as follows:
1. **Submission**: The user uploads a file via the new `POST /v1/analysis-jobs/file` endpoint.
2. **Staging**: The file is securely staged on the local filesystem (`LocalFileStagingStore`), generating a SHA-256 hash without keeping the entire file in RAM.
3. **Queueing**: An `IngestionJob` is created (or updated if retrying) with a `queued` status, and an HTTP 202 is returned immediately with the job ID.
4. **Processing**: The `AnalysisWorker` runs in the background. It claims the oldest `queued` job, marks it as `processing`, and invokes the `AnalysisService`.
5. **Completion**: Upon successful analysis, the job is marked `completed`. If an error occurs, it is marked `failed` with a safe, machine-readable `error_code`. The staged file is securely deleted regardless of outcome.
6. **Result Retrieval**: The user polls `GET /v1/analysis-jobs/{job_id}/result` until it returns a `completed` status along with the incident IDs.

## Idempotency
Phase 5A's idempotency semantics are preserved. Submitting a file with an existing `Idempotency-Key` will either:
- Return the existing processing/queued job.
- Return the completed result (reused).
- Automatically retry if the previous attempt failed.

## Local File Staging
The file staging mechanism (`agent/application/staging.py`) isolates file handling logic from the HTTP route:
- Bounds maximum upload sizes.
- Defends against directory traversal by using a randomized UUID for the filename on disk.
- Removes the file upon job completion to ensure zero dangling temporary files.
