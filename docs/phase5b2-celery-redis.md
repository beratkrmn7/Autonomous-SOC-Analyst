# Phase 5B.2: Celery + Redis Queue Adapter

## Architecture Overview

This phase introduces an optional Celery and Redis task queue adapter, replacing the primary reliance on database polling for background job dispatch. However, the architecture is designed carefully:

1. **Database as the Source of Truth:** The database (`IngestionJob` table) remains the absolute source of truth for job state (queued, processing, completed, failed).
2. **Redis as Transport Only:** Redis is strictly used to transport the `job_id`. No file bytes, local paths, ORM objects, or sensitive evidence are sent through the broker.
3. **Local Database Polling Fallback:** The original polling-based `AnalysisWorker` remains fully functional. By configuring `TASK_QUEUE_BACKEND=database`, the application relies entirely on the SQLite database and polling workers, preserving behavior for environments without Redis.

## Configuration

To enable the Celery dispatcher, set the following environment variables:

```env
TASK_QUEUE_BACKEND=celery
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_QUEUE_NAME=soc-analysis
STAGING_DIR=/tmp/agent_staging
```

If `TASK_QUEUE_BACKEND=database` is configured (the default), the application will use the `DatabasePollingDispatcher` which simply logs the queued state and relies on a local worker polling the database.

## Safe Broker Failure Behavior

If the Redis broker is unavailable or the Celery `send_task` fails, the API gracefully handles the exception:
- The `IngestionJob` is marked as `failed` in the database.
- The safe error code `queue_publish_failed` is assigned.
- The staged file is immediately deleted to prevent storage leaks.
- A HTTP 503 Service Unavailable response is returned.
- Broker credentials and raw exceptions are *never* exposed to the client.

## Requirements and Limitations

- **Shared Staging Directory:** Both the API and the Celery worker must have access to the same `STAGING_DIR`. They must run on the same host or share a mounted volume. Cross-host object storage is not implemented in this phase.
- **Operating System Requirement:** Native Windows support for Celery workers is not claimed. It is strongly recommended to run local Celery workers using WSL, a native Linux environment, or Docker containers.
- **Advanced Celery Features:** Advanced features such as automatic broker retries, late acknowledgements, task timeouts, and dead-letter queues (DLQ) are omitted in this phase. They will be implemented in Phase 5B.3. Exactly-once execution and multi-machine distributed processing are not fully supported yet.

## Starting the Celery Worker

To start a Celery worker to consume tasks from the `soc-analysis` queue:

```bash
python -m celery -A agent.queue.celery_app worker --loglevel=info -Q soc-analysis
```

## Phase 5B.3 Roadmap

The next phase (5B.3) will introduce:
- Advanced retries and redelivery recovery.
- Late acknowledgement for safer task execution.
- Task timeouts and dead-letter support.
