# Phase 5A: Persistent Backend Foundation

This document details the architectural decisions and features introduced in **Phase 5A**. This phase transforms the application from an in-memory PoC to a production-ready, persistent backend foundation.

## Key Architectural Additions

### 1. SQLAlchemy ORM & Database Layer
We introduced a persistent layer using SQLAlchemy and SQLite.
The schema captures:
- Ingestion Jobs & Log Sources
- Canonical Events
- Incidents & Triage Runs
- Evidence & Audit Trails

### 2. Unit of Work & Repository Pattern
To maintain transactional integrity and decouple the business logic from SQLAlchemy sessions, we introduced:
- `UnitOfWork`: Manages SQLAlchemy sessions and transactions.
- `IncidentRepository` & `AuditEventRepository`: Provide focused domain operations for querying and mutating persistence models.
- `DataMapper`: Maps between rich Pydantic domain models (`IncidentBundle`, `DetectionSignal`) and SQLAlchemy ORM models.

### 3. Application Services
We unified the CLI (`main.py`) and API (`server.py`) around a single `AnalysisService` (`agent/application/analysis_service.py`).
This ensures parity between terminal execution and REST API calls. Both interfaces now invoke the same core ingestion, detection, and persistence logic.

### 4. Incident Lifecycle & Audit Trails
Incidents now have defined state transitions (e.g., `new` -> `triaged` -> `investigating` -> `resolved`).
The `IncidentLifecycle` class (`agent/persistence/lifecycle.py`) handles state changes and automatically logs `AuditEvent` records tracking transitions, actors, and metadata.

### 5. Alembic Migrations
Alembic is set up for schema migrations in the `alembic/` directory, allowing iterative DB schema changes without dropping the database.

### 6. Versioned API
A new `v1` REST API router (`agent/api/v1/incidents.py`) exposes persistent incidents:
- `GET /api/v1/incidents/`: List all incidents with optional filtering.
- `GET /api/v1/incidents/{id}`: Get incident details.
- `PATCH /api/v1/incidents/{id}/status`: Update incident status.
- `GET /api/v1/incidents/{id}/timeline`: Retrieve audit event timeline.

## Next Steps (Phase 5B & Beyond)
- Enhanced API endpoints for granular reporting and metrics.
- Background worker queues (e.g., Celery) for async processing.
- Persistent LLM Chat History.
