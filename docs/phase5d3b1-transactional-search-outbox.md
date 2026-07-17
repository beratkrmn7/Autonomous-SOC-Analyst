# Phase 5D.3B.1: Transactional Search Outbox Foundation

## Overview

As part of integrating OpenSearch as a secondary index for SOC incident investigation, we implemented a **Transactional Outbox Pattern** to guarantee eventual consistency between the primary PostgreSQL datastore and the OpenSearch indexes. 

This phase (5D.3B.1) builds the structural foundation without activating background workers.

## Key Components

1. **`SearchIndexOutbox` ORM Model:**
   - Lives in `agent/persistence/orm_models.py`.
   - Stores `entity_type`, `entity_id`, and `operation` for `canonical_event`, `detection_signal`, and `incident`.
   - Uses `payload_sha256` and `deduplication_key` for idempotency.
   - Enforces PostgreSQL constraints (`CheckConstraint`, `UniqueConstraint`) ensuring payloads are valid and limits are respected.

2. **`SearchIndexOutboxRepository`:**
   - Implements `enqueue_upsert()` which validates the payload limit and checksums. 
   - Generates deterministic JSON to avoid checksum drift.
   - Fail-closed approach on checksum mismatch for existing deduplication keys.
   - Contains an atomic `claim_batch()` method designed to lease records safely to background workers.

3. **`AnalysisService` Integration:**
   - During `_persist_analysis`, `CanonicalEvent`, `DetectionSignal`, and `Incident` records are enqueued inside the same transaction after relationship hydration, but before the `uow.commit()` happens (or when leaving the `with uow:` context).
   - This decouples the analysis processing from OpenSearch network latencies.
   
4. **`Incident API` Integration:**
   - Status updates via `update_status` trigger a recalculation of the OpenSearch incident document and enqueue an outbox event.

## Constraints & Idempotency

- `opensearch_outbox_max_payload_bytes`: Configurable limit (default: 64KB) to avoid queue flooding.
- **Fail Closed:** If two concurrent transactions attempt to insert the same `deduplication_key` with differing payloads, the system raises `OutboxError` to avoid silent data drift.
- Operations are enqueued using the `uow` session, guaranteeing they only persist if the core database transaction commits.
