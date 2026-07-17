from typing import List, Optional
import hashlib
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

from agent.persistence.repositories import GenericRepository
from agent.persistence.orm_models import SearchIndexOutbox
from agent.opensearch.documents import SearchDocument, deterministic_document_json
from agent.config import get_settings


class OutboxError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


class SearchIndexOutboxRepository(GenericRepository):
    def __init__(self, session: Session):
        super().__init__(session, SearchIndexOutbox)
        self.settings = get_settings()

    def enqueue_upsert(self, document: SearchDocument) -> Optional[SearchIndexOutbox]:
        """
        Safely enqueues a SearchDocument for OpenSearch indexing.
        Generates deterministic JSON, verifies checksums, enforces payload limits.
        If a duplicate is detected (same deduplication key) and checksum differs, fails closed.
        """
        payload_json = deterministic_document_json(document)
        payload_bytes = payload_json.encode("utf-8")
        payload_size = len(payload_bytes)

        if payload_size > self.settings.opensearch_outbox_max_payload_bytes:
            raise OutboxError(
                code="opensearch_outbox_payload_too_large",
                message=f"Payload size {payload_size} bytes exceeds limit of {self.settings.opensearch_outbox_max_payload_bytes}",
            )

        payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()

        # Deduplication key is a deterministic combination of entity_type, entity_id, operation, schema_version, document_version
        dedup_input = f"{document.entity_type}:{document.entity_id}:upsert:{document.schema_version}:{document.document_version}"
        deduplication_key = hashlib.sha256(dedup_input.encode("utf-8")).hexdigest()

        # Check existing deduplication key to handle idempotency safely
        existing = self.find_by_deduplication_key(deduplication_key)
        if existing:
            if existing.payload_sha256 != payload_sha256:
                raise OutboxError(
                    code="opensearch_outbox_deduplication_conflict",
                    message="Deduplication key conflict with different payload checksum",
                )
            return existing

        outbox_entry = SearchIndexOutbox(
            outbox_id=str(uuid.uuid4()),
            entity_type=document.entity_type,
            entity_id=document.entity_id,
            operation="upsert",
            schema_version=document.schema_version,
            document_version=document.document_version,
            deduplication_key=deduplication_key,
            payload=payload_json,
            payload_sha256=payload_sha256,
            payload_size_bytes=payload_size,
            status="pending",
            available_at=datetime.now(timezone.utc),
        )

        try:
            # We don't want to use self.session.add(outbox_entry) + self.session.flush() directly
            # without handling flush errors safely, because if flush fails, it invalidates the whole transaction.
            # However, if there's a race condition and a unique constraint violation occurs, we WANT to fail closed
            # because we don't know if the conflicting record has the same payload.
            self.session.add(outbox_entry)
            self.session.flush()
        except IntegrityError:
            self.session.rollback()
            raise OutboxError(
                code="opensearch_outbox_enqueue_failed",
                message="Failed to enqueue outbox event due to database integrity conflict",
            )

        return outbox_entry

    def find_by_deduplication_key(self, deduplication_key: str) -> Optional[SearchIndexOutbox]:
        return (
            self.session.query(SearchIndexOutbox)
            .filter(SearchIndexOutbox.deduplication_key == deduplication_key)
            .first()
        )

    def count_by_status(self, status: str) -> int:
        return (
            self.session.query(SearchIndexOutbox)
            .filter(SearchIndexOutbox.status == status)
            .count()
        )

    def claim_batch(
        self, claimant_id: str, limit: int, lease_seconds: int = 300
    ) -> List[SearchIndexOutbox]:
        """
        Claim pending or retry outbox records for processing.
        Atomic claim foundation.
        """
        now = datetime.now(timezone.utc)
        
        query = (
            self.session.query(SearchIndexOutbox.outbox_id)
            .filter(
                SearchIndexOutbox.status.in_(["pending", "retry"]),
                SearchIndexOutbox.available_at <= now,
                or_(
                    SearchIndexOutbox.lease_owner.is_(None),
                    SearchIndexOutbox.lease_expires_at <= now
                )
            )
            .order_by(SearchIndexOutbox.created_at.asc(), SearchIndexOutbox.outbox_id.asc())
            .limit(limit)
        )
        
        candidate_ids = [row[0] for row in query.all()]
        if not candidate_ids:
            return []

        # Atomic update
        from datetime import timedelta
        expires_at = now + timedelta(seconds=lease_seconds)
        
        updated_count = (
            self.session.query(SearchIndexOutbox)
            .filter(
                SearchIndexOutbox.outbox_id.in_(candidate_ids),
                SearchIndexOutbox.status.in_(["pending", "retry"]),
                or_(
                    SearchIndexOutbox.lease_owner.is_(None),
                    SearchIndexOutbox.lease_expires_at <= now
                )
            )
            .update(
                {
                    "status": "processing",
                    "lease_owner": claimant_id,
                    "lease_expires_at": expires_at,
                    "attempt_count": SearchIndexOutbox.attempt_count + 1,
                    "updated_at": now
                },
                synchronize_session=False,
            )
        )
        
        if updated_count == 0:
            return []

        return (
            self.session.query(SearchIndexOutbox)
            .filter(
                SearchIndexOutbox.outbox_id.in_(candidate_ids),
                SearchIndexOutbox.lease_owner == claimant_id,
                SearchIndexOutbox.status == "processing",
            )
            .order_by(SearchIndexOutbox.created_at.asc(), SearchIndexOutbox.outbox_id.asc())
            .all()
        )
