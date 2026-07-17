from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from itertools import islice
from typing import Any, Literal
import uuid

from sqlalchemy import Select, and_, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from agent.opensearch.documents import (
    SearchDocument,
    calculate_payload_sha256,
    canonical_payload_bytes,
    search_document_payload,
)
from agent.persistence.orm_models import SearchIndexOutbox
from agent.persistence.repositories import GenericRepository


OutboxOperation = Literal["upsert"]
OutboxStatus = Literal["pending", "processing", "retry", "completed", "failed"]

OUTBOX_OPERATION: OutboxOperation = "upsert"
CLAIMABLE_STATUSES = ("pending", "retry")
MAX_CLAIMANT_ID_LENGTH = 64
MAX_ENQUEUE_CHUNK_SIZE = 1_000
DEFAULT_ENQUEUE_CHUNK_SIZE = 250
DEFAULT_MAX_LEASE_SECONDS = 86_400


class OutboxError(Exception):
    """Fail-closed outbox error containing only a stable, non-sensitive code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class OutboxEnqueueSummary:
    requested_count: int = 0
    inserted_count: int = 0
    reused_count: int = 0
    chunk_count: int = 0
    max_chunk_size: int = 0


@dataclass(frozen=True)
class _PreparedOutboxEntry:
    document: SearchDocument
    deduplication_key: str
    payload: dict[str, object]
    payload_sha256: str
    payload_size_bytes: int


def _chunks(values: Iterable[SearchDocument], size: int) -> Iterator[list[SearchDocument]]:
    iterator = iter(values)
    while chunk := list(islice(iterator, size)):
        yield chunk


def _deduplication_key(document: SearchDocument) -> str:
    logical_key = ":".join(
        (
            document.entity_type,
            document.entity_id,
            OUTBOX_OPERATION,
            document.schema_version,
            str(document.document_version),
        )
    )
    return hashlib.sha256(logical_key.encode("utf-8")).hexdigest()


class SearchIndexOutboxRepository(GenericRepository):
    def __init__(
        self,
        session: Session,
        *,
        max_payload_bytes: int,
        enqueue_chunk_size: int = DEFAULT_ENQUEUE_CHUNK_SIZE,
        max_claim_batch_size: int = 1_000,
        max_lease_seconds: int = DEFAULT_MAX_LEASE_SECONDS,
    ):
        super().__init__(session, SearchIndexOutbox)
        if max_payload_bytes < 1:
            raise ValueError("opensearch_outbox_max_payload_bytes_invalid")
        if not 1 <= enqueue_chunk_size <= MAX_ENQUEUE_CHUNK_SIZE:
            raise ValueError("opensearch_outbox_enqueue_chunk_size_invalid")
        if max_claim_batch_size < 1:
            raise ValueError("opensearch_outbox_max_claim_batch_size_invalid")
        if max_lease_seconds < 1:
            raise ValueError("opensearch_outbox_max_lease_seconds_invalid")
        self.max_payload_bytes = max_payload_bytes
        self.enqueue_chunk_size = enqueue_chunk_size
        self.max_claim_batch_size = max_claim_batch_size
        self.max_lease_seconds = max_lease_seconds

    def _prepare(self, document: SearchDocument) -> _PreparedOutboxEntry:
        payload = search_document_payload(document)
        payload_size_bytes = len(canonical_payload_bytes(payload))
        if payload_size_bytes > self.max_payload_bytes:
            raise OutboxError("opensearch_outbox_payload_too_large")
        return _PreparedOutboxEntry(
            document=document,
            deduplication_key=_deduplication_key(document),
            payload=payload,
            payload_sha256=calculate_payload_sha256(payload),
            payload_size_bytes=payload_size_bytes,
        )

    @staticmethod
    def _validate_existing(
        prepared: _PreparedOutboxEntry,
        existing: SearchIndexOutbox,
    ) -> None:
        if existing.payload_sha256 != prepared.payload_sha256:
            raise OutboxError("opensearch_outbox_deduplication_conflict")

    def _select_by_keys(self, keys: list[str]) -> dict[str, SearchIndexOutbox]:
        rows = self.session.execute(
            select(SearchIndexOutbox).where(
                SearchIndexOutbox.deduplication_key.in_(keys)
            )
        ).scalars()
        return {str(row.deduplication_key): row for row in rows}

    def _insert_do_nothing(self, values: list[dict[str, object]]) -> int:
        dialect_name = self.session.get_bind().dialect.name
        statement: Any
        if dialect_name == "postgresql":
            statement = postgresql_insert(SearchIndexOutbox).values(values)
        elif dialect_name == "sqlite":
            statement = sqlite_insert(SearchIndexOutbox).values(values)
        else:
            raise OutboxError("opensearch_outbox_dialect_unsupported")
        inserted_keys = self.session.execute(
            statement.on_conflict_do_nothing(
                index_elements=[SearchIndexOutbox.deduplication_key]
            ).returning(SearchIndexOutbox.deduplication_key)
        ).scalars()
        return sum(1 for _key in inserted_keys)

    def _enqueue_chunk(
        self,
        documents: list[SearchDocument],
    ) -> tuple[dict[str, SearchIndexOutbox], int]:
        prepared_by_key: dict[str, _PreparedOutboxEntry] = {}
        for document in documents:
            prepared = self._prepare(document)
            duplicate = prepared_by_key.get(prepared.deduplication_key)
            if duplicate is not None:
                if duplicate.payload_sha256 != prepared.payload_sha256:
                    raise OutboxError("opensearch_outbox_deduplication_conflict")
                continue
            prepared_by_key[prepared.deduplication_key] = prepared

        keys = list(prepared_by_key)
        existing_by_key = self._select_by_keys(keys)
        for key, existing in existing_by_key.items():
            self._validate_existing(prepared_by_key[key], existing)

        now = datetime.now(timezone.utc)
        new_entries = [
            prepared
            for key, prepared in prepared_by_key.items()
            if key not in existing_by_key
        ]
        inserted_count = 0
        if new_entries:
            inserted_count = self._insert_do_nothing(
                [
                    {
                        "outbox_id": str(uuid.uuid4()),
                        "entity_type": entry.document.entity_type,
                        "entity_id": entry.document.entity_id,
                        "operation": OUTBOX_OPERATION,
                        "schema_version": entry.document.schema_version,
                        "document_version": entry.document.document_version,
                        "deduplication_key": entry.deduplication_key,
                        "payload": entry.payload,
                        "payload_sha256": entry.payload_sha256,
                        "payload_size_bytes": entry.payload_size_bytes,
                        "status": "pending",
                        "available_at": now,
                        "attempt_count": 0,
                        "created_at": now,
                        "updated_at": now,
                        "version": 1,
                    }
                    for entry in new_entries
                ]
            )

        # This post-insert read is required even after a pre-check: it verifies the
        # winner of a concurrent ON CONFLICT race before the source transaction commits.
        persisted_by_key = self._select_by_keys(keys)
        if len(persisted_by_key) != len(prepared_by_key):
            raise OutboxError("opensearch_outbox_enqueue_failed")
        for key, existing in persisted_by_key.items():
            self._validate_existing(prepared_by_key[key], existing)
        return persisted_by_key, inserted_count

    def enqueue_upsert(self, document: SearchDocument) -> SearchIndexOutbox:
        """Enqueue one safe upsert without committing or rolling back the session."""
        persisted_by_key, _ = self._enqueue_chunk([document])
        return persisted_by_key[_deduplication_key(document)]

    def enqueue_many_upserts(
        self,
        documents: Iterable[SearchDocument],
        *,
        chunk_size: int | None = None,
    ) -> OutboxEnqueueSummary:
        """Enqueue documents using bounded pre-check, insert, and verification queries."""
        selected_chunk_size = chunk_size or self.enqueue_chunk_size
        if not 1 <= selected_chunk_size <= MAX_ENQUEUE_CHUNK_SIZE:
            raise ValueError("opensearch_outbox_enqueue_chunk_size_invalid")

        requested_count = 0
        inserted_count = 0
        chunk_count = 0
        max_chunk_size = 0
        for chunk in _chunks(documents, selected_chunk_size):
            chunk_count += 1
            requested_count += len(chunk)
            max_chunk_size = max(max_chunk_size, len(chunk))
            _, inserted = self._enqueue_chunk(chunk)
            inserted_count += inserted
        return OutboxEnqueueSummary(
            requested_count=requested_count,
            inserted_count=inserted_count,
            reused_count=requested_count - inserted_count,
            chunk_count=chunk_count,
            max_chunk_size=max_chunk_size,
        )

    def find_by_deduplication_key(
        self,
        deduplication_key: str,
    ) -> SearchIndexOutbox | None:
        return self.session.execute(
            select(SearchIndexOutbox).where(
                SearchIndexOutbox.deduplication_key == deduplication_key
            )
        ).scalar_one_or_none()

    def count_by_status(self, status: OutboxStatus) -> int:
        return int(
            self.session.execute(
                select(func.count()).select_from(SearchIndexOutbox).where(
                    SearchIndexOutbox.status == status
                )
            ).scalar_one()
        )

    def _claim_candidates(self, now: datetime, limit: int) -> Select[tuple[str]]:
        available = and_(
            SearchIndexOutbox.status.in_(CLAIMABLE_STATUSES),
            SearchIndexOutbox.available_at <= now,
            or_(
                SearchIndexOutbox.lease_owner.is_(None),
                SearchIndexOutbox.lease_expires_at <= now,
            ),
        )
        expired_processing = and_(
            SearchIndexOutbox.status == "processing",
            SearchIndexOutbox.lease_expires_at <= now,
        )
        candidates = (
            select(SearchIndexOutbox.outbox_id)
            .where(or_(available, expired_processing))
            .order_by(
                SearchIndexOutbox.created_at.asc(),
                SearchIndexOutbox.outbox_id.asc(),
            )
            .limit(limit)
        )
        if self.session.get_bind().dialect.name == "postgresql":
            candidates = candidates.with_for_update(skip_locked=True)
        return candidates

    def claim_batch(
        self,
        claimant_id: str,
        limit: int,
        lease_seconds: int = 300,
    ) -> list[SearchIndexOutbox]:
        """Atomically claim a bounded batch of available or expired records."""
        normalized_claimant_id = claimant_id.strip() if isinstance(claimant_id, str) else ""
        if not normalized_claimant_id:
            raise ValueError("opensearch_outbox_claimant_id_invalid")
        if len(normalized_claimant_id) > MAX_CLAIMANT_ID_LENGTH:
            raise ValueError("opensearch_outbox_claimant_id_too_long")
        if isinstance(limit, bool) or not 1 <= limit <= self.max_claim_batch_size:
            raise ValueError("opensearch_outbox_claim_limit_invalid")
        if (
            isinstance(lease_seconds, bool)
            or not 1 <= lease_seconds <= self.max_lease_seconds
        ):
            raise ValueError("opensearch_outbox_lease_seconds_invalid")

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=lease_seconds)
        candidates = self._claim_candidates(now, limit)
        claimed_ids = list(
            self.session.execute(
                update(SearchIndexOutbox)
                .where(SearchIndexOutbox.outbox_id.in_(candidates))
                .values(
                    status="processing",
                    lease_owner=normalized_claimant_id,
                    lease_expires_at=expires_at,
                    attempt_count=SearchIndexOutbox.attempt_count + 1,
                    updated_at=now,
                )
                .returning(SearchIndexOutbox.outbox_id)
                .execution_options(synchronize_session=False)
            ).scalars()
        )
        if not claimed_ids:
            return []
        return list(
            self.session.execute(
                select(SearchIndexOutbox)
                .where(
                    SearchIndexOutbox.outbox_id.in_(claimed_ids),
                    SearchIndexOutbox.lease_owner == normalized_claimant_id,
                    SearchIndexOutbox.status == "processing",
                )
                .order_by(
                    SearchIndexOutbox.created_at.asc(),
                    SearchIndexOutbox.outbox_id.asc(),
                )
            ).scalars()
        )
