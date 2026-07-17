from __future__ import annotations

from collections.abc import Iterable, Iterator
from itertools import islice
from typing import TypeVar

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent.config import Settings
from agent.opensearch.documents import (
    SearchDocument,
    canonical_event_document,
    detection_signal_document,
    incident_document,
)
from agent.persistence.orm_models import (
    CanonicalEvent,
    DetectionSignal,
    EvidenceItem,
    Incident,
    IncidentEvent,
    IncidentSignal,
    Report,
    ingestion_job_events,
    ingestion_job_incidents,
    ingestion_job_signals,
)
from agent.persistence.outbox_repository import (
    OutboxEnqueueSummary,
    SearchIndexOutboxRepository,
)


T = TypeVar("T")


def _chunks(values: Iterable[T], size: int) -> Iterator[list[T]]:
    iterator = iter(values)
    while chunk := list(islice(iterator, size)):
        yield chunk


def _merge_summaries(
    left: OutboxEnqueueSummary,
    right: OutboxEnqueueSummary,
) -> OutboxEnqueueSummary:
    return OutboxEnqueueSummary(
        requested_count=left.requested_count + right.requested_count,
        inserted_count=left.inserted_count + right.inserted_count,
        reused_count=left.reused_count + right.reused_count,
        chunk_count=left.chunk_count + right.chunk_count,
        max_chunk_size=max(left.max_chunk_size, right.max_chunk_size),
    )


def _add(mapping: dict[str, set[str]], key: object, value: object) -> None:
    mapping.setdefault(str(key), set()).add(str(value))


class SearchOutboxService:
    """Build stable safe projections and enqueue them in the source transaction."""

    def __init__(
        self,
        session: Session,
        repository: SearchIndexOutboxRepository,
        settings: Settings,
    ) -> None:
        self.session = session
        self.repository = repository
        self.settings = settings
        self.chunk_size = settings.opensearch_outbox_enqueue_chunk_size

    @property
    def enabled(self) -> bool:
        return self.settings.opensearch_enabled

    def enqueue_analysis(
        self,
        *,
        events: Iterable[CanonicalEvent],
        signals: Iterable[DetectionSignal],
        incidents: Iterable[Incident],
    ) -> OutboxEnqueueSummary:
        if not self.enabled:
            return OutboxEnqueueSummary()
        self.session.flush()
        summary = self._enqueue_events(events)
        summary = _merge_summaries(summary, self._enqueue_signals(signals))
        return _merge_summaries(summary, self._enqueue_incidents(incidents))

    def enqueue_incidents(
        self,
        incidents: Iterable[Incident],
    ) -> OutboxEnqueueSummary:
        if not self.enabled:
            return OutboxEnqueueSummary()
        self.session.flush()
        return self._enqueue_incidents(incidents)

    def _enqueue_events(
        self,
        events: Iterable[CanonicalEvent],
    ) -> OutboxEnqueueSummary:
        summary = OutboxEnqueueSummary()
        for rows in _chunks(events, self.chunk_size):
            event_ids = [str(row.event_id) for row in rows]
            job_ids: dict[str, set[str]] = {}
            incident_ids: dict[str, set[str]] = {}
            context_incident_ids: dict[str, set[str]] = {}

            for event_id, job_id in self.session.execute(
                select(
                    ingestion_job_events.c.event_id,
                    ingestion_job_events.c.job_id,
                ).where(ingestion_job_events.c.event_id.in_(event_ids))
            ):
                _add(job_ids, event_id, job_id)
            for event_id, incident_id, is_context in self.session.execute(
                select(
                    IncidentEvent.event_id,
                    IncidentEvent.incident_id,
                    IncidentEvent.is_context,
                ).where(IncidentEvent.event_id.in_(event_ids))
            ):
                target = context_incident_ids if is_context else incident_ids
                _add(target, event_id, incident_id)

            documents: list[SearchDocument] = []
            for row in rows:
                event_id = str(row.event_id)
                jobs = job_ids.get(event_id, set())
                incidents = incident_ids.get(event_id, set())
                context_incidents = context_incident_ids.get(event_id, set())
                projection_version = (
                    1 + len(jobs) + len(incidents) + len(context_incidents)
                )
                documents.append(
                    canonical_event_document(
                        row,
                        schema_version=self.settings.opensearch_schema_version,
                        document_version=projection_version,
                        job_ids=tuple(sorted(jobs)),
                        incident_ids=tuple(sorted(incidents)),
                        context_incident_ids=tuple(sorted(context_incidents)),
                    )
                )
            summary = _merge_summaries(
                summary,
                self.repository.enqueue_many_upserts(
                    documents,
                    chunk_size=self.chunk_size,
                ),
            )
        return summary

    def _enqueue_signals(
        self,
        signals: Iterable[DetectionSignal],
    ) -> OutboxEnqueueSummary:
        summary = OutboxEnqueueSummary()
        for rows in _chunks(signals, self.chunk_size):
            signal_ids = [str(row.signal_id) for row in rows]
            job_ids: dict[str, set[str]] = {}
            incident_ids: dict[str, set[str]] = {}

            for signal_id, job_id in self.session.execute(
                select(
                    ingestion_job_signals.c.signal_id,
                    ingestion_job_signals.c.job_id,
                ).where(ingestion_job_signals.c.signal_id.in_(signal_ids))
            ):
                _add(job_ids, signal_id, job_id)
            for signal_id, incident_id in self.session.execute(
                select(
                    IncidentSignal.signal_id,
                    IncidentSignal.incident_id,
                ).where(IncidentSignal.signal_id.in_(signal_ids))
            ):
                _add(incident_ids, signal_id, incident_id)

            documents: list[SearchDocument] = []
            for row in rows:
                signal_id = str(row.signal_id)
                jobs = job_ids.get(signal_id, set())
                incidents = incident_ids.get(signal_id, set())
                documents.append(
                    detection_signal_document(
                        row,
                        schema_version=self.settings.opensearch_schema_version,
                        document_version=1 + len(jobs) + len(incidents),
                        job_ids=tuple(sorted(jobs)),
                        incident_ids=tuple(sorted(incidents)),
                    )
                )
            summary = _merge_summaries(
                summary,
                self.repository.enqueue_many_upserts(
                    documents,
                    chunk_size=self.chunk_size,
                ),
            )
        return summary

    def _enqueue_incidents(
        self,
        incidents: Iterable[Incident],
    ) -> OutboxEnqueueSummary:
        summary = OutboxEnqueueSummary()
        for rows in _chunks(incidents, self.chunk_size):
            incident_ids = [str(row.incident_id) for row in rows]
            job_ids: dict[str, set[str]] = {}
            report_ids: set[str] = set()
            validated_evidence_ids: set[str] = set()

            for incident_id, job_id in self.session.execute(
                select(
                    ingestion_job_incidents.c.incident_id,
                    ingestion_job_incidents.c.job_id,
                ).where(ingestion_job_incidents.c.incident_id.in_(incident_ids))
            ):
                _add(job_ids, incident_id, job_id)
            report_ids.update(
                str(value)
                for value in self.session.execute(
                    select(Report.incident_id)
                    .where(Report.incident_id.in_(incident_ids))
                    .distinct()
                ).scalars()
            )
            validated_evidence_ids.update(
                str(value)
                for value in self.session.execute(
                    select(EvidenceItem.incident_id)
                    .where(
                        EvidenceItem.incident_id.in_(incident_ids),
                        EvidenceItem.validation_status == "validated",
                    )
                    .distinct()
                ).scalars()
            )

            documents = [
                incident_document(
                    row,
                    schema_version=self.settings.opensearch_schema_version,
                    job_ids=tuple(sorted(job_ids.get(str(row.incident_id), set()))),
                    has_report=str(row.incident_id) in report_ids,
                    has_validated_evidence=(
                        str(row.incident_id) in validated_evidence_ids
                    ),
                )
                for row in rows
            ]
            summary = _merge_summaries(
                summary,
                self.repository.enqueue_many_upserts(
                    documents,
                    chunk_size=self.chunk_size,
                ),
            )
        return summary
