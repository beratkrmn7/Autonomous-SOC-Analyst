from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from agent.application.analysis_service import AnalysisService
from agent.application.cancellation import JobCancellationRequested
from agent.application.models import AnalysisResult
from agent.application.search_outbox import SearchOutboxService
from agent.config import Settings
from agent.detection.models import DetectionMetrics, DetectionResult
from agent.ingestion.models import (
    CanonicalLogEvent,
    IngestionMetrics,
    IngestionResult,
    InputFormat,
)
from agent.persistence.database import Base
from agent.persistence.orm_models import (
    CanonicalEvent,
    IngestionJob,
    SearchIndexOutbox,
    ingestion_job_events,
)
from agent.persistence.outbox_repository import OutboxError
from agent.persistence.unit_of_work import UnitOfWork


NOW = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)


def _settings(*, max_payload_bytes: int = 65_536) -> Settings:
    return Settings(
        _env_file=None,
        opensearch_enabled=True,
        opensearch_outbox_max_payload_bytes=max_payload_bytes,
    )


@pytest.fixture
def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    yield factory
    engine.dispose()


def _counts(factory) -> tuple[int, int, int, int]:
    with factory() as session:
        return (
            session.execute(select(func.count()).select_from(IngestionJob)).scalar_one(),
            session.execute(select(func.count()).select_from(CanonicalEvent)).scalar_one(),
            session.execute(
                select(func.count()).select_from(ingestion_job_events)
            ).scalar_one(),
            session.execute(
                select(func.count()).select_from(SearchIndexOutbox)
            ).scalar_one(),
        )


def test_source_and_association_roll_back_when_outbox_enqueue_fails(database) -> None:
    uow = UnitOfWork(session_factory=database, settings=_settings(max_payload_bytes=1_024))

    with pytest.raises(OutboxError, match="opensearch_outbox_payload_too_large"):
        with uow:
            job = IngestionJob(id="job-too-large", status="processing")
            source = CanonicalEvent(
                event_id="event-too-large",
                timestamp=NOW,
                safe_message_excerpt="x" * 10_000,
            )
            job.events.append(source)
            uow.session.add(job)
            SearchOutboxService(
                uow.session,
                uow.search_index_outbox,
                uow.settings,
            ).enqueue_analysis(events=[source], signals=[], incidents=[])

    assert _counts(database) == (0, 0, 0, 0)


def test_outbox_and_source_roll_back_when_later_transaction_step_fails(database) -> None:
    uow = UnitOfWork(session_factory=database, settings=_settings())

    with pytest.raises(RuntimeError, match="later_source_failure"):
        with uow:
            job = IngestionJob(id="job-late-failure", status="processing")
            source = CanonicalEvent(event_id="event-late-failure", timestamp=NOW)
            job.events.append(source)
            uow.session.add(job)
            SearchOutboxService(
                uow.session,
                uow.search_index_outbox,
                uow.settings,
            ).enqueue_analysis(events=[source], signals=[], incidents=[])
            raise RuntimeError("later_source_failure")

    assert _counts(database) == (0, 0, 0, 0)


def test_cancellation_completion_race_rolls_back_source_and_outbox(database) -> None:
    settings = _settings()
    uow = UnitOfWork(session_factory=database, settings=settings)
    with uow:
        uow.session.add(
            IngestionJob(id="job-cancelled", source_name="source", status="cancelled")
        )

    event = CanonicalLogEvent(
        event_id="event-cancelled",
        timestamp=NOW,
        safe_message_excerpt="safe",
        parser_name="test",
        parse_status="success",
    )
    result = AnalysisResult(
        source_name="source",
        ingestion_result=IngestionResult(
            source_name="source",
            input_format=InputFormat.JSONL,
            events=[event],
            metrics=IngestionMetrics(total_records=1),
        ),
        detection_result=DetectionResult(
            signals=[],
            incidents=[],
            suppressed_signals=[],
            uncorrelated_event_ids=[],
            warnings=[],
            metrics=DetectionMetrics(signal_count=0, duration_ms=1.0),
        ),
        event_map={event.event_id: event},
        signal_map={},
        incidents=[],
        job_id="job-cancelled",
    )

    with pytest.raises(JobCancellationRequested):
        AnalysisService(uow=uow)._persist_analysis(result, run_triage=False)

    assert _counts(database) == (1, 0, 0, 0)
    with database() as session:
        assert session.get(IngestionJob, "job-cancelled").status == "cancelled"


def test_repository_never_commits_independently(database, monkeypatch) -> None:
    uow = UnitOfWork(session_factory=database, settings=_settings())
    with uow:
        commit_calls = 0
        original_commit = uow.session.commit

        def tracked_commit() -> None:
            nonlocal commit_calls
            commit_calls += 1
            original_commit()

        monkeypatch.setattr(uow.session, "commit", tracked_commit)
        source = CanonicalEvent(event_id="event-no-commit", timestamp=NOW)
        uow.session.add(source)
        SearchOutboxService(
            uow.session,
            uow.search_index_outbox,
            uow.settings,
        ).enqueue_analysis(events=[source], signals=[], incidents=[])
        assert commit_calls == 0

    assert commit_calls == 1
