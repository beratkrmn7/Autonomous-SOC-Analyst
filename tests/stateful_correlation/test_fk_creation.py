"""Phase 6E.4A blocker 1: first-state creation must be foreign-key safe.

These tests run with SQLite `PRAGMA foreign_keys=ON` so the
state.incident_id -> incidents.incident_id FK is actually enforced. The
canonical incident and its correlation-state row must be created inside one
savepoint, and a concurrent unique-key loser must roll back both its
temporary incident and state row (leaving no orphan incident) before merging
into the winner.
"""

from __future__ import annotations

import datetime
import os
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from agent.application.stateful_correlation_service import StatefulIncidentCorrelationService
from agent.config import Settings
from agent.persistence.mappers import DataMapper
from agent.persistence.orm_models import Base, Incident, IncidentCorrelationState, IngestionJob
from agent.persistence.unit_of_work import UnitOfWork

from tests.stateful_correlation.conftest import (
    FIXED,
    make_event,
    make_incident,
    make_signal,
    submit_job,
)


def _fk_engine(path: str):
    engine = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False, "timeout": 30},
    )

    @event.listens_for(engine, "connect")
    def _enable_fk(dbapi_connection, _record):  # noqa: ANN001
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


@pytest.fixture
def fk_session_factory():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = _fk_engine(path)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    yield SessionLocal
    engine.dispose()
    try:
        os.remove(path)
    except PermissionError:
        pass


def test_first_creation_is_foreign_key_safe(fk_session_factory) -> None:
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    with UnitOfWork(session_factory=fk_session_factory, settings=settings) as uow:
        events = [make_event("a1")]
        signal = make_signal("SIG-A", ["a1"])
        incident = make_incident("INC-A", signal, events)
        result, _ = submit_job(
            uow, service, settings,
            job_id="job-a", events=events, signal=signal, incident=incident, now=FIXED,
        )

    assert result.status == "created"

    with UnitOfWork(session_factory=fk_session_factory, settings=settings) as uow:
        state = uow.correlation_state.get_by_key(result.correlation_key)
        assert state is not None
        assert str(state.incident_id) == result.canonical_incident_id
        assert uow.incidents.get(result.canonical_incident_id) is not None


def test_expires_at_is_later_than_future_dated_last_seen(fk_session_factory) -> None:
    # A short TTL plus a future-dated event window would push expires_at at or
    # below last_seen (violating the CHECK) unless expires_at anchors to
    # max(now, last_seen) + ttl.
    settings = Settings(
        stateful_correlation_enabled=True,
        stateful_correlation_state_ttl_seconds=1,
        stateful_correlation_window_seconds=1,
    )
    service = StatefulIncidentCorrelationService()
    future_event = FIXED + datetime.timedelta(days=30)

    with UnitOfWork(session_factory=fk_session_factory, settings=settings) as uow:
        events = [make_event("f1", ts=future_event)]
        signal = make_signal("SIG-F", ["f1"], ts=future_event)
        incident = make_incident("INC-F", signal, events, ts=future_event)
        result, _ = submit_job(
            uow, service, settings,
            job_id="job-f", events=events, signal=signal, incident=incident, now=FIXED,
        )

    assert result.status == "created"
    with UnitOfWork(session_factory=fk_session_factory, settings=settings) as uow:
        state = uow.correlation_state.get_by_key(result.correlation_key)
        assert state is not None
        # Both loaded back naive from SQLite; compare directly.
        assert state.expires_at > state.last_seen


def test_concurrent_first_writers_are_fk_safe_and_leave_no_orphan(fk_session_factory) -> None:
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def worker(index: int):
        events = [make_event(f"evt-{index}")]
        signal = make_signal(f"SIG-{index}", [f"evt-{index}"])
        incident = make_incident(f"INC-{index}", signal, events)
        try:
            barrier.wait(timeout=10)
            with UnitOfWork(session_factory=fk_session_factory, settings=settings) as uow:
                return submit_job(
                    uow, service, settings,
                    job_id=f"job-{index}", events=events, signal=signal,
                    incident=incident, now=FIXED,
                )[0]
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(worker, [0, 1]))

    assert not errors, f"worker threads raised: {errors}"
    assert all(r is not None for r in results)
    assert sorted(r.status for r in results) == ["created", "merged"]
    canonical_ids = {r.canonical_incident_id for r in results}
    assert len(canonical_ids) == 1

    with UnitOfWork(session_factory=fk_session_factory, settings=settings) as uow:
        assert uow.session.query(IncidentCorrelationState).count() == 1
        # Exactly one incident row: the loser's temporary incident rolled back.
        assert uow.session.query(Incident).count() == 1
        canonical_id = next(iter(canonical_ids))
        incident_row = uow.incidents.get(canonical_id)
        event_ids = [e.event_id for e in incident_row.events]
        signal_ids = [s.signal_id for s in incident_row.signals]
        assert set(event_ids) == {"evt-0", "evt-1"}
        assert set(signal_ids) == {"SIG-0", "SIG-1"}
        # Both jobs ended up associated with the single canonical incident.
        assert {str(j.id) for j in incident_row.jobs} == {"job-0", "job-1"}


# --- Blocker 2: only the real unique-correlation-key race is swallowed -----


def test_missing_detection_signal_row_propagates_real_integrity_error(
    fk_session_factory,
) -> None:
    """An incoming incident referencing a signal_id that was never persisted
    must raise the real FK IntegrityError, not be silently reinterpreted as
    the unique-correlation_key race - and must leave no orphan incident or
    correlation-state row behind."""
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    events = [make_event("a1")]
    signal = make_signal("SIG-MISSING", ["a1"])
    incident = make_incident("INC-A", signal, events)

    with UnitOfWork(session_factory=fk_session_factory, settings=settings) as uow:
        job = IngestionJob(id="job-a", status="completed")
        uow.ingestion_jobs.add(job)
        # Persist the event, but deliberately never persist SIG-MISSING as a
        # DetectionSignal row, so incident_signals.signal_id has no row to
        # reference under PRAGMA foreign_keys=ON.
        uow.canonical_events.add(DataMapper.domain_event_to_orm(events[0]))
        uow.session.flush()

        orm_signal = DataMapper.domain_signal_to_orm(signal)
        # A detached, never-added DetectionSignal row: passed to
        # resolve_and_merge only so it can build incoming_signal_rows, but
        # never persisted via uow.detection_signals.add(...).

        with pytest.raises(IntegrityError):
            service.resolve_and_merge(
                uow,
                incoming_bundle=incident,
                incoming_events=events,
                incoming_signal_rows=[orm_signal],
                job=job,
                settings=settings,
                now=FIXED,
            )
        uow.session.rollback()

    with UnitOfWork(session_factory=fk_session_factory, settings=settings) as uow:
        assert uow.session.query(IncidentCorrelationState).count() == 0
        assert uow.session.query(Incident).count() == 0


def test_concurrent_unique_key_race_still_swallowed_after_disambiguation_fix(
    fk_session_factory,
) -> None:
    """The known-good concurrent race path (two legitimate first writers on
    the same profile) must remain green after tightening the IntegrityError
    handling to disambiguate real errors from the race."""
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    events_a = [make_event("ra1")]
    signal_a = make_signal("SIG-RA", ["ra1"])
    incident_a = make_incident("INC-RA", signal_a, events_a)
    with UnitOfWork(session_factory=fk_session_factory, settings=settings) as uow:
        result_a, _ = submit_job(
            uow, service, settings,
            job_id="job-ra", events=events_a, signal=signal_a, incident=incident_a, now=FIXED,
        )
    assert result_a.status == "created"

    later = FIXED + datetime.timedelta(minutes=1)
    events_b = [make_event("rb1", ts=later)]
    signal_b = make_signal("SIG-RB", ["rb1"], ts=later)
    incident_b = make_incident("INC-RB", signal_b, events_b, ts=later)
    with UnitOfWork(session_factory=fk_session_factory, settings=settings) as uow:
        result_b, _ = submit_job(
            uow, service, settings,
            job_id="job-rb", events=events_b, signal=signal_b, incident=incident_b, now=later,
        )
    assert result_b.status == "merged"
    assert result_b.canonical_incident_id == result_a.canonical_incident_id
