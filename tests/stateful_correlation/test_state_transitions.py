"""Phase 6E.4A blocker 2: state-transition semantics - a stale backward
arrival must never replace or mutate an active campaign."""

from __future__ import annotations

import datetime
import os
import tempfile

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agent.application.stateful_correlation_service import StatefulIncidentCorrelationService
from agent.config import Settings
from agent.persistence.orm_models import Base, IngestionJob
from agent.persistence.unit_of_work import UnitOfWork

from tests.stateful_correlation.conftest import make_event, make_incident, make_signal, submit_job


DAY = datetime.datetime(2026, 7, 10, tzinfo=datetime.timezone.utc)


@pytest.fixture
def session_factory():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    yield SessionLocal
    engine.dispose()
    try:
        os.remove(path)
    except PermissionError:
        pass


def _at(hour: int) -> datetime.datetime:
    return DAY + datetime.timedelta(hours=hour)


def test_stale_backward_arrival_leaves_active_state_unchanged(session_factory) -> None:
    settings = Settings(
        stateful_correlation_enabled=True,
        stateful_correlation_window_seconds=3600,
        stateful_correlation_state_ttl_seconds=86400,
    )
    service = StatefulIncidentCorrelationService()

    # Active campaign at 10:00.
    active_time = _at(10)
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events = [make_event("a1", ts=active_time)]
        signal = make_signal("SIG-A", ["a1"], ts=active_time)
        incident = make_incident("INC-A", signal, events, ts=active_time)
        result_a, _ = submit_job(
            uow, service, settings,
            job_id="job-a", events=events, signal=signal, incident=incident, now=active_time,
        )
    key = result_a.correlation_key
    canonical_id = result_a.canonical_incident_id

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        state = uow.correlation_state.get_by_key(key)
        before = (
            str(state.incident_id),
            int(state.generation),
            int(state.version),
            state.first_seen,
            state.last_seen,
        )

    # Late incident describing activity at 01:00, ingested at 10:05. 01:00 is
    # far older than 10:00 - window (09:00), so it must be classified stale.
    late_event = _at(1)
    ingestion_time = _at(10) + datetime.timedelta(minutes=5)
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events = [make_event("b1", ts=late_event)]
        signal = make_signal("SIG-B", ["b1"], ts=late_event)
        incident = make_incident("INC-B", signal, events, ts=late_event)
        result_b, _ = submit_job(
            uow, service, settings,
            job_id="job-b", events=events, signal=signal, incident=incident,
            now=ingestion_time,
        )

    assert result_b.status == "stale"
    assert result_b.material_changes == ()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        state = uow.correlation_state.get_by_key(key)
        after = (
            str(state.incident_id),
            int(state.generation),
            int(state.version),
            state.first_seen,
            state.last_seen,
        )
        # The stale arrival never became (or displaced) the canonical
        # campaign incident.
        assert str(state.incident_id) == canonical_id

    # incident_id, generation, version, first_seen and last_seen all unchanged.
    assert after == before


def test_later_burst_beyond_window_starts_new_generation(session_factory) -> None:
    settings = Settings(
        stateful_correlation_enabled=True,
        stateful_correlation_window_seconds=3600,
        stateful_correlation_state_ttl_seconds=86400,
    )
    service = StatefulIncidentCorrelationService()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events = [make_event("a1", ts=_at(10))]
        signal = make_signal("SIG-A", ["a1"], ts=_at(10))
        incident = make_incident("INC-A", signal, events, ts=_at(10))
        result_a, _ = submit_job(
            uow, service, settings,
            job_id="job-a", events=events, signal=signal, incident=incident, now=_at(10),
        )
    canonical_id = result_a.canonical_incident_id

    # A distinctly later burst (16:00) - beyond 10:00 + 1h window - starts a
    # new generation rather than merging into the earlier active campaign.
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events = [make_event("c1", ts=_at(16))]
        signal = make_signal("SIG-C", ["c1"], ts=_at(16))
        incident = make_incident("INC-C", signal, events, ts=_at(16))
        result_c, _ = submit_job(
            uow, service, settings,
            job_id="job-c", events=events, signal=signal, incident=incident, now=_at(16),
        )

    assert result_c.status == "new_generation"
    assert result_c.generation == 2
    assert result_c.canonical_incident_id != canonical_id


# --- Blocker 1 (round 3): same incident_id is never an unconditional no-op --


def test_expired_state_same_id_same_anchor_additional_signal_merges_without_new_generation(
    session_factory,
) -> None:
    """A: expired state + same incident ID + same anchor + additional
    supporting signal/event + new job -> merged, generation unchanged, all
    signals/events/jobs attached, Incident.version increments exactly once.
    """
    settings = Settings(
        stateful_correlation_enabled=True,
        stateful_correlation_state_ttl_seconds=60,
        stateful_correlation_window_seconds=60,
    )
    service = StatefulIncidentCorrelationService()

    events_a = [make_event("a1", ts=_at(10))]
    signal_a = make_signal("SIG-A", ["a1"], ts=_at(10))
    incident_a = make_incident("INC-A", signal_a, events_a, ts=_at(10))
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        result_a, _ = submit_job(
            uow, service, settings,
            job_id="job-a", events=events_a, signal=signal_a, incident=incident_a, now=_at(10),
        )
    assert result_a.status == "created"
    canonical_id = result_a.canonical_incident_id
    assert canonical_id == "INC-A"
    key = result_a.correlation_key

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        version_before = int(uow.incidents.get(canonical_id).version)

    # Well past TTL/window - state is now expired. Resubmit the SAME
    # deterministic incident_id (same anchor), but with an additional
    # supporting signal/event, via a new job.
    much_later = _at(10) + datetime.timedelta(hours=2)
    events_b = [make_event("b1", ts=much_later)]
    signal_b = make_signal("SIG-B", ["b1"], ts=much_later)
    incident_b = make_incident("INC-A", signal_b, events_b, ts=much_later)
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        result_b, _ = submit_job(
            uow, service, settings,
            job_id="job-b", events=events_b, signal=signal_b, incident=incident_b, now=much_later,
        )

    assert result_b.status == "merged"
    assert result_b.generation == 1  # preserved - never a fabricated new generation
    assert result_b.canonical_incident_id == canonical_id

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        incident_row = uow.incidents.get(canonical_id)
        event_ids = {e.event_id for e in incident_row.events if not e.is_context}
        signal_ids = {s.signal_id for s in incident_row.signals}
        job_ids = {str(j.id) for j in incident_row.jobs}
        assert event_ids == {"a1", "b1"}
        assert signal_ids == {"SIG-A", "SIG-B"}
        assert job_ids == {"job-a", "job-b"}
        assert int(incident_row.version) == version_before + 1
        state = uow.correlation_state.get_by_key(key)
        assert int(state.generation) == 1


def test_expired_state_same_id_identical_content_same_job_is_true_noop(session_factory) -> None:
    """B: expired state + same incident ID + identical content + same job ->
    true no_op, no version/state changes."""
    settings = Settings(
        stateful_correlation_enabled=True,
        stateful_correlation_state_ttl_seconds=60,
        stateful_correlation_window_seconds=60,
    )
    service = StatefulIncidentCorrelationService()

    events = [make_event("a1", ts=_at(10))]
    signal = make_signal("SIG-A", ["a1"], ts=_at(10))
    incident = make_incident("INC-A", signal, events, ts=_at(10))
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        result_a, _ = submit_job(
            uow, service, settings,
            job_id="job-a", events=events, signal=signal, incident=incident, now=_at(10),
        )
    canonical_id = result_a.canonical_incident_id
    key = result_a.correlation_key

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        version_before = int(uow.incidents.get(canonical_id).version)
        state_before = uow.correlation_state.get_by_key(key)
        before = (int(state_before.generation), int(state_before.version))

    much_later = _at(10) + datetime.timedelta(hours=2)
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        job_a = uow.ingestion_jobs.get("job-a")
        orm_signal = uow.detection_signals.get("SIG-A")
        result_b = service.resolve_and_merge(
            uow,
            incoming_bundle=make_incident("INC-A", signal, events, ts=_at(10)),
            incoming_events=events,
            incoming_signal_rows=[orm_signal],
            job=job_a,
            settings=settings,
            now=much_later,
        )

    assert result_b.status == "no_op"
    assert result_b.material_changes == ()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        version_after = int(uow.incidents.get(canonical_id).version)
        state_after = uow.correlation_state.get_by_key(key)
        after = (int(state_after.generation), int(state_after.version))

    assert version_after == version_before
    assert after == before


def test_expired_state_same_id_identical_ids_new_job_attaches_and_bumps_version_once(
    session_factory,
) -> None:
    """C: expired state + same incident ID + identical event/signal IDs but
    new job -> job attached, correlated_job_count increments,
    Incident.version increments exactly once, generation unchanged."""
    settings = Settings(
        stateful_correlation_enabled=True,
        stateful_correlation_state_ttl_seconds=60,
        stateful_correlation_window_seconds=60,
    )
    service = StatefulIncidentCorrelationService()

    events = [make_event("a1", ts=_at(10))]
    signal = make_signal("SIG-A", ["a1"], ts=_at(10))
    incident = make_incident("INC-A", signal, events, ts=_at(10))
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        result_a, _ = submit_job(
            uow, service, settings,
            job_id="job-a", events=events, signal=signal, incident=incident, now=_at(10),
        )
    canonical_id = result_a.canonical_incident_id
    key = result_a.correlation_key

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        version_before = int(uow.incidents.get(canonical_id).version)
        job_count_before = int(dict(uow.incidents.get(canonical_id).metrics)["correlated_job_count"])

    much_later = _at(10) + datetime.timedelta(hours=2)
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        job_b = IngestionJob(id="job-b", status="completed")
        uow.ingestion_jobs.add(job_b)
        orm_signal = uow.detection_signals.get("SIG-A")
        job_b.signals.append(orm_signal)
        uow.session.flush()
        result_b = service.resolve_and_merge(
            uow,
            incoming_bundle=make_incident("INC-A", signal, events, ts=_at(10)),
            incoming_events=events,
            incoming_signal_rows=[orm_signal],
            job=job_b,
            settings=settings,
            now=much_later,
        )

    assert result_b.status == "merged"
    assert "job_association_added" in result_b.material_changes
    assert result_b.generation == 1

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        incident_row = uow.incidents.get(canonical_id)
        assert int(incident_row.version) == version_before + 1
        metrics = dict(incident_row.metrics)
        assert metrics["correlated_job_count"] == job_count_before + 1
        state = uow.correlation_state.get_by_key(key)
        assert int(state.generation) == 1
