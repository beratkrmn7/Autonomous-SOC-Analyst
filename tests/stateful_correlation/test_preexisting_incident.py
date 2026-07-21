"""Phase 6E.4A blocker 4: correctly handle pre-existing Incident rows.

`create_canonical()`'s early return for an already-persisted Incident used
to skip all stateful metrics/version bookkeeping. It must instead apply the
full scalar metric set, bump Incident.version exactly once on a real change,
and never fabricate a "new generation" that silently reuses the same
canonical incident_id.
"""

from __future__ import annotations

import datetime
import os
import tempfile

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agent.application.stateful_correlation_service import StatefulIncidentCorrelationService
from agent.config import Settings
from agent.persistence.mappers import DataMapper
from agent.persistence.orm_models import Base, IngestionJob
from agent.persistence.unit_of_work import UnitOfWork

from tests.stateful_correlation.conftest import FIXED, make_event, make_incident, make_signal


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


def _persist_plain_incident(uow, *, incident_id, signal, events, job_id) -> IngestionJob:
    """Persist an Incident the way plain batch-local persistence would -
    with no stateful metrics stamped at all, and no correlation-state row."""
    job = IngestionJob(id=job_id, status="completed")
    uow.ingestion_jobs.add(job)
    for event in events:
        uow.canonical_events.add(DataMapper.domain_event_to_orm(event))
    orm_signal = DataMapper.domain_signal_to_orm(signal)
    uow.detection_signals.add(orm_signal)
    job.signals.append(orm_signal)

    bundle = make_incident(incident_id, signal, events)
    orm_incident = DataMapper.domain_incident_to_orm(bundle)
    uow.incidents.add(orm_incident)
    orm_incident.jobs.append(job)
    uow.session.flush()
    return job


# --- 1: pre-existing incident + no state row ---------------------------------


def test_preexisting_incident_with_no_state_row_gets_full_metrics_and_state(
    session_factory,
) -> None:
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    events = [make_event("a1")]
    signal = make_signal("SIG-A", ["a1"])

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        _persist_plain_incident(
            uow, incident_id="INC-A", signal=signal, events=events, job_id="job-a"
        )
        version_before = int(uow.incidents.get("INC-A").version)

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        job_b = IngestionJob(id="job-b", status="completed")
        uow.ingestion_jobs.add(job_b)
        orm_signal = uow.detection_signals.get("SIG-A")
        job_b.signals.append(orm_signal)
        uow.session.flush()
        result = service.resolve_and_merge(
            uow,
            incoming_bundle=make_incident("INC-A", signal, events),
            incoming_events=events,
            incoming_signal_rows=[orm_signal],
            job=job_b,
            settings=settings,
            now=FIXED,
        )

    assert result.status == "created"
    assert result.generation == 1

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        incident_row = uow.incidents.get("INC-A")
        metrics = dict(incident_row.metrics)
        assert metrics["stateful_generation"] == 1
        assert metrics["correlated_job_count"] == 2
        assert metrics["stateful_correlation_key"] == result.correlation_key
        assert int(incident_row.version) == version_before + 1
        state = uow.correlation_state.get_by_key(result.correlation_key)
        assert state is not None
        assert str(state.incident_id) == "INC-A"
        assert int(state.generation) == 1


# --- 2: pre-existing incident + new job --------------------------------------


def test_preexisting_incident_new_job_increments_job_count_and_version_once(
    session_factory,
) -> None:
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    events = [make_event("a1")]
    signal = make_signal("SIG-A", ["a1"])

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        _persist_plain_incident(
            uow, incident_id="INC-A", signal=signal, events=events, job_id="job-a"
        )

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        incident_row = uow.incidents.get("INC-A")
        job_b = IngestionJob(id="job-b", status="completed")
        uow.ingestion_jobs.add(job_b)
        version_before = int(incident_row.version)
        job_count_before = len(incident_row.jobs)

        canonical_row, changed = service._merge_service.create_canonical(
            uow,
            bundle=make_incident("INC-A", signal, events),
            job=job_b,
            correlation_key="scv1:test-key",
            strategy="source_service_campaign",
            correlation_version="1",
            generation=1,
        )

        assert changed is True
        assert len(canonical_row.jobs) == job_count_before + 1
        assert int(canonical_row.version) == version_before + 1
        assert dict(canonical_row.metrics)["correlated_job_count"] == job_count_before + 1


def test_preexisting_incident_same_job_and_metrics_is_a_true_noop(session_factory) -> None:
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    events = [make_event("a1")]
    signal = make_signal("SIG-A", ["a1"])

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        job_a = _persist_plain_incident(
            uow, incident_id="INC-A", signal=signal, events=events, job_id="job-a"
        )
        # Stamp the exact same stateful metrics this call will pass, so the
        # second call is a genuine repeat with nothing new to record.
        canonical_row, changed_first = service._merge_service.create_canonical(
            uow,
            bundle=make_incident("INC-A", signal, events),
            job=job_a,
            correlation_key="scv1:test-key",
            strategy="source_service_campaign",
            correlation_version="1",
            generation=1,
        )
        assert changed_first is True
        version_after_first = int(canonical_row.version)

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        job_a = uow.ingestion_jobs.get("job-a")
        canonical_row, changed_second = service._merge_service.create_canonical(
            uow,
            bundle=make_incident("INC-A", signal, events),
            job=job_a,
            correlation_key="scv1:test-key",
            strategy="source_service_campaign",
            correlation_version="1",
            generation=1,
        )
        assert changed_second is False
        assert int(canonical_row.version) == version_after_first


# --- 3: expired state + identical incoming incident_id/event IDs ------------


def test_expired_state_with_identical_incoming_id_does_not_fake_new_generation(
    session_factory,
) -> None:
    settings = Settings(
        stateful_correlation_enabled=True,
        stateful_correlation_state_ttl_seconds=60,
        stateful_correlation_window_seconds=60,
    )
    service = StatefulIncidentCorrelationService()

    events = [make_event("a1")]
    signal = make_signal("SIG-A", ["a1"])
    incident = make_incident("INC-A", signal, events)

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        job_a = IngestionJob(id="job-a", status="completed")
        uow.ingestion_jobs.add(job_a)
        for event in events:
            uow.canonical_events.add(DataMapper.domain_event_to_orm(event))
        orm_signal = DataMapper.domain_signal_to_orm(signal)
        uow.detection_signals.add(orm_signal)
        job_a.signals.append(orm_signal)
        uow.session.flush()
        result_a = service.resolve_and_merge(
            uow,
            incoming_bundle=incident,
            incoming_events=events,
            incoming_signal_rows=[orm_signal],
            job=job_a,
            settings=settings,
            now=FIXED,
        )

    assert result_a.status == "created"
    canonical_id = result_a.canonical_incident_id
    key = result_a.correlation_key
    assert canonical_id == "INC-A"

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        state = uow.correlation_state.get_by_key(key)
        before = (
            str(state.incident_id),
            int(state.generation),
            int(state.version),
        )

    # Well past the TTL/window: the state is now expired. Resubmit the exact
    # same deterministic incident/event content (same job, same bundle).
    much_later = FIXED + datetime.timedelta(hours=1)
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        job_a = uow.ingestion_jobs.get("job-a")
        orm_signal = uow.detection_signals.get("SIG-A")
        result_b = service.resolve_and_merge(
            uow,
            incoming_bundle=incident,
            incoming_events=events,
            incoming_signal_rows=[orm_signal],
            job=job_a,
            settings=settings,
            now=much_later,
        )

    # Must not claim a fabricated new generation reusing the same incident_id.
    assert not (result_b.status == "new_generation" and result_b.canonical_incident_id == canonical_id)
    assert result_b.canonical_incident_id == canonical_id

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        state = uow.correlation_state.get_by_key(key)
        after = (
            str(state.incident_id),
            int(state.generation),
            int(state.version),
        )

    assert after == before
