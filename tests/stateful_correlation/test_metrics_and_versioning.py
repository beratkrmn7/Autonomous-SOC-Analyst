"""Phase 6E.4A blocker 3: stateful metrics, job-version semantics, guarded
state-version freshness within one UoW, and OpenSearch projection versioning."""

from __future__ import annotations

import datetime
import os
import tempfile

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agent.application.search_outbox import SearchOutboxService
from agent.application.stateful_correlation_service import StatefulIncidentCorrelationService
from agent.config import Settings
from agent.persistence.orm_models import (
    Base,
    IncidentCorrelationState,
    IngestionJob,
    SearchIndexOutbox,
)
from agent.persistence.unit_of_work import UnitOfWork

from tests.stateful_correlation.conftest import (
    FIXED,
    make_event,
    make_incident,
    make_signal,
    submit_job,
)


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


_STATEFUL_METRIC_KEYS = {
    "stateful_correlation_version",
    "stateful_correlation_key",
    "stateful_correlation_strategy",
    "stateful_generation",
    "stateful_merge_count",
    "correlated_job_count",
    "total_events",
    "correlated_signal_count",
    "absorbed_signal_count",
    "primary_signal_id",
}


def test_created_incident_has_full_bounded_scalar_metrics(session_factory) -> None:
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events = [make_event("a1")]
        signal = make_signal("SIG-A", ["a1"])
        incident = make_incident("INC-A", signal, events)
        result, _ = submit_job(
            uow, service, settings,
            job_id="job-a", events=events, signal=signal, incident=incident, now=FIXED,
        )
    canonical_id = result.canonical_incident_id

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        metrics = dict(uow.incidents.get(canonical_id).metrics)

    assert _STATEFUL_METRIC_KEYS <= set(metrics)
    assert metrics["stateful_generation"] == 1
    assert metrics["stateful_merge_count"] == 0
    assert metrics["correlated_job_count"] == 1
    # No mutable id lists ever land in metrics JSON.
    assert not any(isinstance(value, list) for value in metrics.values())


def test_new_job_with_identical_ids_increments_version_exactly_once(session_factory) -> None:
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events = [make_event("a1")]
        signal = make_signal("SIG-A", ["a1"])
        incident = make_incident("INC-A", signal, events)
        result_a, _ = submit_job(
            uow, service, settings,
            job_id="job-a", events=events, signal=signal, incident=incident, now=FIXED,
        )
    canonical_id = result_a.canonical_incident_id
    key = result_a.correlation_key

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        version_before = int(uow.incidents.get(canonical_id).version)

    # A *different* job re-reports the exact same event/signal IDs. This is a
    # material projection change (job_association_added), not a no-op.
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        job_b = IngestionJob(id="job-b", status="completed")
        uow.ingestion_jobs.add(job_b)
        orm_signal = uow.detection_signals.get("SIG-A")
        job_b.signals.append(orm_signal)
        uow.session.flush()
        result_b = service.resolve_and_merge(
            uow,
            incoming_bundle=make_incident("INC-A2", make_signal("SIG-A", ["a1"]), [make_event("a1")]),
            incoming_events=[make_event("a1")],
            incoming_signal_rows=[orm_signal],
            job=job_b,
            settings=settings,
            now=FIXED,
        )

    assert result_b.status == "merged"
    assert "job_association_added" in result_b.material_changes

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        incident_row = uow.incidents.get(canonical_id)
        assert int(incident_row.version) == version_before + 1
        assert int(dict(incident_row.metrics)["correlated_job_count"]) == 2
        assert {str(j.id) for j in incident_row.jobs} == {"job-a", "job-b"}
        state = uow.correlation_state.get_by_key(key)
        assert int(state.generation) == 1


def test_repeating_the_same_job_is_a_true_noop(session_factory) -> None:
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events = [make_event("a1")]
        signal = make_signal("SIG-A", ["a1"])
        incident = make_incident("INC-A", signal, events)
        result_a, _ = submit_job(
            uow, service, settings,
            job_id="job-a", events=events, signal=signal, incident=incident, now=FIXED,
        )
    canonical_id = result_a.canonical_incident_id
    key = result_a.correlation_key

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        version_before = int(uow.incidents.get(canonical_id).version)
        merge_count_before = int(dict(uow.incidents.get(canonical_id).metrics)["stateful_merge_count"])

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        job_a = uow.ingestion_jobs.get("job-a")
        orm_signal = uow.detection_signals.get("SIG-A")
        result_repeat = service.resolve_and_merge(
            uow,
            incoming_bundle=make_incident("INC-A", make_signal("SIG-A", ["a1"]), [make_event("a1")]),
            incoming_events=[make_event("a1")],
            incoming_signal_rows=[orm_signal],
            job=job_a,
            settings=settings,
            now=FIXED,
        )

    assert result_repeat.status == "no_op"
    assert result_repeat.material_changes == ()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        incident_row = uow.incidents.get(canonical_id)
        assert int(incident_row.version) == version_before
        assert int(dict(incident_row.metrics)["stateful_merge_count"]) == merge_count_before
        assert int(uow.correlation_state.get_by_key(key).generation) == 1


def test_three_same_profile_resolves_in_one_uow_do_not_hit_stale_state_version(
    session_factory,
) -> None:
    """A guarded bulk state UPDATE must not leave a stale in-session ORM
    version; three same-profile merges in one open UnitOfWork must all
    succeed rather than raising a spurious optimistic-concurrency conflict."""
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        statuses = []
        for index in range(3):
            event = make_event(f"e{index}", ts=FIXED + datetime.timedelta(minutes=index))
            signal = make_signal(f"SIG-{index}", [f"e{index}"], ts=FIXED + datetime.timedelta(minutes=index))
            incident = make_incident(
                f"INC-{index}", signal, [event], ts=FIXED + datetime.timedelta(minutes=index)
            )
            result, _ = submit_job(
                uow, service, settings,
                job_id=f"job-{index}", events=[event], signal=signal, incident=incident,
                now=FIXED + datetime.timedelta(minutes=index),
            )
            statuses.append(result.status)

    assert statuses == ["created", "merged", "merged"]

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        states = uow.session.query(IncidentCorrelationState).all()
        assert len(states) == 1
        # generation stayed 1 (all merges), version advanced once per merge.
        assert int(states[0].generation) == 1
        assert int(states[0].version) == 3  # 1 create + 2 guarded extends


def test_new_job_association_bumps_opensearch_document_version(session_factory) -> None:
    settings = Settings(stateful_correlation_enabled=True, opensearch_enabled=True)
    service = StatefulIncidentCorrelationService()

    def _enqueue(uow, incident_row):
        SearchOutboxService(
            uow.session, uow.search_index_outbox, uow.settings
        ).enqueue_incidents([incident_row])

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events = [make_event("a1")]
        signal = make_signal("SIG-A", ["a1"])
        incident = make_incident("INC-A", signal, events)
        result_a, _ = submit_job(
            uow, service, settings,
            job_id="job-a", events=events, signal=signal, incident=incident, now=FIXED,
        )
        _enqueue(uow, result_a.canonical_incident)
    canonical_id = result_a.canonical_incident_id

    def _document_versions(uow) -> list[int]:
        return [
            int(row.document_version)
            for row in uow.session.query(SearchIndexOutbox).filter(
                SearchIndexOutbox.entity_type == "incident",
                SearchIndexOutbox.entity_id == canonical_id,
            )
        ]

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        first_versions = _document_versions(uow)
    assert first_versions
    first_max = max(first_versions)

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        job_b = IngestionJob(id="job-b", status="completed")
        uow.ingestion_jobs.add(job_b)
        orm_signal = uow.detection_signals.get("SIG-A")
        job_b.signals.append(orm_signal)
        uow.session.flush()
        result_b = service.resolve_and_merge(
            uow,
            incoming_bundle=make_incident("INC-A2", make_signal("SIG-A", ["a1"]), [make_event("a1")]),
            incoming_events=[make_event("a1")],
            incoming_signal_rows=[orm_signal],
            job=job_b,
            settings=settings,
            now=FIXED,
        )
        assert result_b.status == "merged"
        _enqueue(uow, result_b.canonical_incident)

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        all_versions = _document_versions(uow)

    assert max(all_versions) > first_max
