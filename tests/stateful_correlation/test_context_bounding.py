"""Phase 6E.4A: persisted context associations must be bounded and
versioned, not add-only.

The pure merge already computes a deterministic bounded context_event_ids
set, but persistence used to only add/promote associations - it never
removed context-only rows that fell outside the final bounded set, and
merge_into_canonical ignored the changed result from _reconcile_associations,
so pure context changes could occur without an Incident.version increment.
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
from agent.detection.config import DetectionSettings
from agent.detection.models import DetectionSignal, IncidentBundle
from agent.persistence.mappers import DataMapper
from agent.persistence.orm_models import Base, IngestionJob
from agent.persistence.unit_of_work import UnitOfWork

from tests.stateful_correlation.conftest import FIXED, make_event, make_signal


MAX_CTX = DetectionSettings().MAX_CONTEXT_EVENTS_PER_INCIDENT


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


def _incident(
    incident_id: str,
    signal: DetectionSignal,
    events: list,
    *,
    ts: datetime.datetime = FIXED,
    context_event_ids: list[str] | None = None,
) -> IncidentBundle:
    return IncidentBundle(
        incident_id=incident_id,
        incident_type="rdp_probe",
        incident_family="service_probing",
        title="Detected RDP Probe from 203.0.113.10",
        severity="medium",
        confidence=0.6,
        first_seen=ts,
        last_seen=max(e.timestamp for e in events),
        primary_entity="203.0.113.10",
        target_entities=["10.0.0.5"],
        signal_ids=[signal.signal_id],
        event_ids=[e.event_id for e in events],
        context_event_ids=context_event_ids or [],
        evidence=signal.evidence,
        metrics={"primary_signal_id": signal.signal_id},
        mitre_techniques=signal.mitre_techniques,
        merge_key="m1",
    )


def _submit(uow, service, settings, *, job_id, event, signal, context_event_ids, ts, now):
    job = IngestionJob(id=job_id, status="completed")
    uow.ingestion_jobs.add(job)
    uow.canonical_events.add(DataMapper.domain_event_to_orm(event))
    orm_signal = DataMapper.domain_signal_to_orm(signal)
    uow.detection_signals.add(orm_signal)
    job.signals.append(orm_signal)
    uow.session.flush()
    incident = _incident(
        "INC-A", signal, [event], ts=ts, context_event_ids=context_event_ids
    )
    return service.resolve_and_merge(
        uow,
        incoming_bundle=incident,
        incoming_events=[event],
        incoming_signal_rows=[orm_signal],
        job=job,
        settings=settings,
        now=now,
    )


# --- 1: sequential jobs contribute more than MAX_CONTEXT_EVENTS_PER_INCIDENT
# distinct context IDs -------------------------------------------------------


def test_sequential_jobs_keep_persisted_context_bounded_and_hydration_matches(
    session_factory,
) -> None:
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    canonical_id = None
    for i in range(MAX_CTX + 10):
        ts = FIXED + datetime.timedelta(minutes=i)
        event = make_event(f"e{i}", ts=ts)
        signal = make_signal(f"SIG-{i}", [f"e{i}"], ts=ts)
        with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
            result = _submit(
                uow, service, settings,
                job_id=f"job-{i}", event=event, signal=signal,
                context_event_ids=[f"ctx-{i:05d}"], ts=ts, now=ts,
            )
        canonical_id = result.canonical_incident_id

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        incident_row = uow.incidents.get(canonical_id)
        context_rows = [e.event_id for e in incident_row.events if e.is_context]
        assert len(context_rows) <= MAX_CTX

        hydrated = DataMapper.orm_to_domain_incident(incident_row)
        # The deterministic merged bound keeps the sorted-first MAX_CTX
        # context IDs contributed across every job.
        expected = sorted(f"ctx-{i:05d}" for i in range(MAX_CTX + 10))[:MAX_CTX]
        assert sorted(hydrated.context_event_ids) == expected
        assert sorted(context_rows) == expected


# --- 2: a new context ID sorts into the bounded set, displacing an old one --


def test_new_context_id_displaces_old_one_and_bumps_version(session_factory) -> None:
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    event_a = make_event("a1")
    signal_a = make_signal("SIG-A", ["a1"])
    initial_context = [f"ctx-{i:05d}" for i in range(MAX_CTX)]
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        result_a = _submit(
            uow, service, settings,
            job_id="job-a", event=event_a, signal=signal_a,
            context_event_ids=initial_context, ts=FIXED, now=FIXED,
        )
    canonical_id = result_a.canonical_incident_id

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        version_before = int(uow.incidents.get(canonical_id).version)

    # A context ID that sorts first ("0000-...") displaces the alphabetically
    # last currently-persisted context row.
    later = FIXED + datetime.timedelta(minutes=5)
    event_b = make_event("b1", ts=later)
    signal_b = make_signal("SIG-B", ["b1"], ts=later)
    new_context_id = "0000-new-context"
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        result_b = _submit(
            uow, service, settings,
            job_id="job-b", event=event_b, signal=signal_b,
            context_event_ids=[new_context_id], ts=later, now=later,
        )

    assert result_b.status == "merged"
    assert "context_changed" in result_b.material_changes

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        incident_row = uow.incidents.get(canonical_id)
        context_rows = sorted(e.event_id for e in incident_row.events if e.is_context)
        assert new_context_id in context_rows
        assert len(context_rows) <= MAX_CTX
        displaced_id = sorted(initial_context)[-1]
        assert displaced_id not in context_rows
        assert int(incident_row.version) == version_before + 1


# --- 3: a context-only addition below the cap -------------------------------


def test_context_only_addition_below_cap_persists_and_bumps_version_once(
    session_factory,
) -> None:
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    event_a = make_event("a1")
    signal_a = make_signal("SIG-A", ["a1"])
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        result_a = _submit(
            uow, service, settings,
            job_id="job-a", event=event_a, signal=signal_a,
            context_event_ids=[], ts=FIXED, now=FIXED,
        )
    canonical_id = result_a.canonical_incident_id

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        version_before = int(uow.incidents.get(canonical_id).version)

    later = FIXED + datetime.timedelta(minutes=5)
    event_b = make_event("b1", ts=later)
    signal_b = make_signal("SIG-B", ["b1"], ts=later)
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        result_b = _submit(
            uow, service, settings,
            job_id="job-b", event=event_b, signal=signal_b,
            context_event_ids=["ctx-only-1"], ts=later, now=later,
        )

    assert result_b.status == "merged"
    assert "context_changed" in result_b.material_changes

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        incident_row = uow.incidents.get(canonical_id)
        context_rows = [e.event_id for e in incident_row.events if e.is_context]
        assert context_rows == ["ctx-only-1"]
        assert int(incident_row.version) == version_before + 1


# --- 4: an incoming context ID discarded by the bound, same job, no other
# changes -> true no-op ------------------------------------------------------


def test_context_id_discarded_by_bound_same_job_no_other_change_is_true_noop(
    session_factory,
) -> None:
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    event_a = make_event("a1")
    signal_a = make_signal("SIG-A", ["a1"])
    # All existing context IDs sort before the discarded candidate below.
    initial_context = [f"ctx-{i:05d}" for i in range(MAX_CTX)]
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        result_a = _submit(
            uow, service, settings,
            job_id="job-a", event=event_a, signal=signal_a,
            context_event_ids=initial_context, ts=FIXED, now=FIXED,
        )
    canonical_id = result_a.canonical_incident_id
    key = result_a.correlation_key

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        version_before = int(uow.incidents.get(canonical_id).version)
        state_before = uow.correlation_state.get_by_key(key)
        before = (int(state_before.generation), int(state_before.version), state_before.last_seen)
        metrics_before = dict(uow.incidents.get(canonical_id).metrics)
        merge_count_before = metrics_before["stateful_merge_count"]

    # Same job, same already-represented event/signal, but proposes a new
    # context ID that sorts last and is discarded entirely by the bound.
    later = FIXED + datetime.timedelta(minutes=5)
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        job_a = uow.ingestion_jobs.get("job-a")
        orm_signal_a = uow.detection_signals.get("SIG-A")
        incident = _incident(
            "INC-A", signal_a, [event_a], ts=FIXED, context_event_ids=["zzz-discarded"]
        )
        result_b = service.resolve_and_merge(
            uow,
            incoming_bundle=incident,
            incoming_events=[event_a],
            incoming_signal_rows=[orm_signal_a],
            job=job_a,
            settings=settings,
            now=later,
        )

    assert result_b.status == "no_op"
    assert result_b.material_changes == ()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        version_after = int(uow.incidents.get(canonical_id).version)
        state_after = uow.correlation_state.get_by_key(key)
        after = (int(state_after.generation), int(state_after.version), state_after.last_seen)
        metrics_after = dict(uow.incidents.get(canonical_id).metrics)
        context_rows = [e.event_id for e in uow.incidents.get(canonical_id).events if e.is_context]

    assert "zzz-discarded" not in context_rows
    assert version_after == version_before
    assert after == before
    assert metrics_after["stateful_merge_count"] == merge_count_before


# --- 5: a persisted context ID promoted to a real incident event -----------


def test_context_id_promoted_to_real_event_is_not_duplicated(session_factory) -> None:
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    event_a = make_event("a1")
    signal_a = make_signal("SIG-A", ["a1"])
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        result_a = _submit(
            uow, service, settings,
            job_id="job-a", event=event_a, signal=signal_a,
            context_event_ids=["ctx-to-promote"], ts=FIXED, now=FIXED,
        )
    canonical_id = result_a.canonical_incident_id

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        incident_row = uow.incidents.get(canonical_id)
        context_rows = [e.event_id for e in incident_row.events if e.is_context]
        assert "ctx-to-promote" in context_rows
        version_before = int(incident_row.version)

    # A later job reports "ctx-to-promote" as one of its OWN real incident
    # events (not context) - the same underlying event now has direct
    # detection evidence.
    later = FIXED + datetime.timedelta(minutes=5)
    promoted_event = make_event("ctx-to-promote", ts=later)
    promoting_signal = make_signal("SIG-B", ["ctx-to-promote"], ts=later)
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        result_b = _submit(
            uow, service, settings,
            job_id="job-b", event=promoted_event, signal=promoting_signal,
            context_event_ids=[], ts=later, now=later,
        )

    assert result_b.status == "merged"

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        incident_row = uow.incidents.get(canonical_id)
        all_rows_for_id = [
            e for e in incident_row.events if e.event_id == "ctx-to-promote"
        ]
        assert len(all_rows_for_id) == 1, "promoted row must not be duplicated"
        assert all_rows_for_id[0].is_context is False

        hydrated = DataMapper.orm_to_domain_incident(incident_row)
        assert "ctx-to-promote" not in hydrated.context_event_ids
        assert "ctx-to-promote" in hydrated.event_ids

        assert int(incident_row.version) == version_before + 1
