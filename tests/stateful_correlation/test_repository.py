"""Phase 6E.4A focused tests: repository/facade behavior - eligibility,
generation transitions, idempotency, job/signal associations, retention
cascade, and the disabled-by-default feature flag (required tests 11-15,
20-22, 26-28)."""

from __future__ import annotations

import datetime
import os
import tempfile

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agent.application.stateful_correlation_service import StatefulIncidentCorrelationService
from agent.config import Settings
from agent.detection.models import DetectionEvidence, DetectionSignal, IncidentBundle
from agent.persistence.cleanup_repository import RetentionCleanupRepository
from agent.persistence.mappers import DataMapper
from agent.persistence.orm_models import Base, IncidentCorrelationState, IngestionJob
from agent.persistence.unit_of_work import UnitOfWork
from agent.schema import CanonicalLogEvent


FIXED = datetime.datetime(2026, 7, 10, 6, 0, 0, tzinfo=datetime.timezone.utc)


@pytest.fixture
def session_factory():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    yield SessionLocal
    engine.dispose()
    os.remove(path)


def _event(event_id: str, **overrides) -> CanonicalLogEvent:
    values = dict(
        event_id=event_id,
        timestamp=FIXED,
        src_ip="203.0.113.10",
        dst_ip="10.0.0.5",
        dst_port=3389,
        protocol="TCP",
        action="block",
        parser_name="pf_firewall",
        parse_status="parsed",
        source_name="firewall.json",
        safe_message_excerpt="BLOCK TCP 203.0.113.10 -> 10.0.0.5:3389",
    )
    values.update(overrides)
    return CanonicalLogEvent(**values)


def _signal(signal_id: str, event_ids: list[str], ts: datetime.datetime = FIXED) -> DetectionSignal:
    return DetectionSignal(
        signal_id=signal_id,
        rule_id="remote_service_probe",
        rule_version="1",
        rule_name="RDP Probe",
        signal_type="rdp_probe",
        signal_family="service_probing",
        severity="medium",
        confidence=0.6,
        first_seen=ts,
        last_seen=ts,
        event_ids=event_ids,
        primary_entity="203.0.113.10",
        target_entities=["10.0.0.5"],
        metrics={},
        evidence=[
            DetectionEvidence(
                event_id=event_ids[0], quote="q", reason="r", source="pf_firewall",
                original_fields={}, correlation_context={},
            )
        ],
        mitre_techniques=["T1021.001"],
        tags=[],
    )


def _incident(
    incident_id: str, signal: DetectionSignal, events: list[CanonicalLogEvent],
    ts: datetime.datetime = FIXED,
) -> IncidentBundle:
    return IncidentBundle(
        incident_id=incident_id,
        incident_type="rdp_probe",
        incident_family="service_probing",
        title="Detected RDP Probe from 203.0.113.10",
        severity="medium",
        confidence=0.6,
        first_seen=ts,
        last_seen=ts,
        primary_entity="203.0.113.10",
        target_entities=["10.0.0.5"],
        signal_ids=[signal.signal_id],
        event_ids=[e.event_id for e in events],
        context_event_ids=[],
        evidence=signal.evidence,
        metrics={"primary_signal_id": signal.signal_id},
        mitre_techniques=signal.mitre_techniques,
        merge_key="m1",
    )


def _submit_job(uow: UnitOfWork, service, job_id, events, signal, incident_bundle, settings, now=None):
    job = IngestionJob(id=job_id, status="completed")
    uow.ingestion_jobs.add(job)
    for event in events:
        uow.canonical_events.add(DataMapper.domain_event_to_orm(event))
    orm_signal = DataMapper.domain_signal_to_orm(signal)
    uow.detection_signals.add(orm_signal)
    job.signals.append(orm_signal)
    uow.session.flush()
    return service.resolve_and_merge(
        uow,
        incoming_bundle=incident_bundle,
        incoming_events=events,
        incoming_signal_rows=[orm_signal],
        job=job,
        settings=settings,
        now=now,
    ), job


# --- 11: active state inside the correlation window reuses the canonical
# incident ID


def test_active_state_within_window_reuses_canonical_incident_id(session_factory) -> None:
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events_a = [_event("a1")]
        sig_a = _signal("SIG-A", ["a1"])
        inc_a = _incident("INC-A", sig_a, events_a)
        result_a, _ = _submit_job(uow, service, "job-a", events_a, sig_a, inc_a, settings, now=FIXED)
        canon_id = result_a.canonical_incident_id

    later = FIXED + datetime.timedelta(minutes=30)
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events_b = [_event("b1", timestamp=later)]
        sig_b = _signal("SIG-B", ["b1"], ts=later)
        inc_b = _incident("INC-B", sig_b, events_b, ts=later)
        result_b, _ = _submit_job(uow, service, "job-b", events_b, sig_b, inc_b, settings, now=later)

    assert result_b.status == "merged"
    assert result_b.canonical_incident_id == canon_id


# --- 12: expired state starts a new generation and new canonical incident


def test_expired_state_starts_new_generation_and_new_canonical_incident(session_factory) -> None:
    settings = Settings(
        stateful_correlation_enabled=True,
        stateful_correlation_state_ttl_seconds=3600,
        stateful_correlation_window_seconds=3600,
    )
    service = StatefulIncidentCorrelationService()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events_a = [_event("a1")]
        sig_a = _signal("SIG-A", ["a1"])
        inc_a = _incident("INC-A", sig_a, events_a)
        result_a, _ = _submit_job(uow, service, "job-a", events_a, sig_a, inc_a, settings, now=FIXED)
        canon_id = result_a.canonical_incident_id
        assert result_a.generation == 1

    much_later_now = FIXED + datetime.timedelta(hours=3)
    much_later_event = FIXED + datetime.timedelta(hours=3)
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events_b = [_event("b1", timestamp=much_later_event)]
        sig_b = _signal("SIG-B", ["b1"], ts=much_later_event)
        inc_b = _incident("INC-B", sig_b, events_b, ts=much_later_event)
        result_b, _ = _submit_job(
            uow, service, "job-b", events_b, sig_b, inc_b, settings, now=much_later_now
        )

    assert result_b.status == "new_generation"
    assert result_b.generation == 2
    assert result_b.canonical_incident_id != canon_id


# --- 13: TTL alone does not make incidents correlation-compatible


def test_ttl_alone_does_not_grant_correlation_compatibility(session_factory) -> None:
    settings = Settings(
        stateful_correlation_enabled=True,
        stateful_correlation_state_ttl_seconds=86400,  # generous TTL, state stays "alive"
        stateful_correlation_window_seconds=600,  # narrow campaign-continuity window
    )
    service = StatefulIncidentCorrelationService()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events_a = [_event("a1")]
        sig_a = _signal("SIG-A", ["a1"])
        inc_a = _incident("INC-A", sig_a, events_a)
        result_a, _ = _submit_job(uow, service, "job-a", events_a, sig_a, inc_a, settings, now=FIXED)
        canon_id = result_a.canonical_incident_id

    # Well within the generous TTL, but the incoming activity's own event
    # window is far outside the narrow correlation window.
    far_event_time = FIXED + datetime.timedelta(hours=2)
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events_b = [_event("b1", timestamp=far_event_time)]
        sig_b = _signal("SIG-B", ["b1"], ts=far_event_time)
        inc_b = _incident("INC-B", sig_b, events_b, ts=far_event_time)
        result_b, _ = _submit_job(
            uow, service, "job-b", events_b, sig_b, inc_b, settings, now=far_event_time
        )

    assert result_b.status == "new_generation"
    assert result_b.canonical_incident_id != canon_id


# --- 14: event timestamps, not ingestion timestamps, control eligibility


def test_event_timestamps_not_ingestion_timestamps_control_eligibility(session_factory) -> None:
    settings = Settings(
        stateful_correlation_enabled=True,
        stateful_correlation_window_seconds=600,
        stateful_correlation_state_ttl_seconds=86400,
    )
    service = StatefulIncidentCorrelationService()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events_a = [_event("a1")]
        sig_a = _signal("SIG-A", ["a1"])
        inc_a = _incident("INC-A", sig_a, events_a)
        result_a, _ = _submit_job(uow, service, "job-a", events_a, sig_a, inc_a, settings, now=FIXED)
        canon_id = result_a.canonical_incident_id

    # Ingested (now) much later than job A, but the batch itself describes
    # activity whose event timestamp is still close to job A's window.
    ingestion_time = FIXED + datetime.timedelta(hours=5)
    close_event_time = FIXED + datetime.timedelta(minutes=5)
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events_b = [_event("b1", timestamp=close_event_time)]
        sig_b = _signal("SIG-B", ["b1"], ts=close_event_time)
        inc_b = _incident("INC-B", sig_b, events_b, ts=close_event_time)
        result_b, _ = _submit_job(
            uow, service, "job-b", events_b, sig_b, inc_b, settings, now=ingestion_time
        )

    assert result_b.status == "merged"
    assert result_b.canonical_incident_id == canon_id


# --- 15: out-of-order but window-compatible activity may merge


def test_out_of_order_window_compatible_activity_merges(session_factory) -> None:
    settings = Settings(stateful_correlation_enabled=True, stateful_correlation_window_seconds=3600)
    service = StatefulIncidentCorrelationService()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events_a = [_event("a1", timestamp=FIXED + datetime.timedelta(minutes=30))]
        sig_a = _signal("SIG-A", ["a1"], ts=FIXED + datetime.timedelta(minutes=30))
        inc_a = _incident("INC-A", sig_a, events_a, ts=FIXED + datetime.timedelta(minutes=30))
        result_a, _ = _submit_job(uow, service, "job-a", events_a, sig_a, inc_a, settings, now=FIXED)
        canon_id = result_a.canonical_incident_id

    # Job B arrives "late" (in ingestion order) but describes slightly
    # earlier activity, still inside the window around job A's campaign.
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events_b = [_event("b1", timestamp=FIXED)]
        sig_b = _signal("SIG-B", ["b1"], ts=FIXED)
        inc_b = _incident("INC-B", sig_b, events_b, ts=FIXED)
        result_b, _ = _submit_job(uow, service, "job-b", events_b, sig_b, inc_b, settings, now=FIXED)

    assert result_b.status == "merged"
    assert result_b.canonical_incident_id == canon_id


# --- 20 & 21: applying the same incoming incident twice is a no-op that
# does not bump Incident.version or state generation


def test_applying_same_incoming_incident_twice_is_a_noop(session_factory) -> None:
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events_a = [_event("a1")]
        sig_a = _signal("SIG-A", ["a1"])
        inc_a = _incident("INC-A", sig_a, events_a)
        result_a, job_a = _submit_job(uow, service, "job-a", events_a, sig_a, inc_a, settings, now=FIXED)
        canon_id = result_a.canonical_incident_id
        key = result_a.correlation_key

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        version_before = uow.incidents.get(canon_id).version
        generation_before = uow.correlation_state.get_by_key(key).generation

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        job_a = uow.ingestion_jobs.get("job-a")
        sig_a_orm = uow.detection_signals.get("SIG-A")
        events_a = [_event("a1")]
        inc_a = _incident("INC-A", _signal("SIG-A", ["a1"]), events_a)
        result_repeat = service.resolve_and_merge(
            uow,
            incoming_bundle=inc_a,
            incoming_events=events_a,
            incoming_signal_rows=[sig_a_orm],
            job=job_a,
            settings=settings,
            now=FIXED,
        )

    assert result_repeat.status == "no_op"
    assert result_repeat.material_changes == ()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        version_after = uow.incidents.get(canon_id).version
        generation_after = uow.correlation_state.get_by_key(key).generation
        event_rows = [e.event_id for e in uow.incidents.get(canon_id).events]
        signal_rows = [s.signal_id for s in uow.incidents.get(canon_id).signals]

    assert version_after == version_before
    assert generation_after == generation_before
    assert len(event_rows) == len(set(event_rows))
    assert len(signal_rows) == len(set(signal_rows))


# --- 22: job-to-incident associations are added without associating
# historical signals to the new job


def test_job_association_does_not_associate_historical_signals(session_factory) -> None:
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events_a = [_event("a1")]
        sig_a = _signal("SIG-A", ["a1"])
        inc_a = _incident("INC-A", sig_a, events_a)
        _submit_job(uow, service, "job-a", events_a, sig_a, inc_a, settings, now=FIXED)

    later = FIXED + datetime.timedelta(minutes=5)
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events_b = [_event("b1", timestamp=later)]
        sig_b = _signal("SIG-B", ["b1"], ts=later)
        inc_b = _incident("INC-B", sig_b, events_b, ts=later)
        result_b, job_b = _submit_job(
            uow, service, "job-b", events_b, sig_b, inc_b, settings, now=later
        )
        assert result_b.status == "merged"

        job_b_signal_ids = {s.signal_id for s in job_b.signals}
        incident_signal_ids = {s.signal_id for s in result_b.canonical_incident.signals}

    # The canonical incident now carries both signals, but job B itself is
    # only ever associated with the signal it actually produced.
    assert incident_signal_ids == {"SIG-A", "SIG-B"}
    assert job_b_signal_ids == {"SIG-B"}


# --- 26: incident deletion does not leave a dangling correlation-state row


def test_incident_deletion_removes_correlation_state_row(session_factory) -> None:
    settings = Settings(stateful_correlation_enabled=True)
    service = StatefulIncidentCorrelationService()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events_a = [_event("a1")]
        sig_a = _signal("SIG-A", ["a1"])
        inc_a = _incident("INC-A", sig_a, events_a)
        result_a, _ = _submit_job(uow, service, "job-a", events_a, sig_a, inc_a, settings, now=FIXED)
        canon_id = result_a.canonical_incident_id
        key = result_a.correlation_key

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        assert uow.correlation_state.get_by_key(key) is not None
        cleanup = RetentionCleanupRepository(uow.session)
        cleanup._delete_incident_dependencies({canon_id})

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        assert uow.correlation_state.get_by_key(key) is None


# --- 27: feature flag defaults to false


def test_stateful_correlation_disabled_by_default() -> None:
    settings = Settings()
    assert settings.stateful_correlation_enabled is False


# --- 28: disabled foundation causes no production pipeline behavior change


def test_disabled_flag_makes_resolve_and_merge_a_complete_noop(session_factory) -> None:
    settings = Settings(stateful_correlation_enabled=False)
    service = StatefulIncidentCorrelationService()

    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        events_a = [_event("a1")]
        sig_a = _signal("SIG-A", ["a1"])
        inc_a = _incident("INC-A", sig_a, events_a)
        job = IngestionJob(id="job-a", status="completed")
        uow.ingestion_jobs.add(job)
        for event in events_a:
            uow.canonical_events.add(DataMapper.domain_event_to_orm(event))
        orm_signal = DataMapper.domain_signal_to_orm(sig_a)
        uow.detection_signals.add(orm_signal)
        uow.session.flush()

        result = service.resolve_and_merge(
            uow,
            incoming_bundle=inc_a,
            incoming_events=events_a,
            incoming_signal_rows=[orm_signal],
            job=job,
            settings=settings,
            now=FIXED,
        )

        assert result.status == "disabled"
        assert result.canonical_incident is None
        assert uow.session.query(IncidentCorrelationState).count() == 0
        assert uow.incidents.get("INC-A") is None
