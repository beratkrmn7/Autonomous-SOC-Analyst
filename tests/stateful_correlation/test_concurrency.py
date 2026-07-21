"""Phase 6E.4A focused test: concurrent first-writers on the same stateful
correlation profile must not create two active states or two canonical
incidents (required test 23).

Uses a file-backed SQLite database (a real DB file, not sqlite memory) and
a threading.Barrier to align both workers at the same point before either
calls resolve_and_merge, rather than relying on sleeps for synchronization.
"""

from __future__ import annotations

import datetime
import os
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agent.application.stateful_correlation_service import StatefulIncidentCorrelationService
from agent.config import Settings
from agent.detection.models import DetectionEvidence, DetectionSignal, IncidentBundle
from agent.persistence.mappers import DataMapper
from agent.persistence.orm_models import Base, IncidentCorrelationState, IngestionJob
from agent.persistence.unit_of_work import UnitOfWork
from agent.schema import CanonicalLogEvent


FIXED = datetime.datetime(2026, 7, 10, 6, 0, 0, tzinfo=datetime.timezone.utc)


def _event(event_id: str) -> CanonicalLogEvent:
    return CanonicalLogEvent(
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


def _signal(signal_id: str, event_id: str) -> DetectionSignal:
    return DetectionSignal(
        signal_id=signal_id,
        rule_id="remote_service_probe",
        rule_version="1",
        rule_name="RDP Probe",
        signal_type="rdp_probe",
        signal_family="service_probing",
        severity="medium",
        confidence=0.6,
        first_seen=FIXED,
        last_seen=FIXED,
        event_ids=[event_id],
        primary_entity="203.0.113.10",
        target_entities=["10.0.0.5"],
        metrics={},
        evidence=[
            DetectionEvidence(
                event_id=event_id, quote="q", reason="r", source="pf_firewall",
                original_fields={}, correlation_context={},
            )
        ],
        mitre_techniques=["T1021.001"],
        tags=[],
    )


def _incident(incident_id: str, signal: DetectionSignal, event_id: str) -> IncidentBundle:
    return IncidentBundle(
        incident_id=incident_id,
        incident_type="rdp_probe",
        incident_family="service_probing",
        title="Detected RDP Probe from 203.0.113.10",
        severity="medium",
        confidence=0.6,
        first_seen=FIXED,
        last_seen=FIXED,
        primary_entity="203.0.113.10",
        target_entities=["10.0.0.5"],
        signal_ids=[signal.signal_id],
        event_ids=[event_id],
        context_event_ids=[],
        evidence=signal.evidence,
        metrics={"primary_signal_id": signal.signal_id},
        mitre_techniques=signal.mitre_techniques,
        merge_key="m1",
    )


def test_concurrent_first_writers_produce_one_state_and_one_canonical_incident() -> None:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        engine = create_engine(
            f"sqlite:///{path}",
            connect_args={"check_same_thread": False, "timeout": 30},
        )
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

        settings = Settings(stateful_correlation_enabled=True)
        service = StatefulIncidentCorrelationService()
        barrier = threading.Barrier(2)
        errors: list[BaseException] = []

        def worker(worker_index: int):
            event_id = f"evt-{worker_index}"
            signal_id = f"SIG-{worker_index}"
            job_id = f"job-{worker_index}"
            event = _event(event_id)
            signal = _signal(signal_id, event_id)
            incident = _incident(f"INC-{worker_index}", signal, event_id)

            try:
                # Synchronize before any write starts: SQLite's single-writer
                # lock means a write-in-progress transaction would otherwise
                # block the other thread from ever reaching the barrier,
                # deadlocking both sides instead of racing them.
                barrier.wait(timeout=10)
                with UnitOfWork(session_factory=SessionLocal, settings=settings) as uow:
                    job = IngestionJob(id=job_id, status="completed")
                    uow.ingestion_jobs.add(job)
                    uow.canonical_events.add(DataMapper.domain_event_to_orm(event))
                    orm_signal = DataMapper.domain_signal_to_orm(signal)
                    uow.detection_signals.add(orm_signal)
                    job.signals.append(orm_signal)
                    uow.session.flush()

                    return service.resolve_and_merge(
                        uow,
                        incoming_bundle=incident,
                        incoming_events=[event],
                        incoming_signal_rows=[orm_signal],
                        job=job,
                        settings=settings,
                        now=FIXED,
                    )
            except BaseException as exc:  # noqa: BLE001 - surfaced via errors list below
                errors.append(exc)
                return None

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(worker, [0, 1]))

        assert not errors, f"worker threads raised: {errors}"
        assert all(result is not None for result in results)
        statuses = sorted(result.status for result in results)
        assert statuses == ["created", "merged"], statuses

        canonical_ids = {result.canonical_incident_id for result in results}
        assert len(canonical_ids) == 1

        with UnitOfWork(session_factory=SessionLocal, settings=settings) as uow:
            state_rows = uow.session.query(IncidentCorrelationState).all()
            assert len(state_rows) == 1
            canonical_id = next(iter(canonical_ids))
            incident_row = uow.incidents.get(canonical_id)
            event_ids = [e.event_id for e in incident_row.events]
            signal_ids = [s.signal_id for s in incident_row.signals]
            assert len(event_ids) == len(set(event_ids))
            assert len(signal_ids) == len(set(signal_ids))
            assert set(event_ids) == {"evt-0", "evt-1"}
            assert set(signal_ids) == {"SIG-0", "SIG-1"}

        engine.dispose()
    finally:
        if os.path.exists(path):
            try:
                os.remove(path)
            except PermissionError:
                pass
