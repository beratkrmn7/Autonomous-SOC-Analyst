"""Upgrade regressions for exact cross-job severity facts and state versions."""

from __future__ import annotations

import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agent.application.stateful_correlation_service import (
    StatefulIncidentCorrelationService,
)
from agent.config import Settings
from agent.detection.config import DetectionSettings
from agent.detection.models import DetectionSignal, IncidentBundle
from agent.detection.scoring import (
    calculate_incident_severity,
    derive_incident_severity_facts,
)
from agent.persistence.database import Base
from agent.persistence.mappers import DataMapper
from agent.persistence.orm_models import IncidentCorrelationState, IngestionJob
from agent.persistence.unit_of_work import UnitOfWork
from agent.schema import CanonicalLogEvent

from tests.stateful_correlation.conftest import FIXED, make_event, make_incident, make_signal


@pytest.fixture
def session_factory(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'upgrade-union-severity.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    yield factory
    engine.dispose()


def _settings(*, version: str = "2") -> Settings:
    return Settings(
        _env_file=None,
        stateful_correlation_enabled=True,
        stateful_correlation_version=version,
    )


def _recon_signal(
    signal_id: str,
    events: list[CanonicalLogEvent],
    *,
    ts: datetime.datetime,
) -> DetectionSignal:
    return make_signal(
        signal_id, [event.event_id for event in events], ts=ts
    ).model_copy(
        update={
            "rule_id": "rdp_probe",
            "target_entities": sorted(
                {event.dst_ip for event in events if event.dst_ip}
            ),
        }
    )


def _recon_incident(
    incident_id: str,
    signal: DetectionSignal,
    events: list[CanonicalLogEvent],
    *,
    ts: datetime.datetime,
) -> IncidentBundle:
    facts = derive_incident_severity_facts(events, family="service_probing")
    return make_incident(incident_id, signal, events, ts=ts).model_copy(
        update={
            "severity": calculate_incident_severity(
                [signal], signal.primary_entity, DetectionSettings(), facts=facts
            ),
            "target_entities": signal.target_entities,
            "metrics": {
                "primary_signal_id": signal.signal_id,
                **facts.as_metrics(),
            },
        }
    )


def _exposure_signal(
    signal_id: str,
    event: CanonicalLogEvent,
    *,
    ts: datetime.datetime,
) -> DetectionSignal:
    destination = event.translated_dst_ip or event.dst_ip
    return make_signal(signal_id, [event.event_id], ts=ts).model_copy(
        update={
            "rule_id": "critical_management_service_exposed",
            "rule_version": "1.0.0",
            "rule_name": "Critical Management Service Exposed",
            "signal_type": "critical_management_service_exposed",
            "signal_family": "firewall_exposure",
            "severity": "high",
            "confidence": 0.91,
            "primary_entity": event.src_ip,
            "target_entities": [destination] if destination else [],
            "mitre_techniques": [],
            "metrics": {"service": "redis"},
        }
    )


def _exposure_incident(
    incident_id: str,
    signal: DetectionSignal,
    event: CanonicalLogEvent,
    *,
    ts: datetime.datetime,
) -> IncidentBundle:
    destination = event.translated_dst_ip or event.dst_ip
    facts = derive_incident_severity_facts([event], family="firewall_exposure")
    return make_incident(incident_id, signal, [event], ts=ts).model_copy(
        update={
            "incident_type": signal.signal_type,
            "incident_family": signal.signal_family,
            "title": "Detected Critical Management Service Exposed",
            "severity": calculate_incident_severity(
                [signal], destination or "unknown", DetectionSettings(), facts=facts
            ),
            "confidence": signal.confidence,
            "primary_entity": destination or "unknown",
            "target_entities": [destination] if destination else [],
            "mitre_techniques": [],
            "metrics": {
                "primary_signal_id": signal.signal_id,
                **facts.as_metrics(),
            },
            "merge_key": f"exposure:{destination}:redis",
        }
    )


def _submit(
    session_factory,
    service: StatefulIncidentCorrelationService,
    settings: Settings,
    *,
    job_id: str,
    events: list[CanonicalLogEvent],
    signal: DetectionSignal,
    incident: IncidentBundle,
    now: datetime.datetime,
):
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        job = IngestionJob(id=job_id, status="completed")
        uow.ingestion_jobs.add(job)
        for event in events:
            if uow.canonical_events.get(event.event_id) is None:
                uow.canonical_events.add(DataMapper.domain_event_to_orm(event))
        signal_row = uow.detection_signals.get(signal.signal_id)
        if signal_row is None:
            signal_row = DataMapper.domain_signal_to_orm(signal)
            uow.detection_signals.add(signal_row)
        job.signals.append(signal_row)
        uow.session.flush()
        return service.resolve_and_merge(
            uow,
            incoming_bundle=incident,
            incoming_events=events,
            incoming_signal_rows=[signal_row],
            job=job,
            settings=settings,
            now=now,
        )


def _row(session_factory, settings: Settings, incident_id: str):
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        row = uow.incidents.get(incident_id)
        assert row is not None
        return DataMapper.orm_to_domain_incident(row)


def test_disjoint_cross_job_recon_uses_all_29_destinations(session_factory) -> None:
    settings = _settings()
    service = StatefulIncidentCorrelationService()
    events_a = [
        make_event(f"a-{index}", dst_ip=f"10.0.1.{index}")
        for index in range(1, 12)
    ]
    events_b = [
        make_event(
            f"b-{index}",
            ts=FIXED + datetime.timedelta(minutes=1),
            dst_ip=f"10.0.2.{index}",
        )
        for index in range(1, 19)
    ]
    signal_a = _recon_signal("SIG-A", events_a, ts=FIXED)
    signal_b = _recon_signal(
        "SIG-B", events_b, ts=FIXED + datetime.timedelta(minutes=1)
    )
    created = _submit(
        session_factory,
        service,
        settings,
        job_id="job-a",
        events=events_a,
        signal=signal_a,
        incident=_recon_incident("INC-A", signal_a, events_a, ts=FIXED),
        now=FIXED,
    )
    merged = _submit(
        session_factory,
        service,
        settings,
        job_id="job-b",
        events=events_b,
        signal=signal_b,
        incident=_recon_incident(
            "INC-B",
            signal_b,
            events_b,
            ts=FIXED + datetime.timedelta(minutes=1),
        ),
        now=FIXED + datetime.timedelta(minutes=1),
    )

    assert created.status == "created"
    assert merged.status == "merged"
    incident = _row(session_factory, settings, created.canonical_incident_id)
    assert incident.severity == "medium"
    assert len(incident.event_ids) == 29
    assert len(incident.target_entities) == 29
    assert incident.metrics["severity_total_event_count"] == 29
    assert incident.metrics["blocked_event_count"] == 29
    assert incident.metrics["distinct_destination_count"] == 29
    assert incident.metrics["targeting"] == "broad"


def test_overlapping_cross_job_events_are_counted_once(session_factory) -> None:
    settings = _settings()
    service = StatefulIncidentCorrelationService()
    events = [
        make_event(f"shared-{index}", dst_ip=f"10.1.0.{index}")
        for index in range(1, 11)
    ]
    signal_a = _recon_signal("SIG-A", events, ts=FIXED)
    signal_b = _recon_signal("SIG-B", events, ts=FIXED)
    created = _submit(
        session_factory,
        service,
        settings,
        job_id="job-a",
        events=events,
        signal=signal_a,
        incident=_recon_incident("INC-A", signal_a, events, ts=FIXED),
        now=FIXED,
    )
    merged = _submit(
        session_factory,
        service,
        settings,
        job_id="job-b",
        events=events,
        signal=signal_b,
        incident=_recon_incident("INC-B", signal_b, events, ts=FIXED),
        now=FIXED + datetime.timedelta(minutes=1),
    )

    assert merged.status == "merged"
    incident = _row(session_factory, settings, created.canonical_incident_id)
    assert len(incident.event_ids) == 10
    assert incident.metrics["severity_total_event_count"] == 10
    assert incident.metrics["blocked_event_count"] == 10
    assert incident.metrics["allowed_event_count"] == 0
    assert len(incident.signal_ids) == 2


def test_three_jobs_derive_broad_targeting_from_actual_union(session_factory) -> None:
    settings = _settings()
    service = StatefulIncidentCorrelationService()
    canonical_id = ""
    for index in range(3):
        ts = FIXED + datetime.timedelta(minutes=index)
        events = [make_event(f"event-{index}", ts=ts, dst_ip=f"10.2.0.{index + 1}")]
        signal = _recon_signal(f"SIG-{index}", events, ts=ts)
        result = _submit(
            session_factory,
            service,
            settings,
            job_id=f"job-{index}",
            events=events,
            signal=signal,
            incident=_recon_incident(f"INC-{index}", signal, events, ts=ts),
            now=ts,
        )
        canonical_id = result.canonical_incident_id

    incident = _row(session_factory, settings, canonical_id)
    assert incident.metrics["severity_total_event_count"] == 3
    assert incident.metrics["distinct_destination_count"] == 3
    assert incident.metrics["targeting"] == "broad"


def test_cross_job_translated_critical_exposure_remains_critical(
    session_factory,
) -> None:
    settings = _settings()
    service = StatefulIncidentCorrelationService()
    canonical_id = ""
    for index, source_ip in enumerate(("8.8.8.8", "9.9.9.9")):
        ts = FIXED + datetime.timedelta(minutes=index)
        event = make_event(
            f"exposure-{index}",
            ts=ts,
            src_ip=source_ip,
            dst_ip="198.51.100.25",
            dst_port=6379,
            translated_dst_ip="10.3.0.25",
            translated_dst_port=6379,
            action="pass",
            inbound_zone="wan",
        )
        signal = _exposure_signal(f"SIG-EXP-{index}", event, ts=ts)
        result = _submit(
            session_factory,
            service,
            settings,
            job_id=f"job-exp-{index}",
            events=[event],
            signal=signal,
            incident=_exposure_incident(
                f"INC-EXP-{index}", signal, event, ts=ts
            ),
            now=ts,
        )
        canonical_id = result.canonical_incident_id

    incident = _row(session_factory, settings, canonical_id)
    assert incident.severity == "critical"
    assert incident.primary_entity == "10.3.0.25"
    assert incident.metrics["asset_value"] == "critical"
    assert incident.metrics["allowed_event_count"] == 2
    assert incident.metrics["severity_total_event_count"] == 2
    assert incident.metrics["distinct_destination_count"] == 1


def test_v1_active_state_is_not_reused_by_v2_analysis(session_factory) -> None:
    service = StatefulIncidentCorrelationService()
    event_v1 = make_event("v1-event")
    signal_v1 = _recon_signal("SIG-V1", [event_v1], ts=FIXED)
    result_v1 = _submit(
        session_factory,
        service,
        _settings(version="1"),
        job_id="job-v1",
        events=[event_v1],
        signal=signal_v1,
        incident=_recon_incident("INC-SHARED", signal_v1, [event_v1], ts=FIXED),
        now=FIXED,
    )

    ts_v2 = FIXED + datetime.timedelta(minutes=1)
    event_v2 = make_event("v2-event", ts=ts_v2, dst_ip="10.9.0.2")
    signal_v2 = _recon_signal("SIG-V2", [event_v2], ts=ts_v2)
    result_v2 = _submit(
        session_factory,
        service,
        _settings(version="2"),
        job_id="job-v2",
        events=[event_v2],
        signal=signal_v2,
        incident=_recon_incident(
            "INC-SHARED", signal_v2, [event_v2], ts=ts_v2
        ),
        now=ts_v2,
    )

    assert result_v1.status == "created"
    assert result_v2.status == "created"
    assert result_v2.canonical_incident_id != result_v1.canonical_incident_id

    with UnitOfWork(session_factory=session_factory, settings=_settings()) as uow:
        states = uow.session.query(IncidentCorrelationState).all()
        assert {str(state.correlation_version) for state in states} == {"1", "2"}
        assert len({str(state.incident_id) for state in states}) == 2
