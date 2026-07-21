"""Shared fixtures/builders for Phase 6E.4A stateful-correlation tests."""

from __future__ import annotations

import datetime

from agent.detection.models import DetectionEvidence, DetectionSignal, IncidentBundle
from agent.persistence.mappers import DataMapper
from agent.persistence.orm_models import IngestionJob
from agent.persistence.unit_of_work import UnitOfWork
from agent.schema import CanonicalLogEvent


FIXED = datetime.datetime(2026, 7, 10, 6, 0, 0, tzinfo=datetime.timezone.utc)


def make_event(event_id: str, *, ts: datetime.datetime = FIXED, **overrides) -> CanonicalLogEvent:
    values = dict(
        event_id=event_id,
        timestamp=ts,
        src_ip="203.0.113.10",
        dst_ip="10.0.0.5",
        dst_port=3389,
        protocol="TCP",
        action="block",
        parser_name="pf_firewall",
        parse_status="parsed",
        source_name="firewall.json",
        safe_message_excerpt=f"BLOCK TCP 203.0.113.10 -> 10.0.0.5:3389 {event_id}",
    )
    values.update(overrides)
    return CanonicalLogEvent(**values)


def make_signal(
    signal_id: str, event_ids: list[str], *, ts: datetime.datetime = FIXED
) -> DetectionSignal:
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


def make_incident(
    incident_id: str,
    signal: DetectionSignal,
    events: list[CanonicalLogEvent],
    *,
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
        last_seen=max(e.timestamp for e in events) if events else ts,
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


def submit_job(
    uow: UnitOfWork,
    service,
    settings,
    *,
    job_id: str,
    events: list[CanonicalLogEvent],
    signal: DetectionSignal,
    incident: IncidentBundle,
    now: datetime.datetime | None = None,
):
    """Persist a job's events/signal, then run resolve_and_merge for it."""
    job = IngestionJob(id=job_id, status="completed")
    uow.ingestion_jobs.add(job)
    for event in events:
        uow.canonical_events.add(DataMapper.domain_event_to_orm(event))
    orm_signal = DataMapper.domain_signal_to_orm(signal)
    uow.detection_signals.add(orm_signal)
    job.signals.append(orm_signal)
    uow.session.flush()
    result = service.resolve_and_merge(
        uow,
        incoming_bundle=incident,
        incoming_events=events,
        incoming_signal_rows=[orm_signal],
        job=job,
        settings=settings,
        now=now,
    )
    return result, job
