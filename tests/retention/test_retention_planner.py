from __future__ import annotations

from datetime import timedelta

from agent.application.retention import RetentionPlanner, RetentionPolicy
from agent.persistence.orm_models import (
    AuditEvent,
    CanonicalEvent,
    DetectionSignal,
    Incident,
    IncidentEvent,
    IncidentSignal,
    IngestionJob,
    RetentionHold,
)
from agent.persistence.retention_repository import RetentionRepository
from tests.retention.conftest import NOW, RetentionEnvironment


def _plan(environment: RetentionEnvironment):
    with environment.session_factory() as session:
        return RetentionPlanner(
            RetentionRepository(session),
            RetentionPolicy.from_settings(environment.settings),
            clock=lambda: NOW,
        ).plan()


def _summary(plan, entity_type):
    return next(
        summary
        for summary in plan.candidates
        if summary.entity_type == entity_type
    )


def test_old_and_new_event_and_signal_eligibility_and_ranges(retention_env) -> None:
    event_oldest = NOW - timedelta(days=50)
    event_newest = NOW - timedelta(days=40)
    signal_oldest = NOW - timedelta(days=120)
    signal_newest = NOW - timedelta(days=100)
    with retention_env.session_factory() as session:
        session.add_all(
            [
                CanonicalEvent(event_id="event-oldest", timestamp=event_oldest),
                CanonicalEvent(event_id="event-newest", timestamp=event_newest),
                CanonicalEvent(
                    event_id="event-new",
                    timestamp=NOW - timedelta(days=10),
                ),
                DetectionSignal(
                    signal_id="signal-oldest",
                    created_at=signal_oldest,
                ),
                DetectionSignal(
                    signal_id="signal-newest",
                    created_at=signal_newest,
                ),
                DetectionSignal(
                    signal_id="signal-new",
                    created_at=NOW - timedelta(days=10),
                ),
            ]
        )
        session.commit()

    plan = _plan(retention_env)
    events = _summary(plan, "canonical_event")
    signals = _summary(plan, "detection_signal")
    assert events.candidate_count == 2
    assert events.oldest_candidate_at == event_oldest.replace(tzinfo=None)
    assert events.newest_candidate_at == event_newest.replace(tzinfo=None)
    assert signals.candidate_count == 2
    assert signals.oldest_candidate_at == signal_oldest.replace(tzinfo=None)
    assert signals.newest_candidate_at == signal_newest.replace(tzinfo=None)


def test_active_incident_and_job_relationships_protect_events_and_signals(
    retention_env,
) -> None:
    old_event_time = NOW - timedelta(days=60)
    old_signal_time = NOW - timedelta(days=120)
    with retention_env.session_factory() as session:
        investigating = Incident(
            incident_id="incident-investigating",
            status="investigating",
            updated_at=NOW,
        )
        needs_review = Incident(
            incident_id="incident-needs-review",
            status="needs_review",
            updated_at=NOW,
        )
        event_active = CanonicalEvent(
            event_id="event-active",
            timestamp=old_event_time,
        )
        event_review = CanonicalEvent(
            event_id="event-review",
            timestamp=old_event_time,
        )
        event_job = CanonicalEvent(
            event_id="event-job",
            timestamp=old_event_time,
        )
        event_free = CanonicalEvent(
            event_id="event-free",
            timestamp=old_event_time,
        )
        signal_active = DetectionSignal(
            signal_id="signal-active",
            created_at=old_signal_time,
        )
        signal_free = DetectionSignal(
            signal_id="signal-free",
            created_at=old_signal_time,
        )
        investigating.events.append(IncidentEvent(event_id="event-active"))
        needs_review.events.extend(
            [
                IncidentEvent(event_id="event-active"),
                IncidentEvent(event_id="event-review"),
            ]
        )
        investigating.signals.append(IncidentSignal(signal_id="signal-active"))
        processing_job = IngestionJob(id="job-processing", status="processing")
        processing_job.events.append(event_job)
        session.add_all(
            [
                investigating,
                needs_review,
                event_active,
                event_review,
                event_job,
                event_free,
                signal_active,
                signal_free,
                processing_job,
            ]
        )
        session.commit()

    plan = _plan(retention_env)
    events = _summary(plan, "canonical_event")
    signals = _summary(plan, "detection_signal")
    assert events.candidate_count == 1
    assert events.protected_by_active_relationship_count == 3
    assert signals.candidate_count == 1
    assert signals.protected_by_active_relationship_count == 1


def test_only_completed_jobs_and_explicitly_terminal_incidents_are_eligible(
    retention_env,
) -> None:
    old_job_time = NOW - timedelta(days=120)
    old_incident_time = NOW - timedelta(days=500)
    with retention_env.session_factory() as session:
        jobs = [
            IngestionJob(
                id=f"job-{status}",
                status=status,
                completed_at=old_job_time,
            )
            for status in (
                "queued",
                "processing",
                "cancel_requested",
                "failed",
                "cancelled",
            )
        ]
        completed = IngestionJob(
            id="job-completed",
            status="completed",
            completed_at=old_job_time,
        )
        completed_linked = IngestionJob(
            id="job-completed-linked",
            status="completed",
            completed_at=old_job_time,
        )
        active_incident = Incident(
            incident_id="incident-linked-active",
            status="new",
            updated_at=NOW,
        )
        completed_linked.incidents.append(active_incident)
        incidents = [
            Incident(
                incident_id=f"incident-{status}",
                status=status,
                updated_at=old_incident_time,
            )
            for status in (
                "resolved",
                "closed",
                "new",
                "triaged",
                "assigned",
                "investigating",
                "confirmed",
                "needs_review",
                "false_positive",
                "reopened",
            )
        ]
        session.add_all(jobs + [completed, completed_linked, active_incident] + incidents)
        session.commit()

    plan = _plan(retention_env)
    jobs_summary = _summary(plan, "ingestion_job")
    incidents_summary = _summary(plan, "incident")
    assert jobs_summary.candidate_count == 1
    assert jobs_summary.protected_by_active_relationship_count == 6
    assert incidents_summary.candidate_count == 2
    assert incidents_summary.protected_by_active_relationship_count == 8


def test_indefinite_active_expired_and_released_legal_holds(retention_env) -> None:
    old = NOW - timedelta(days=60)
    created = NOW - timedelta(days=70)
    events = [
        CanonicalEvent(event_id=f"event-{kind}", timestamp=old)
        for kind in ("indefinite", "active", "expired", "released")
    ]
    holds = [
        RetentionHold(
            hold_id="hold-indefinite",
            entity_type="canonical_event",
            entity_id="event-indefinite",
            reason="Approved investigation hold",
            created_at=created,
        ),
        RetentionHold(
            hold_id="hold-active",
            entity_type="canonical_event",
            entity_id="event-active",
            reason="Approved time-bound hold",
            created_at=created,
            expires_at=NOW + timedelta(days=1),
        ),
        RetentionHold(
            hold_id="hold-expired",
            entity_type="canonical_event",
            entity_id="event-expired",
            reason="Expired investigation hold",
            created_at=created,
            expires_at=NOW - timedelta(days=1),
        ),
        RetentionHold(
            hold_id="hold-released",
            entity_type="canonical_event",
            entity_id="event-released",
            reason="Released investigation hold",
            created_at=created,
            released_at=NOW - timedelta(days=1),
        ),
    ]
    with retention_env.session_factory() as session:
        session.add_all(events + holds)
        session.commit()

    summary = _summary(_plan(retention_env), "canonical_event")
    assert summary.candidate_count == 2
    assert summary.protected_by_legal_hold_count == 2


def test_active_holds_apply_to_every_retention_entity_type(retention_env) -> None:
    created = NOW - timedelta(days=600)
    with retention_env.session_factory() as session:
        session.add_all(
            [
                CanonicalEvent(
                    event_id="held-event",
                    timestamp=NOW - timedelta(days=60),
                ),
                DetectionSignal(
                    signal_id="held-signal",
                    created_at=NOW - timedelta(days=120),
                ),
                IngestionJob(
                    id="held-job",
                    status="completed",
                    completed_at=NOW - timedelta(days=120),
                ),
                Incident(
                    incident_id="held-incident",
                    status="closed",
                    updated_at=NOW - timedelta(days=500),
                ),
                AuditEvent(
                    audit_event_id="held-audit",
                    timestamp=NOW - timedelta(days=500),
                ),
            ]
        )
        for entity_type, entity_id in (
            ("canonical_event", "held-event"),
            ("detection_signal", "held-signal"),
            ("ingestion_job", "held-job"),
            ("incident", "held-incident"),
            ("audit_event", "held-audit"),
        ):
            session.add(
                RetentionHold(
                    hold_id=f"hold-{entity_type}",
                    entity_type=entity_type,
                    entity_id=entity_id,
                    reason="Approved cross-entity hold test",
                    created_at=created,
                )
            )
        session.commit()

    plan = _plan(retention_env)
    assert all(summary.candidate_count == 0 for summary in plan.candidates)
    assert all(
        summary.protected_by_legal_hold_count == 1
        for summary in plan.candidates
    )
