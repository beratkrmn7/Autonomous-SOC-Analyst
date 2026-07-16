from __future__ import annotations

from collections import Counter
from datetime import timedelta
from pathlib import Path

from sqlalchemy import func, select

from agent.application.retention import RetentionPlanner, RetentionPolicy
from agent.archive.io import ArchiveReader, ArchiveVerifier
from agent.archive.schemas import canonical_json_bytes
from agent.persistence.orm_models import (
    AuditEvent,
    CanonicalEvent,
    DetectionSignal,
    EvidenceItem,
    Incident,
    IncidentEvent,
    IncidentSignal,
    IngestionJob,
    Report,
    RetentionArchiveRun,
    RetentionHold,
    TriageRun,
    ingestion_job_events,
    ingestion_job_incidents,
    ingestion_job_signals,
)
from agent.persistence.retention_repository import RetentionRepository
from tests.archive.conftest import ARCHIVE_ID, NOW, SECRETS, seed_archive_graph


def _target_counts(environment) -> dict[str, int]:
    tables = (
        CanonicalEvent.__table__,
        DetectionSignal.__table__,
        IngestionJob.__table__,
        Incident.__table__,
        EvidenceItem.__table__,
        TriageRun.__table__,
        Report.__table__,
        RetentionHold.__table__,
        IncidentEvent.__table__,
        IncidentSignal.__table__,
        ingestion_job_events,
        ingestion_job_signals,
        ingestion_job_incidents,
    )
    with environment.session_factory() as session:
        return {
            table.name: session.execute(
                select(func.count()).select_from(table)
            ).scalar_one()
            for table in tables
        }


def test_archive_matches_plan_and_preserves_database_records(archive_env) -> None:
    seed_archive_graph(archive_env)
    marker = Path(archive_env.settings.staging_dir) / "must-remain.upload"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_bytes(b"staging-data-must-remain")
    before = _target_counts(archive_env)
    with archive_env.session_factory() as session:
        plan = RetentionPlanner(
            RetentionRepository(session),
            RetentionPolicy.from_settings(archive_env.settings),
            clock=lambda: NOW,
        ).plan()
    result = archive_env.service().create()

    assert result.status == "verified"
    assert result.verified is True
    assert result.candidate_record_count == plan.total_candidate_count == 5
    assert result.dependency_record_count == 16
    assert result.total_record_count == 21
    assert before == _target_counts(archive_env)
    assert marker.read_bytes() == b"staging-data-must-remain"
    assert archive_env.store.exists(ARCHIVE_ID)

    with archive_env.session_factory() as session:
        run = session.get(RetentionArchiveRun, ARCHIVE_ID)
        assert run is not None
        assert run.status == "verified"
        assert run.storage_key == ARCHIVE_ID
        assert run.manifest_sha256 == result.manifest_sha256
        assert run.sanitized_error_code is None
        event_types = {
            row.event_type
            for row in session.scalars(
                select(AuditEvent).where(
                    AuditEvent.entity_type == "retention_archive",
                    AuditEvent.entity_id == ARCHIVE_ID,
                )
            )
        }
        assert event_types == {
            "retention_archive_started",
            "retention_archive_completed",
            "retention_archive_verified",
        }


def test_candidate_and_dependency_records_are_typed_unique_and_complete(
    archive_env,
) -> None:
    seed_archive_graph(archive_env)
    archive_env.service().create()
    verification = ArchiveVerifier(archive_env.store).verify(ARCHIVE_ID)
    records = list(ArchiveReader(archive_env.store).iter_records(ARCHIVE_ID))

    assert verification.manifest.total_record_count == len(records) == 21
    assert len({(record.entity_type, record.entity_id) for record in records}) == 21
    role_counts = Counter(record.archive_role for record in records)
    assert role_counts == {"retention_candidate": 5, "dependency": 16}
    candidate_types = {
        record.entity_type
        for record in records
        if record.archive_role == "retention_candidate"
    }
    assert candidate_types == {
        "canonical_event",
        "detection_signal",
        "ingestion_job",
        "incident",
        "audit_event",
    }
    dependency_types = Counter(
        record.entity_type
        for record in records
        if record.archive_role == "dependency"
    )
    assert dependency_types == {
        "canonical_event": 1,
        "detection_signal": 1,
        "incident": 1,
        "triage_run": 1,
        "evidence_item": 1,
        "report": 1,
        "incident_event_association": 2,
        "incident_signal_association": 2,
        "job_event_association": 2,
        "job_signal_association": 2,
        "job_incident_association": 2,
    }


def test_archive_allowlist_excludes_secrets_raw_fields_and_paths(archive_env) -> None:
    seed_archive_graph(archive_env)
    archive_env.service().create()
    verification = ArchiveVerifier(archive_env.store).verify(ARCHIVE_ID)
    reader = ArchiveReader(archive_env.store)
    rendered = b"\n".join(
        canonical_json_bytes(record)
        for record in reader.iter_records(ARCHIVE_ID)
    )
    manifest_bytes = canonical_json_bytes(verification.manifest)

    for secret in SECRETS:
        encoded = secret.encode("utf-8")
        assert encoded not in rendered
        assert encoded not in manifest_bytes
    assert b"safe_message_excerpt" not in rendered
    assert b"original_filename" not in rendered
    assert b"original_fields" not in rendered
    assert b'"content"' not in rendered
    assert b'"quote"' not in rendered
    assert b'"messages"' not in rendered
    assert b'"details"' not in rendered
    assert b"retention-archives" not in manifest_bytes
    assert b"staging-private" not in manifest_bytes

    with archive_env.session_factory() as session:
        run = session.get(RetentionArchiveRun, ARCHIVE_ID)
        assert run is not None
        run_text = " ".join(
            str(value)
            for value in (
                run.storage_key,
                run.manifest_sha256,
                run.sanitized_error_code,
            )
        )
        audit_text = " ".join(
            str(event.details)
            for event in session.scalars(
                select(AuditEvent).where(
                    AuditEvent.entity_type == "retention_archive"
                )
            )
        )
    for secret in SECRETS:
        assert secret not in run_text
        assert secret not in audit_text


def test_active_and_held_records_are_not_exported_as_candidates(archive_env) -> None:
    seed_archive_graph(archive_env)
    archive_env.service().create()
    records = list(ArchiveReader(archive_env.store).iter_records(ARCHIVE_ID))
    candidate_ids = {
        record.entity_id
        for record in records
        if record.archive_role == "retention_candidate"
    }
    assert "incident-needs-review" not in candidate_ids
    assert "event-held" not in candidate_ids
    assert "job-queued-protected" not in candidate_ids
    assert "job-processing-protected" not in candidate_ids
    assert "job-cancel-requested-protected" not in candidate_ids


def test_expired_hold_uses_same_as_of_and_allows_archive_candidate(
    archive_env,
) -> None:
    event = CanonicalEvent(
        event_id="event-expired-hold",
        timestamp=NOW - timedelta(days=60),
    )
    hold = RetentionHold(
        hold_id="hold-expired",
        entity_type="canonical_event",
        entity_id=event.event_id,
        reason="Expired approved hold",
        created_at=NOW - timedelta(days=70),
        expires_at=NOW - timedelta(days=1),
    )
    with archive_env.session_factory() as session:
        session.add_all([event, hold])
        session.commit()

    result = archive_env.service().create()
    candidates = {
        record.entity_id
        for record in ArchiveReader(archive_env.store).iter_records(ARCHIVE_ID)
        if record.archive_role == "retention_candidate"
    }

    assert result.candidate_record_count == 1
    assert candidates == {"event-expired-hold"}
