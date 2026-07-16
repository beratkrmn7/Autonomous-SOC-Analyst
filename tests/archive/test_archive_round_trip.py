from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from sqlalchemy import create_engine, func, insert, select, text
from sqlalchemy.orm import sessionmaker

from agent.archive.io import ArchiveReader, ArchiveVerifier
from agent.persistence.orm_models import (
    AuditEvent,
    Base,
    CanonicalEvent,
    DetectionSignal,
    EvidenceItem,
    Incident,
    IncidentEvent,
    IncidentSignal,
    IngestionJob,
    Report,
    TriageRun,
    ingestion_job_events,
    ingestion_job_incidents,
    ingestion_job_signals,
)
from tests.archive.conftest import ARCHIVE_ID, SECRETS, seed_archive_graph


_DATETIME_FIELDS = {
    "canonical_event": {"timestamp", "observed_at"},
    "detection_signal": {"first_seen", "last_seen", "created_at"},
    "ingestion_job": {
        "created_at",
        "updated_at",
        "queued_at",
        "started_at",
        "completed_at",
        "cancel_requested_at",
        "cancelled_at",
    },
    "incident": {"first_seen", "last_seen", "created_at", "updated_at"},
    "audit_event": {"timestamp"},
    "triage_run": {"started_at", "completed_at"},
    "report": {"generated_at"},
}


def _restore_data(entity_type: str, data: dict) -> dict:
    restored = dict(data)
    for field in _DATETIME_FIELDS.get(entity_type, set()):
        value = restored.get(field)
        if isinstance(value, str):
            restored[field] = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return restored


def test_verified_archive_round_trips_into_fresh_database_without_orphans(
    archive_env,
    tmp_path,
) -> None:
    seed_archive_graph(archive_env)
    archive_env.service().create()
    ArchiveVerifier(archive_env.store).verify(ARCHIVE_ID)
    grouped: dict[str, list] = defaultdict(list)
    for record in ArchiveReader(archive_env.store).iter_records(ARCHIVE_ID):
        grouped[record.entity_type].append(record)

    restore_database = tmp_path / "restored.db"
    engine = create_engine(f"sqlite:///{restore_database}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    try:
        with factory() as session:
            session.execute(text("PRAGMA foreign_keys=ON"))
            for record in grouped["canonical_event"]:
                session.add(
                    CanonicalEvent(
                        event_id=record.entity_id,
                        **_restore_data(record.entity_type, record.data),
                    )
                )
            for record in grouped["detection_signal"]:
                session.add(
                    DetectionSignal(
                        signal_id=record.entity_id,
                        **_restore_data(record.entity_type, record.data),
                    )
                )
            for record in grouped["ingestion_job"]:
                session.add(
                    IngestionJob(
                        id=record.entity_id,
                        **_restore_data(record.entity_type, record.data),
                    )
                )
            for record in grouped["incident"]:
                session.add(
                    Incident(
                        incident_id=record.entity_id,
                        **_restore_data(record.entity_type, record.data),
                    )
                )
            session.flush()

            triage_id_map: dict[int, int] = {}
            for record in grouped["triage_run"]:
                data = _restore_data(record.entity_type, record.data)
                source_database_id = int(data.pop("source_database_id"))
                triage = TriageRun(triage_run_id=record.entity_id, **data)
                session.add(triage)
                session.flush()
                triage_id_map[source_database_id] = int(triage.id)

            for record in grouped["evidence_item"]:
                data = _restore_data(record.entity_type, record.data)
                source_triage_id = data.pop("triage_run_id", None)
                data["triage_run_id"] = (
                    triage_id_map[int(source_triage_id)]
                    if source_triage_id is not None
                    else None
                )
                session.add(EvidenceItem(evidence_id=record.entity_id, **data))
            for record in grouped["report"]:
                data = _restore_data(record.entity_type, record.data)
                source_triage_id = data.pop("triage_run_id", None)
                data["triage_run_id"] = (
                    triage_id_map[int(source_triage_id)]
                    if source_triage_id is not None
                    else None
                )
                session.add(Report(report_id=record.entity_id, **data))
            for record in grouped["audit_event"]:
                session.add(
                    AuditEvent(
                        audit_event_id=record.entity_id,
                        **_restore_data(record.entity_type, record.data),
                    )
                )
            session.flush()

            for record in grouped["incident_event_association"]:
                session.add(IncidentEvent(**record.data))
            for record in grouped["incident_signal_association"]:
                session.add(IncidentSignal(**record.data))
            for record in grouped["job_event_association"]:
                session.execute(insert(ingestion_job_events).values(**record.data))
            for record in grouped["job_signal_association"]:
                session.execute(insert(ingestion_job_signals).values(**record.data))
            for record in grouped["job_incident_association"]:
                session.execute(
                    insert(ingestion_job_incidents).values(**record.data)
                )
            session.commit()

        with factory() as session:
            session.execute(text("PRAGMA foreign_keys=ON"))
            expected_counts = {
                CanonicalEvent.__table__: 2,
                DetectionSignal.__table__: 2,
                IngestionJob.__table__: 1,
                Incident.__table__: 2,
                AuditEvent.__table__: 1,
                TriageRun.__table__: 1,
                EvidenceItem.__table__: 1,
                Report.__table__: 1,
                IncidentEvent.__table__: 2,
                IncidentSignal.__table__: 2,
                ingestion_job_events: 2,
                ingestion_job_signals: 2,
                ingestion_job_incidents: 2,
            }
            assert {
                table.name: session.scalar(select(func.count()).select_from(table))
                for table in expected_counts
            } == {table.name: count for table, count in expected_counts.items()}
            assert set(session.scalars(select(CanonicalEvent.event_id))) == {
                "event-old-candidate",
                "event-young-dependency",
            }
            assert set(session.scalars(select(DetectionSignal.signal_id))) == {
                "signal-old-candidate",
                "signal-young-dependency",
            }
            assert set(session.scalars(select(Incident.incident_id))) == {
                "incident-old-candidate",
                "incident-young-dependency",
            }
            assert session.execute(text("PRAGMA foreign_key_check")).all() == []
            sensitive_values = [
                *session.scalars(select(CanonicalEvent.safe_message_excerpt)),
                *session.scalars(select(IngestionJob.original_filename)),
                *session.scalars(select(Incident.review_reason)),
                *session.scalars(select(EvidenceItem.quote)),
                *session.scalars(select(Report.content)),
            ]
            rendered = " ".join(str(value) for value in sensitive_values)
            for secret in SECRETS:
                assert secret not in rendered
    finally:
        engine.dispose()
