from __future__ import annotations

from datetime import timedelta
from io import StringIO
import os
from pathlib import Path
import subprocess
import sys

from sqlalchemy import event, func, insert, select

from agent.application.retention import RetentionPlanner, RetentionPolicy
from agent.maintenance.retention import main
from agent.persistence.orm_models import (
    AuditEvent,
    Base,
    CanonicalEvent,
    DetectionSignal,
    EvidenceItem,
    Incident,
    IncidentEvent,
    IngestionJob,
    Report,
    TriageRun,
)
from agent.persistence.retention_repository import RetentionRepository
from agent.persistence.unit_of_work import UnitOfWork
from tests.retention.conftest import NOW


def _table_counts(environment) -> dict[str, int]:
    with environment.session_factory() as session:
        return {
            table.name: session.execute(
                select(func.count()).select_from(table)
            ).scalar_one()
            for table in Base.metadata.sorted_tables
        }


def test_cli_dry_run_preserves_all_database_and_staging_state(retention_env) -> None:
    old_event = CanonicalEvent(
        event_id="event-private-id",
        timestamp=NOW - timedelta(days=60),
    )
    old_signal = DetectionSignal(
        signal_id="signal-private-id",
        created_at=NOW - timedelta(days=120),
    )
    old_job = IngestionJob(
        id="job-private-id",
        status="completed",
        completed_at=NOW - timedelta(days=120),
    )
    old_incident = Incident(
        incident_id="incident-private-id",
        status="resolved",
        updated_at=NOW - timedelta(days=500),
    )
    old_incident.events.append(IncidentEvent(event_id=old_event.event_id))
    old_job.events.append(old_event)
    old_job.signals.append(old_signal)
    old_job.incidents.append(old_incident)
    with retention_env.session_factory() as session:
        session.add_all([old_event, old_signal, old_job, old_incident])
        session.add(
            TriageRun(
                triage_run_id="triage-private-id",
                job_id=old_job.id,
                incident_id=old_incident.incident_id,
            )
        )
        session.add(
            EvidenceItem(
                evidence_id="evidence-private-id",
                job_id=old_job.id,
                incident_id=old_incident.incident_id,
                event_id=old_event.event_id,
            )
        )
        session.add(
            Report(
                report_id="report-private-id",
                job_id=old_job.id,
                incident_id=old_incident.incident_id,
            )
        )
        session.add(
            AuditEvent(
                audit_event_id="audit-private-id",
                incident_id=old_incident.incident_id,
                timestamp=NOW - timedelta(days=500),
            )
        )
        session.commit()

    staging_dir = retention_env.settings.staging_dir
    staged_file = Path(staging_dir) / "job-private-id.upload"
    staged_file.parent.mkdir(parents=True)
    staged_file.write_text("private staged content", encoding="utf-8")
    before = _table_counts(retention_env)
    output = StringIO()
    errors = StringIO()

    exit_code = main(
        ["--dry-run"],
        settings=retention_env.settings,
        uow_factory=lambda: UnitOfWork(retention_env.session_factory),
        clock=lambda: NOW,
        stdout=output,
        stderr=errors,
    )

    assert exit_code == 0
    assert errors.getvalue() == ""
    assert before == _table_counts(retention_env)
    assert staged_file.read_text(encoding="utf-8") == "private staged content"
    rendered = output.getvalue()
    assert "No records were modified." in rendered
    assert retention_env.settings.database_url not in rendered
    assert "private-retention-test-secret" not in rendered
    assert staging_dir not in rendered
    assert "private-id" not in rendered
    assert "staged content" not in rendered


def test_cli_defaults_to_dry_run(retention_env) -> None:
    output = StringIO()
    assert main(
        [],
        settings=retention_env.settings,
        uow_factory=lambda: UnitOfWork(retention_env.session_factory),
        clock=lambda: NOW,
        stdout=output,
    ) == 0
    assert output.getvalue().startswith("Retention dry-run plan")


def test_cli_rejects_execute_before_database_access(retention_env) -> None:
    errors = StringIO()

    def unexpected_uow() -> UnitOfWork:
        raise AssertionError("database must not be accessed")

    assert main(
        ["--execute"],
        settings=retention_env.settings,
        uow_factory=unexpected_uow,
        stderr=errors,
    ) == 2
    assert errors.getvalue() == (
        "Retention execution is not supported; use --dry-run.\n"
    )


def test_python_module_entrypoint_exits_zero_without_modification(
    retention_env,
) -> None:
    before = _table_counts(retention_env)
    environment = os.environ.copy()
    environment.update(
        {
            "APP_ENV": "test",
            "DATABASE_URL": retention_env.settings.database_url,
            "GROQ_API_KEY": "entrypoint-private-secret",
            "STAGING_DIR": retention_env.settings.staging_dir,
        }
    )
    completed = subprocess.run(
        [sys.executable, "-m", "agent.maintenance.retention", "--dry-run"],
        cwd=Path.cwd(),
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stderr == ""
    assert "Retention dry-run plan" in completed.stdout
    assert "entrypoint-private-secret" not in completed.stdout
    assert retention_env.settings.database_url not in completed.stdout
    assert before == _table_counts(retention_env)


def test_large_plan_uses_five_aggregate_queries_without_loading_ids(
    retention_env,
) -> None:
    rows = [
        {
            "event_id": f"bulk-event-{index:05d}",
            "timestamp": NOW - timedelta(days=60),
        }
        for index in range(5_000)
    ]
    with retention_env.session_factory() as session:
        session.execute(insert(CanonicalEvent), rows)
        session.commit()

    statements: list[str] = []

    def capture_statement(
        _connection,
        _cursor,
        statement,
        _parameters,
        _context,
        _executemany,
    ) -> None:
        statements.append(" ".join(statement.lower().split()))

    event.listen(
        retention_env.engine,
        "before_cursor_execute",
        capture_statement,
    )
    try:
        with retention_env.session_factory() as session:
            plan = RetentionPlanner(
                RetentionRepository(session),
                RetentionPolicy.from_settings(retention_env.settings),
                clock=lambda: NOW,
            ).plan()
    finally:
        event.remove(
            retention_env.engine,
            "before_cursor_execute",
            capture_statement,
        )

    event_summary = next(
        summary
        for summary in plan.candidates
        if summary.entity_type == "canonical_event"
    )
    select_statements = [sql for sql in statements if sql.startswith("select")]
    assert event_summary.candidate_count == 5_000
    assert len(select_statements) == 5
    assert all("sum(case" in sql and "min(case" in sql for sql in select_statements)
    assert not any(
        sql.startswith("select canonical_events.event_id")
        or sql.startswith("select detection_signals.signal_id")
        or sql.startswith("select ingestion_jobs.id")
        or sql.startswith("select incidents.incident_id")
        for sql in select_statements
    )
