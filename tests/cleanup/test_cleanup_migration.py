from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError


CLEANUP_REVISION = "5d2c9a7e4b10"
ARCHIVE_REVISION = "5d2b8f6a1c42"
OUTBOX_REVISION = "02a14b4d18bf"


def _config(database: Path) -> Config:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    return config


def test_cleanup_revision_follows_archive() -> None:
    script = ScriptDirectory.from_config(Config("alembic.ini"))
    assert script.get_heads() == [OUTBOX_REVISION]
    revision = script.get_revision(CLEANUP_REVISION)
    assert revision is not None
    assert revision.down_revision == ARCHIVE_REVISION


def test_cleanup_upgrade_constraints_indexes_uniqueness_and_downgrade(
    tmp_path,
) -> None:
    database = tmp_path / "cleanup-migration.db"
    config = _config(database)
    command.upgrade(config, "head")
    engine = create_engine(f"sqlite:///{database}")
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        assert "retention_holds" in tables
        assert "retention_archive_runs" in tables
        assert "retention_cleanup_runs" in tables
        assert "retention_cleanup_progress" in tables
        assert {
            index["name"]
            for index in inspector.get_indexes("retention_cleanup_runs")
        } == {"ix_retention_cleanup_runs_status_lease"}
        assert {
            constraint["name"]
            for constraint in inspector.get_check_constraints(
                "retention_cleanup_runs"
            )
        } == {
            "ck_retention_cleanup_runs_manifest_sha256",
            "ck_retention_cleanup_runs_nonnegative_counts",
            "ck_retention_cleanup_runs_status",
            "ck_retention_cleanup_runs_version",
        }
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO retention_archive_runs "
                    "(archive_id, policy_version, schema_version, status, "
                    "archive_as_of, created_at, storage_key, "
                    "candidate_record_count, dependency_record_count, "
                    "total_record_count) VALUES "
                    "('ARC-00000000000000000000000000000000', 'v1', 'v1', "
                    "'verified', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, "
                    "'ARC-00000000000000000000000000000000', 0, 0, 0)"
                )
            )
            insert = text(
                "INSERT INTO retention_cleanup_runs "
                "(cleanup_run_id, archive_id, status, policy_version, "
                "archive_schema_version, manifest_sha256, archive_as_of, "
                "archive_snapshot, updated_at, current_phase, attempt_count, "
                "deleted_record_count, protected_record_count, "
                "missing_record_count, skipped_record_count, version) VALUES "
                "(:run_id, 'ARC-00000000000000000000000000000000', "
                "'pending', 'v1', 'v1', :checksum, CURRENT_TIMESTAMP, '{}', "
                "CURRENT_TIMESTAMP, 'pending', 0, 0, 0, 0, 0, 1)"
            )
            connection.execute(insert, {"run_id": "CLN-" + "1" * 32, "checksum": "a" * 64})
            with pytest.raises(IntegrityError):
                connection.execute(
                    insert,
                    {"run_id": "CLN-" + "2" * 32, "checksum": "b" * 64},
                )
    finally:
        engine.dispose()

    command.downgrade(config, ARCHIVE_REVISION)
    engine = create_engine(f"sqlite:///{database}")
    try:
        tables = set(inspect(engine).get_table_names())
        assert "retention_cleanup_runs" not in tables
        assert "retention_cleanup_progress" not in tables
        assert "retention_archive_runs" in tables
        assert "retention_holds" in tables
    finally:
        engine.dispose()
