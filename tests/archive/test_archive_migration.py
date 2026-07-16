from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError


ARCHIVE_REVISION = "5d2b8f6a1c42"
RETENTION_REVISION = "5d2a7e4c9b31"


def _config(database: Path) -> Config:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    return config


def test_archive_revision_is_the_only_alembic_head() -> None:
    script = ScriptDirectory.from_config(Config("alembic.ini"))
    assert script.get_heads() == [ARCHIVE_REVISION]
    revision = script.get_revision(ARCHIVE_REVISION)
    assert revision is not None
    assert revision.down_revision == RETENTION_REVISION


def test_archive_upgrade_creates_run_constraints_indexes_and_keeps_holds(
    tmp_path,
) -> None:
    database = tmp_path / "archive-upgrade.db"
    command.upgrade(_config(database), "head")
    engine = create_engine(f"sqlite:///{database}")
    try:
        inspector = inspect(engine)
        assert "retention_archive_runs" in inspector.get_table_names()
        assert "retention_holds" in inspector.get_table_names()
        assert {
            index["name"]
            for index in inspector.get_indexes("retention_archive_runs")
        } == {
            "ix_retention_archive_runs_archive_as_of",
            "ix_retention_archive_runs_status",
        }
        assert {
            constraint["name"]
            for constraint in inspector.get_check_constraints(
                "retention_archive_runs"
            )
        } == {
            "ck_retention_archive_runs_manifest_sha256",
            "ck_retention_archive_runs_nonnegative_counts",
            "ck_retention_archive_runs_status",
            "ck_retention_archive_runs_total_count",
        }
        with engine.begin() as connection:
            with pytest.raises(IntegrityError):
                connection.execute(
                    text(
                        "INSERT INTO retention_archive_runs "
                        "(archive_id, policy_version, schema_version, status, "
                        "archive_as_of, created_at, storage_key, "
                        "candidate_record_count, dependency_record_count, "
                        "total_record_count) VALUES "
                        "('ARC-00000000000000000000000000000000', 'v1', 'v1', "
                        "'invalid', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, "
                        "'ARC-00000000000000000000000000000000', 0, 0, 0)"
                    )
                )
    finally:
        engine.dispose()


def test_archive_downgrade_removes_only_archive_run_table(tmp_path) -> None:
    database = tmp_path / "archive-downgrade.db"
    config = _config(database)
    command.upgrade(config, "head")
    command.downgrade(config, RETENTION_REVISION)
    engine = create_engine(f"sqlite:///{database}")
    try:
        tables = set(inspect(engine).get_table_names())
        assert "retention_archive_runs" not in tables
        assert "retention_holds" in tables
        assert "canonical_events" in tables
        assert "incidents" in tables
    finally:
        engine.dispose()
