from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect


RETENTION_REVISION = "5d2a7e4c9b31"
PREVIOUS_REVISION = "5d1a9c2e7f40"


def _config(database: Path) -> Config:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    return config


def test_retention_revision_is_the_single_head() -> None:
    script = ScriptDirectory.from_config(Config("alembic.ini"))
    assert script.get_heads() == [RETENTION_REVISION]


def test_upgrade_creates_hold_table_constraints_and_indexes(tmp_path) -> None:
    database = tmp_path / "retention-upgrade.db"
    config = _config(database)
    command.upgrade(config, "head")
    engine = create_engine(f"sqlite:///{database}")
    try:
        inspector = inspect(engine)
        assert "retention_holds" in inspector.get_table_names()
        assert {
            index["name"]
            for index in inspector.get_indexes("retention_holds")
        } == {
            "ix_retention_holds_entity_active",
            "ix_retention_holds_expires_at",
        }
        constraint_names = {
            constraint["name"]
            for constraint in inspector.get_check_constraints("retention_holds")
        }
        assert constraint_names == {
            "ck_retention_holds_entity_type",
            "ck_retention_holds_expiry_after_creation",
            "ck_retention_holds_reason_not_blank",
        }
    finally:
        engine.dispose()


def test_downgrade_removes_only_retention_hold_schema(tmp_path) -> None:
    database = tmp_path / "retention-downgrade.db"
    config = _config(database)
    command.upgrade(config, "head")
    command.downgrade(config, PREVIOUS_REVISION)
    engine = create_engine(f"sqlite:///{database}")
    try:
        tables = set(inspect(engine).get_table_names())
        assert "retention_holds" not in tables
        assert "canonical_events" in tables
        assert "incidents" in tables
    finally:
        engine.dispose()
