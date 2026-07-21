"""Phase 6E.4A focused tests: the incident_correlation_states migration
(required tests 24-25)."""

from __future__ import annotations

import os
import tempfile

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


def _alembic_config(db_path: str) -> Config:
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    from agent.config import get_settings

    get_settings.cache_clear()
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    return cfg


# --- 24: migration upgrade creates the table, indexes and constraints


def test_migration_upgrade_creates_table_indexes_and_constraints() -> None:
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = None
    try:
        cfg = _alembic_config(db_path)
        command.upgrade(cfg, "head")

        engine = create_engine(f"sqlite:///{db_path}")
        inspector = inspect(engine)

        assert "incident_correlation_states" in inspector.get_table_names()

        columns = {col["name"] for col in inspector.get_columns("incident_correlation_states")}
        assert {
            "correlation_key",
            "correlation_version",
            "strategy",
            "incident_id",
            "profile",
            "generation",
            "first_seen",
            "last_seen",
            "expires_at",
            "version",
            "created_at",
            "updated_at",
        }.issubset(columns)

        pk_constraint = inspector.get_pk_constraint("incident_correlation_states")
        assert pk_constraint["constrained_columns"] == ["correlation_key"]

        fks = inspector.get_foreign_keys("incident_correlation_states")
        assert any(fk["referred_table"] == "incidents" for fk in fks)

        index_names = {idx["name"] for idx in inspector.get_indexes("incident_correlation_states")}
        assert {
            "ix_incident_correlation_states_incident_id",
            "ix_incident_correlation_states_expires_at",
            "ix_incident_correlation_states_last_seen",
            "ix_incident_correlation_states_strategy_last_seen",
        }.issubset(index_names)
    finally:
        if engine is not None:
            engine.dispose()
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except PermissionError:
                pass


# --- 25: migration downgrade removes only the new objects safely


def test_migration_downgrade_removes_only_new_table() -> None:
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = None
    try:
        cfg = _alembic_config(db_path)
        command.upgrade(cfg, "head")

        engine = create_engine(f"sqlite:///{db_path}")
        inspector = inspect(engine)
        tables_before_downgrade = set(inspector.get_table_names())
        assert "incident_correlation_states" in tables_before_downgrade

        command.downgrade(cfg, "7b9c2e4f6a81")

        inspector = inspect(engine)
        tables_after_downgrade = set(inspector.get_table_names())

        assert "incident_correlation_states" not in tables_after_downgrade
        # Every other table introduced by earlier migrations must survive
        # this downgrade untouched.
        assert tables_after_downgrade == tables_before_downgrade - {
            "incident_correlation_states"
        }
        assert "incidents" in tables_after_downgrade
        assert "search_projection_states" in tables_after_downgrade
    finally:
        if engine is not None:
            engine.dispose()
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except PermissionError:
                pass
