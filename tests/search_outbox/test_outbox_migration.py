from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
import pytest
from sqlalchemy import JSON, MetaData, Table, create_engine, inspect
from sqlalchemy.exc import IntegrityError


OUTBOX_REVISION = "02a14b4d18bf"
PREVIOUS_REVISION = "5d2c9a7e4b10"
PREVIOUS_TABLES = {
    "retention_holds",
    "retention_archive_runs",
    "retention_cleanup_runs",
    "retention_cleanup_progress",
}


def _config(database: Path) -> Config:
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    return config


def _outbox_values(**overrides: object) -> dict[str, object]:
    now = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
    values: dict[str, object] = {
        "outbox_id": "outbox-1",
        "entity_type": "canonical_event",
        "entity_id": "event-1",
        "operation": "upsert",
        "schema_version": "v1",
        "document_version": 1,
        "deduplication_key": "d" * 64,
        "payload": {"entity_type": "canonical_event"},
        "payload_sha256": "a" * 64,
        "payload_size_bytes": 32,
        "status": "pending",
        "available_at": now,
        "attempt_count": 0,
        "created_at": now,
        "updated_at": now,
        "version": 1,
    }
    values.update(overrides)
    return values


def test_outbox_revision_is_the_only_head_and_follows_cleanup() -> None:
    script = ScriptDirectory.from_config(Config("alembic.ini"))
    assert script.get_heads() == [OUTBOX_REVISION]
    revision = script.get_revision(OUTBOX_REVISION)
    assert revision is not None
    assert revision.down_revision == PREVIOUS_REVISION


def test_empty_database_upgrade_creates_constraints_indexes_and_keeps_retention(
    tmp_path: Path,
) -> None:
    database = tmp_path / "outbox-upgrade.db"
    command.upgrade(_config(database), "head")
    engine = create_engine(f"sqlite:///{database}")
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        assert "search_index_outbox" in tables
        assert PREVIOUS_TABLES <= tables
        assert {
            index["name"] for index in inspector.get_indexes("search_index_outbox")
        } == {
            "ix_search_index_outbox_entity_lookup",
            "ix_search_index_outbox_lease_expires",
            "ix_search_index_outbox_status_available",
        }
        assert {
            constraint["name"]
            for constraint in inspector.get_check_constraints("search_index_outbox")
        } == {
            "ck_search_index_outbox_document_version",
            "ck_search_index_outbox_entity_type",
            "ck_search_index_outbox_nonnegative",
            "ck_search_index_outbox_operation",
            "ck_search_index_outbox_status",
        }

        metadata = MetaData()
        outbox = Table(
            "search_index_outbox",
            metadata,
            autoload_with=engine,
        )
        assert isinstance(outbox.c.payload.type, JSON)
        invalid_values = [
            {"entity_type": "raw_log"},
            {"operation": "delete"},
            {"status": "unknown"},
            {"document_version": 0},
            {"attempt_count": -1},
            {"payload_size_bytes": -1},
        ]
        for index, overrides in enumerate(invalid_values, start=1):
            values = _outbox_values(
                outbox_id=f"invalid-{index}",
                deduplication_key=f"{index:064x}",
                **overrides,
            )
            with engine.begin() as connection:
                with pytest.raises(IntegrityError):
                    connection.execute(outbox.insert().values(**values))

        with engine.begin() as connection:
            connection.execute(outbox.insert().values(**_outbox_values()))
        with engine.begin() as connection:
            with pytest.raises(IntegrityError):
                connection.execute(
                    outbox.insert().values(
                        **_outbox_values(outbox_id="outbox-duplicate")
                    )
                )
    finally:
        engine.dispose()


def test_upgrade_downgrade_upgrade_round_trip_preserves_previous_tables(
    tmp_path: Path,
) -> None:
    database = tmp_path / "outbox-round-trip.db"
    config = _config(database)
    command.upgrade(config, "head")
    command.downgrade(config, PREVIOUS_REVISION)

    engine = create_engine(f"sqlite:///{database}")
    try:
        tables = set(inspect(engine).get_table_names())
        assert "search_index_outbox" not in tables
        assert PREVIOUS_TABLES <= tables
    finally:
        engine.dispose()

    command.upgrade(config, "head")
    engine = create_engine(f"sqlite:///{database}")
    try:
        tables = set(inspect(engine).get_table_names())
        assert "search_index_outbox" in tables
        assert PREVIOUS_TABLES <= tables
    finally:
        engine.dispose()
