from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest
from pydantic import ValidationError

from agent.config import Settings
from agent.maintenance import cleanup as cleanup_cli
from agent.persistence.unit_of_work import UnitOfWork
from tests.archive.conftest import ARCHIVE_ID, SECRETS


@pytest.mark.parametrize(
    "arguments",
    [
        ["execute", "--archive-id", ARCHIVE_ID],
        [
            "execute",
            "--archive-id",
            ARCHIVE_ID,
            "--confirm-archive-id",
            "ARC-ffffffffffffffffffffffffffffffff",
        ],
        [
            "execute",
            "--archive-id",
            "../private/archive",
            "--confirm-archive-id",
            "../private/archive",
        ],
        [
            "execute",
            "--archive-id",
            "C:\\private\\archive",
            "--confirm-archive-id",
            "C:\\private\\archive",
        ],
    ],
)
def test_confirmation_rejected_before_settings_database_or_filesystem(
    monkeypatch,
    arguments,
) -> None:
    accessed = False

    def forbidden_settings():
        nonlocal accessed
        accessed = True
        raise AssertionError("settings accessed")

    monkeypatch.setattr(cleanup_cli, "get_settings", forbidden_settings)
    stdout = StringIO()
    stderr = StringIO()
    exit_code = cleanup_cli.main(arguments, stdout=stdout, stderr=stderr)

    assert exit_code == 2
    assert accessed is False
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "Retention cleanup failed safely.\n"


def test_cleanup_cli_success_is_safe_and_idempotent(cleanup_env) -> None:
    stdout = StringIO()
    stderr = StringIO()
    def make_uow() -> UnitOfWork:
        return UnitOfWork(cleanup_env.archive.session_factory)

    exit_code = cleanup_cli.main(
        [
            "execute",
            "--archive-id",
            ARCHIVE_ID,
            "--confirm-archive-id",
            ARCHIVE_ID,
        ],
        settings=cleanup_env.settings,
        store=cleanup_env.archive.store,
        uow_factory=make_uow,
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 0
    assert stderr.getvalue() == ""
    rendered = stdout.getvalue()
    assert "Status: completed" in rendered
    assert "Deleted records: 2" in rendered
    assert "Completed entity phases:" in rendered
    for secret in SECRETS:
        assert secret not in rendered
    assert cleanup_env.settings.database_url not in rendered
    assert cleanup_env.settings.retention_archive_root not in rendered

    second_stdout = StringIO()
    assert cleanup_cli.main(
        [
            "execute",
            "--archive-id",
            ARCHIVE_ID,
            "--confirm-archive-id",
            ARCHIVE_ID,
        ],
        settings=cleanup_env.settings,
        store=cleanup_env.archive.store,
        uow_factory=make_uow,
        stdout=second_stdout,
        stderr=StringIO(),
    ) == 0
    assert "Deleted records: 2" in second_stdout.getvalue()


def test_corrupt_archive_cli_failure_is_generic_and_redacted(cleanup_env) -> None:
    payload = (
        Path(cleanup_env.settings.retention_archive_root)
        / ARCHIVE_ID
        / "audit_events.ndjson.gz"
    )
    payload.write_bytes(payload.read_bytes() + b"raw exception secret")
    stdout = StringIO()
    stderr = StringIO()

    def make_uow() -> UnitOfWork:
        return UnitOfWork(cleanup_env.archive.session_factory)

    exit_code = cleanup_cli.main(
        [
            "execute",
            "--archive-id",
            ARCHIVE_ID,
            "--confirm-archive-id",
            ARCHIVE_ID,
        ],
        settings=cleanup_env.settings,
        store=cleanup_env.archive.store,
        uow_factory=make_uow,
        stdout=stdout,
        stderr=stderr,
    )
    assert exit_code == 1
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "Retention cleanup failed safely.\n"
    rendered = stdout.getvalue() + stderr.getvalue()
    assert "raw exception secret" not in rendered
    assert cleanup_env.settings.database_url not in rendered
    assert cleanup_env.settings.retention_archive_root not in rendered


@pytest.mark.parametrize(
    "field,value",
    [
        ("retention_cleanup_batch_size", 0),
        ("retention_cleanup_batch_size", 5_001),
        ("retention_cleanup_lease_seconds", 0),
        ("retention_cleanup_lease_seconds", 29),
        ("retention_cleanup_lease_seconds", 86_401),
    ],
)
def test_cleanup_settings_are_bounded(field, value, tmp_path) -> None:
    values = {
        "_env_file": None,
        "staging_dir": str(tmp_path / "staging"),
        "retention_archive_root": str(tmp_path / "archives"),
        field: value,
    }
    with pytest.raises(ValidationError):
        Settings(**values)


def test_cleanup_settings_environment_override(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("RETENTION_CLEANUP_BATCH_SIZE", "37")
    monkeypatch.setenv("RETENTION_CLEANUP_LEASE_SECONDS", "91")
    settings = Settings(
        _env_file=None,
        staging_dir=str(tmp_path / "staging"),
        retention_archive_root=str(tmp_path / "archives"),
    )
    assert settings.retention_cleanup_batch_size == 37
    assert settings.retention_cleanup_lease_seconds == 91
