from __future__ import annotations

from io import StringIO
import re

import pytest
from sqlalchemy import select

import agent.maintenance.archive as archive_cli
from agent.application.archive import ArchiveOperationError, ArchiveService
from agent.archive.storage import ArchiveWorkspace, LocalArchiveStore
from agent.persistence.orm_models import AuditEvent, RetentionArchiveRun
from agent.persistence.unit_of_work import UnitOfWork
from tests.archive.conftest import ARCHIVE_ID, NOW, SECRETS, seed_archive_graph


def _uow_factory(environment):
    return lambda: UnitOfWork(environment.session_factory)


def _all_cli_text(stdout: StringIO, stderr: StringIO) -> str:
    return f"{stdout.getvalue()}\n{stderr.getvalue()}"


def test_archive_create_and_verify_cli_emit_only_safe_summaries(archive_env) -> None:
    seed_archive_graph(archive_env)
    create_stdout = StringIO()
    create_stderr = StringIO()
    create_code = archive_cli.main(
        ["create"],
        settings=archive_env.settings,
        store=archive_env.store,
        uow_factory=_uow_factory(archive_env),
        clock=lambda: NOW,
        stdout=create_stdout,
        stderr=create_stderr,
    )
    archive_id_match = re.search(
        r"Archive ID: (ARC-[0-9a-f]{32})",
        create_stdout.getvalue(),
    )
    assert archive_id_match is not None
    archive_id = archive_id_match.group(1)
    verify_stdout = StringIO()
    verify_stderr = StringIO()
    verify_code = archive_cli.main(
        ["verify", "--archive-id", archive_id],
        settings=archive_env.settings,
        store=archive_env.store,
        uow_factory=_uow_factory(archive_env),
        clock=lambda: NOW,
        stdout=verify_stdout,
        stderr=verify_stderr,
    )

    assert create_code == verify_code == 0
    assert create_stderr.getvalue() == verify_stderr.getvalue() == ""
    for output in (create_stdout.getvalue(), verify_stdout.getvalue()):
        assert f"Archive ID: {archive_id}" in output
        assert "Status: verified" in output
        assert "Candidate records: 5" in output
        assert "Dependency records: 16" in output
        assert "Database records were not deleted." in output
        assert str(archive_env.store.root) not in output
        assert archive_env.settings.database_url not in output
        assert archive_env.settings.staging_dir not in output
        for secret in SECRETS:
            assert secret not in output


def test_invalid_archive_id_is_rejected_before_settings_or_database(
    monkeypatch,
) -> None:
    def fail_if_called():
        raise AssertionError("settings access must not happen")

    monkeypatch.setattr(archive_cli, "get_settings", fail_if_called)
    stdout = StringIO()
    stderr = StringIO()

    code = archive_cli.main(
        ["verify", "--archive-id", "../private/archive"],
        stdout=stdout,
        stderr=stderr,
    )

    assert code == 2
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "Archive verification failed safely.\n"


@pytest.mark.parametrize("known_but_corrupt", [False, True])
def test_unknown_or_corrupted_archive_cli_returns_sanitized_error(
    archive_env,
    known_but_corrupt,
) -> None:
    seed_archive_graph(archive_env)
    archive_id = "ARC-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    if known_but_corrupt:
        archive_env.service().create()
        archive_id = ARCHIVE_ID
        manifest = archive_env.store.root / ARCHIVE_ID / "manifest.json"
        manifest.write_bytes(manifest.read_bytes() + b" ")
    stdout = StringIO()
    stderr = StringIO()

    code = archive_cli.main(
        ["verify", "--archive-id", archive_id],
        settings=archive_env.settings,
        store=archive_env.store,
        uow_factory=_uow_factory(archive_env),
        clock=lambda: NOW,
        stdout=stdout,
        stderr=stderr,
    )

    assert code == 1
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "Archive verification failed safely.\n"
    rendered = _all_cli_text(stdout, stderr)
    assert str(archive_env.store.root) not in rendered
    for secret in SECRETS:
        assert secret not in rendered


class _FailingFinalizeStore(LocalArchiveStore):
    def finalize(self, workspace: ArchiveWorkspace) -> None:
        raise RuntimeError(SECRETS[0])


def test_create_failure_is_sanitized_failed_and_cleans_partial_archive(
    archive_env,
) -> None:
    seed_archive_graph(archive_env)
    failing_store = _FailingFinalizeStore(str(archive_env.store.root))
    service = ArchiveService(
        _uow_factory(archive_env),
        failing_store,
        archive_env.settings,
        clock=lambda: NOW,
        archive_id_factory=lambda: ARCHIVE_ID,
    )

    with pytest.raises(ArchiveOperationError, match="archive_operation_failed"):
        service.create()

    assert failing_store.exists(ARCHIVE_ID) is False
    assert not (failing_store.root / ".partial" / ARCHIVE_ID).exists()
    with archive_env.session_factory() as session:
        run = session.get(RetentionArchiveRun, ARCHIVE_ID)
        assert run is not None
        assert run.status == "failed"
        assert run.sanitized_error_code == "archive_operation_failed"
        assert str(failing_store.root) not in str(run.storage_key)
        assert SECRETS[0] not in str(run.sanitized_error_code)
        failed_audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.entity_type == "retention_archive",
                AuditEvent.entity_id == ARCHIVE_ID,
                AuditEvent.event_type == "retention_archive_failed",
            )
        )
        assert failed_audit is not None
        assert SECRETS[0] not in str(failed_audit.details)


def test_completed_archive_cannot_be_created_again(archive_env) -> None:
    seed_archive_graph(archive_env)
    first = archive_env.service().create()
    manifest_before = (
        archive_env.store.root / ARCHIVE_ID / "manifest.json"
    ).read_bytes()

    with pytest.raises(ArchiveOperationError):
        archive_env.service().create()

    assert (
        archive_env.store.root / ARCHIVE_ID / "manifest.json"
    ).read_bytes() == manifest_before
    with archive_env.session_factory() as session:
        run = session.get(RetentionArchiveRun, ARCHIVE_ID)
        assert run is not None
        assert run.status == "verified"
        assert run.manifest_sha256 == first.manifest_sha256


def test_final_artifact_survives_metadata_failure_and_verify_recovers(
    archive_env,
    monkeypatch,
) -> None:
    seed_archive_graph(archive_env)
    service = archive_env.service()

    def fail_verified_metadata(_verification) -> None:
        raise RuntimeError(SECRETS[7])

    monkeypatch.setattr(service, "_mark_verified", fail_verified_metadata)
    with pytest.raises(
        ArchiveOperationError,
        match="archive_metadata_finalize_pending",
    ):
        service.create()

    assert archive_env.store.exists(ARCHIVE_ID) is True
    assert not (archive_env.store.root / ".partial" / ARCHIVE_ID).exists()
    with archive_env.session_factory() as session:
        run = session.get(RetentionArchiveRun, ARCHIVE_ID)
        assert run is not None
        assert run.status == "completed"
        assert run.sanitized_error_code is None

    recovered = archive_env.service().verify(ARCHIVE_ID)
    assert recovered.status == "verified"
    with archive_env.session_factory() as session:
        run = session.get(RetentionArchiveRun, ARCHIVE_ID)
        assert run is not None
        assert run.status == "verified"
        assert SECRETS[7] not in str(run.sanitized_error_code)
