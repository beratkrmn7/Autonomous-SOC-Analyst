from __future__ import annotations

import hashlib
import os
import pytest
from pydantic import ValidationError

from agent.archive.schemas import EXPECTED_PAYLOAD_FILES
from agent.archive.storage import (
    ArchiveAlreadyExistsError,
    ArchiveStorageError,
    LocalArchiveStore,
)
from agent.config import Settings
from tests.archive.conftest import ARCHIVE_ID


def test_archive_settings_defaults(monkeypatch) -> None:
    for key in (
        "RETENTION_ARCHIVE_BACKEND",
        "RETENTION_ARCHIVE_ROOT",
        "RETENTION_ARCHIVE_BATCH_SIZE",
        "RETENTION_ARCHIVE_SCHEMA_VERSION",
    ):
        monkeypatch.delenv(key, raising=False)
    settings = Settings(_env_file=None)
    assert settings.retention_archive_backend == "local"
    assert settings.retention_archive_root == "./var/retention-archives"
    assert settings.retention_archive_batch_size == 1000
    assert settings.retention_archive_schema_version == "retention-archive/v1"


@pytest.mark.parametrize("batch_size", [0, -1, 10_001])
def test_archive_settings_reject_invalid_batch_size(batch_size) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, retention_archive_batch_size=batch_size)


def test_archive_settings_reject_unsupported_backend_and_schema() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, retention_archive_backend="s3")
    with pytest.raises(ValidationError):
        Settings(_env_file=None, retention_archive_schema_version="v2")


@pytest.mark.parametrize(
    ("staging_suffix", "archive_suffix"),
    [
        ("shared", "shared"),
        ("shared", "shared/archives"),
        ("shared/staging", "shared"),
    ],
)
def test_archive_settings_reject_staging_root_overlap(
    tmp_path,
    staging_suffix,
    archive_suffix,
) -> None:
    with pytest.raises(
        ValidationError,
        match="retention_archive_root_conflicts_with_staging",
    ):
        Settings(
            _env_file=None,
            staging_dir=str(tmp_path / staging_suffix),
            retention_archive_root=str(tmp_path / archive_suffix),
        )


@pytest.mark.parametrize(
    "archive_id",
    [
        "../escape",
        "ARC-0123456789abcdef0123456789abcde/",
        "ARC-0123456789abcdef0123456789abcde\\",
        "C:/absolute/archive",
        "/absolute/archive",
        "ARC-not-hex",
    ],
)
def test_archive_id_path_traversal_and_absolute_paths_are_rejected(
    tmp_path,
    archive_id,
) -> None:
    store = LocalArchiveStore(str(tmp_path / "archives"))
    with pytest.raises(ValueError, match="archive_id_invalid"):
        store.begin(archive_id)
    assert list((tmp_path / "archives").glob("ARC-*")) == []


def test_payload_filename_cannot_escape_archive_workspace(tmp_path) -> None:
    store = LocalArchiveStore(str(tmp_path / "archives"))
    workspace = store.begin(ARCHIVE_ID)
    with pytest.raises(ArchiveStorageError, match="archive_filename_invalid"):
        with store.open_payload_writer(workspace, "../payload.ndjson.gz"):
            pass
    assert not (tmp_path / "payload.ndjson.gz").exists()


def test_partial_archive_is_hidden_and_abort_removes_it(tmp_path) -> None:
    store = LocalArchiveStore(str(tmp_path / "archives"))
    workspace = store.begin(ARCHIVE_ID)
    assert store.exists(ARCHIVE_ID) is False
    partial = store.root / ".partial" / ARCHIVE_ID
    assert partial.is_dir()
    store.abort(workspace)
    assert not partial.exists()
    assert store.exists(ARCHIVE_ID) is False


def _finalize_placeholder_archive(store: LocalArchiveStore) -> None:
    workspace = store.begin(ARCHIVE_ID)
    for filename in EXPECTED_PAYLOAD_FILES:
        with store.open_payload_writer(workspace, filename) as stream:
            stream.write(b"placeholder")
    manifest = b"{}"
    store.write_manifest(workspace, manifest, hashlib.sha256(manifest).hexdigest())
    store.finalize(workspace)


def test_atomic_finalize_exposes_complete_archive_and_prevents_overwrite(
    tmp_path,
) -> None:
    store = LocalArchiveStore(str(tmp_path / "archives"))
    _finalize_placeholder_archive(store)
    assert store.exists(ARCHIVE_ID) is True
    assert not (store.root / ".partial" / ARCHIVE_ID).exists()
    assert (store.root / ARCHIVE_ID / "manifest.json").is_file()
    with pytest.raises(ArchiveAlreadyExistsError):
        store.begin(ARCHIVE_ID)


def test_symlink_archive_and_payload_escape_are_rejected(tmp_path) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlink unsupported")
    store = LocalArchiveStore(str(tmp_path / "archives"))
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_archive = "ARC-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    try:
        os.symlink(
            outside,
            store.root / linked_archive,
            target_is_directory=True,
        )
    except OSError:
        pytest.skip("symlink creation is not permitted")
    with pytest.raises(ArchiveStorageError):
        store.exists(linked_archive)

    workspace = store.begin(ARCHIVE_ID)
    outside_file = outside / "payload"
    outside_file.write_bytes(b"outside")
    os.symlink(
        outside_file,
        store.root / ".partial" / ARCHIVE_ID / "canonical_events.ndjson.gz",
    )
    with pytest.raises(ArchiveStorageError, match="archive_symlink_forbidden"):
        with store.open_payload_writer(
            workspace,
            "canonical_events.ndjson.gz",
        ):
            pass


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
def test_local_archive_permissions_are_owner_only(tmp_path) -> None:
    store = LocalArchiveStore(str(tmp_path / "archives"))
    workspace = store.begin(ARCHIVE_ID)
    with store.open_payload_writer(
        workspace,
        "canonical_events.ndjson.gz",
    ) as stream:
        stream.write(b"payload")
    directory_mode = (store.root / ".partial" / ARCHIVE_ID).stat().st_mode & 0o777
    file_mode = (
        store.root / ".partial" / ARCHIVE_ID / "canonical_events.ndjson.gz"
    ).stat().st_mode & 0o777
    assert directory_mode == 0o700
    assert file_mode == 0o600
