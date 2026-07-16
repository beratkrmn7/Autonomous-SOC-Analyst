from __future__ import annotations

from collections.abc import Callable
import gzip
import hashlib
import json
from pathlib import Path

import pytest

from agent.archive.io import ArchiveIntegrityError, ArchiveVerifier
from agent.archive.schemas import (
    ARCHIVE_MANIFEST_SCHEMA_VERSION,
    ARCHIVE_SAFETY_PROFILE,
    EXPECTED_PAYLOAD_FILES,
    ArchiveManifestV1,
    canonical_json_bytes,
)
from tests.archive.conftest import (
    ARCHIVE_ID,
    SECRETS,
    make_environment,
    seed_archive_graph,
)


def _archive_directory(environment) -> Path:
    return environment.store.root / ARCHIVE_ID


def _manifest_document(environment) -> dict:
    return json.loads(
        (_archive_directory(environment) / "manifest.json").read_text("utf-8")
    )


def _write_manifest(environment, document: dict) -> None:
    content = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    directory = _archive_directory(environment)
    (directory / "manifest.json").write_bytes(content)
    (directory / "manifest.sha256").write_text(
        f"{hashlib.sha256(content).hexdigest()}\n",
        encoding="ascii",
    )


def _rewrite_payload(
    environment,
    filename: str,
    transform: Callable[[list[bytes]], list[bytes]],
) -> None:
    directory = _archive_directory(environment)
    path = directory / filename
    lines = gzip.decompress(path.read_bytes()).splitlines(keepends=True)
    uncompressed = b"".join(transform(lines))
    compressed = gzip.compress(uncompressed, compresslevel=9, mtime=0)
    path.write_bytes(compressed)
    document = _manifest_document(environment)
    payload = next(
        item for item in document["payloads"] if item["filename"] == filename
    )
    payload["sha256"] = hashlib.sha256(compressed).hexdigest()
    payload["compressed_bytes"] = len(compressed)
    payload["uncompressed_bytes"] = len(uncompressed)
    _write_manifest(environment, document)


def _created_archive(environment) -> None:
    seed_archive_graph(environment)
    environment.service().create()


def test_manifest_v1_is_typed_canonical_complete_and_safe(archive_env) -> None:
    _created_archive(archive_env)
    directory = _archive_directory(archive_env)
    manifest_bytes = (directory / "manifest.json").read_bytes()
    manifest = ArchiveManifestV1.model_validate_json(manifest_bytes)

    assert manifest_bytes == canonical_json_bytes(manifest)
    assert manifest.schema_version == ARCHIVE_MANIFEST_SCHEMA_VERSION
    assert manifest.archive_safety_profile == ARCHIVE_SAFETY_PROFILE
    assert manifest.compression == "gzip"
    assert manifest.hash_algorithm == "sha256"
    assert manifest.archive_format == "ndjson"
    assert manifest.contains_raw_logs is False
    assert manifest.contains_credentials is False
    assert tuple(payload.filename for payload in manifest.payloads) == (
        EXPECTED_PAYLOAD_FILES
    )
    assert manifest.total_record_count == 21
    assert manifest.candidate_record_count == 5
    assert manifest.dependency_record_count == 16
    assert all(
        payload.oldest_record_at <= payload.newest_record_at
        for payload in manifest.payloads
        if payload.record_count
    )
    sidecar = (directory / "manifest.sha256").read_text("ascii").strip()
    assert sidecar == hashlib.sha256(manifest_bytes).hexdigest()
    rendered = manifest_bytes.decode("utf-8")
    assert str(archive_env.store.root) not in rendered
    for secret in SECRETS:
        assert secret not in rendered


def test_payloads_are_deterministic_gzip_with_compressed_checksums(
    tmp_path,
) -> None:
    first = make_environment(tmp_path / "first")
    second = make_environment(tmp_path / "second")
    try:
        _created_archive(first)
        _created_archive(second)
        first_manifest = ArchiveVerifier(first.store).verify(ARCHIVE_ID).manifest
        second_manifest = ArchiveVerifier(second.store).verify(ARCHIVE_ID).manifest
        for first_payload, second_payload in zip(
            first_manifest.payloads,
            second_manifest.payloads,
            strict=True,
        ):
            first_bytes = (
                _archive_directory(first) / first_payload.filename
            ).read_bytes()
            second_bytes = (
                _archive_directory(second) / second_payload.filename
            ).read_bytes()
            assert first_bytes[:2] == b"\x1f\x8b"
            assert first_bytes == second_bytes
            assert hashlib.sha256(first_bytes).hexdigest() == first_payload.sha256
            assert first_payload.sha256 == second_payload.sha256
    finally:
        first.engine.dispose()
        second.engine.dispose()


def test_manifest_mutation_is_rejected(archive_env) -> None:
    _created_archive(archive_env)
    path = _archive_directory(archive_env) / "manifest.json"
    path.write_bytes(path.read_bytes().replace(b'"gzip"', b'"GZIP"', 1))

    with pytest.raises(
        ArchiveIntegrityError,
        match="archive_manifest_checksum_mismatch",
    ):
        ArchiveVerifier(archive_env.store).verify(ARCHIVE_ID)


@pytest.mark.parametrize("mutation", ["missing", "unexpected"])
def test_missing_or_unexpected_archive_file_is_rejected(
    archive_env,
    mutation,
) -> None:
    _created_archive(archive_env)
    directory = _archive_directory(archive_env)
    if mutation == "missing":
        (directory / "audit_events.ndjson.gz").unlink()
    else:
        (directory / "unexpected.payload").write_bytes(b"not-allowed")

    with pytest.raises(
        ArchiveIntegrityError,
        match="archive_file_set_invalid",
    ):
        ArchiveVerifier(archive_env.store).verify(ARCHIVE_ID)


def test_manifest_payload_path_traversal_is_rejected(archive_env) -> None:
    _created_archive(archive_env)
    document = _manifest_document(archive_env)
    document["payloads"][0]["filename"] = "../canonical_events.ndjson.gz"
    _write_manifest(archive_env, document)

    with pytest.raises(ArchiveIntegrityError, match="archive_manifest_invalid"):
        ArchiveVerifier(archive_env.store).verify(ARCHIVE_ID)


@pytest.mark.parametrize("mode", ["truncated", "mutated"])
def test_corrupt_compressed_payload_is_rejected(archive_env, mode) -> None:
    _created_archive(archive_env)
    filename = "canonical_events.ndjson.gz"
    path = _archive_directory(archive_env) / filename
    content = bytearray(path.read_bytes())
    if mode == "truncated":
        changed = bytes(content[:-8])
    else:
        content[len(content) // 2] ^= 0x01
        changed = bytes(content)
    path.write_bytes(changed)

    if mode == "truncated":
        document = _manifest_document(archive_env)
        payload = next(
            item for item in document["payloads"] if item["filename"] == filename
        )
        payload["sha256"] = hashlib.sha256(changed).hexdigest()
        payload["compressed_bytes"] = len(changed)
        _write_manifest(archive_env, document)

    with pytest.raises(ArchiveIntegrityError):
        ArchiveVerifier(archive_env.store).verify(ARCHIVE_ID)


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        (lambda lines: [b"{invalid-json}\n", *lines[1:]], "archive_record_invalid"),
        (
            lambda lines: [
                json.dumps(
                    {
                        **json.loads(lines[0]),
                        "schema_version": "retention-archive/v2",
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode()
                + b"\n",
                *lines[1:],
            ],
            "archive_record_invalid",
        ),
        (
            lambda lines: [
                json.dumps(
                    {**json.loads(lines[0]), "entity_type": "unknown_entity"},
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode()
                + b"\n",
                *lines[1:],
            ],
            "archive_record_invalid",
        ),
    ],
)
def test_invalid_payload_records_are_rejected(
    archive_env,
    mutation,
    expected_code,
) -> None:
    _created_archive(archive_env)
    _rewrite_payload(
        archive_env,
        "dependent_records.ndjson.gz",
        mutation,
    )

    with pytest.raises(ArchiveIntegrityError, match=expected_code):
        ArchiveVerifier(archive_env.store).verify(ARCHIVE_ID)


def test_payload_count_mismatch_is_rejected(archive_env) -> None:
    _created_archive(archive_env)
    _rewrite_payload(
        archive_env,
        "dependent_records.ndjson.gz",
        lambda lines: lines[:-1],
    )

    with pytest.raises(
        ArchiveIntegrityError,
        match="archive_payload_metadata_mismatch",
    ):
        ArchiveVerifier(archive_env.store).verify(ARCHIVE_ID)


def test_payload_timestamp_range_mismatch_is_rejected(archive_env) -> None:
    _created_archive(archive_env)
    document = _manifest_document(archive_env)
    payload = next(item for item in document["payloads"] if item["record_count"])
    payload["oldest_record_at"] = "2000-01-01T00:00:00Z"
    _write_manifest(archive_env, document)

    with pytest.raises(
        ArchiveIntegrityError,
        match="archive_payload_metadata_mismatch",
    ):
        ArchiveVerifier(archive_env.store).verify(ARCHIVE_ID)


def test_duplicate_entity_is_rejected_with_bounded_disk_index(archive_env) -> None:
    _created_archive(archive_env)
    _rewrite_payload(
        archive_env,
        "dependent_records.ndjson.gz",
        lambda lines: [lines[0], lines[0], *lines[2:]],
    )

    with pytest.raises(
        ArchiveIntegrityError,
        match="archive_record_duplicate",
    ):
        ArchiveVerifier(archive_env.store).verify(ARCHIVE_ID)
