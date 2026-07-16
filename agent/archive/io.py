from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
import gzip
import hashlib
import sqlite3

from pydantic import ValidationError

from agent.archive.schemas import (
    ARCHIVE_RECORD_SCHEMA_VERSION,
    ArchiveEntityType,
    ArchiveManifestV1,
    ArchivePayloadManifest,
    ArchiveRecord,
    EXPECTED_PAYLOAD_FILES,
    MAX_ARCHIVE_LINE_BYTES,
    SHA256_PATTERN,
    canonical_json_bytes,
    utc_datetime,
)
from agent.archive.storage import (
    ARCHIVE_METADATA_FILES,
    MANIFEST_CHECKSUM_FILENAME,
    MANIFEST_FILENAME,
    ArchiveStore,
    ArchiveWorkspace,
)


class ArchiveIntegrityError(Exception):
    def __init__(self, code: str = "archive_integrity_failed") -> None:
        super().__init__(code)
        self.code = code


class ArchiveExportError(Exception):
    def __init__(self, code: str = "archive_export_failed") -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ArchiveVerificationResult:
    archive_id: str
    manifest: ArchiveManifestV1
    manifest_sha256: str


@dataclass(frozen=True)
class ArchivePayloadSnapshot:
    filename: str
    sha256: str
    compressed_bytes: int


@dataclass(frozen=True)
class ArchiveStabilitySnapshot:
    manifest_sha256: str
    payloads: tuple[ArchivePayloadSnapshot, ...]

    @classmethod
    def from_verification(
        cls,
        verification: ArchiveVerificationResult,
    ) -> ArchiveStabilitySnapshot:
        return cls(
            manifest_sha256=verification.manifest_sha256,
            payloads=tuple(
                ArchivePayloadSnapshot(
                    filename=payload.filename,
                    sha256=payload.sha256,
                    compressed_bytes=payload.compressed_bytes,
                )
                for payload in verification.manifest.payloads
            ),
        )

    @classmethod
    def from_dict(cls, value: object) -> ArchiveStabilitySnapshot:
        if not isinstance(value, dict):
            raise ArchiveIntegrityError("archive_snapshot_invalid")
        manifest_sha256 = value.get("manifest_sha256")
        raw_payloads = value.get("payloads")
        if not isinstance(manifest_sha256, str) or not SHA256_PATTERN.fullmatch(
            manifest_sha256
        ):
            raise ArchiveIntegrityError("archive_snapshot_invalid")
        if not isinstance(raw_payloads, list):
            raise ArchiveIntegrityError("archive_snapshot_invalid")
        payloads: list[ArchivePayloadSnapshot] = []
        for raw in raw_payloads:
            if not isinstance(raw, dict):
                raise ArchiveIntegrityError("archive_snapshot_invalid")
            filename = raw.get("filename")
            sha256 = raw.get("sha256")
            compressed_bytes = raw.get("compressed_bytes")
            if (
                filename not in EXPECTED_PAYLOAD_FILES
                or not isinstance(sha256, str)
                or not SHA256_PATTERN.fullmatch(sha256)
                or isinstance(compressed_bytes, bool)
                or not isinstance(compressed_bytes, int)
                or compressed_bytes < 0
            ):
                raise ArchiveIntegrityError("archive_snapshot_invalid")
            payloads.append(
                ArchivePayloadSnapshot(filename, sha256, compressed_bytes)
            )
        if tuple(payload.filename for payload in payloads) != EXPECTED_PAYLOAD_FILES:
            raise ArchiveIntegrityError("archive_snapshot_invalid")
        return cls(manifest_sha256, tuple(payloads))

    def to_dict(self) -> dict[str, object]:
        return {
            "manifest_sha256": self.manifest_sha256,
            "payloads": [
                {
                    "filename": payload.filename,
                    "sha256": payload.sha256,
                    "compressed_bytes": payload.compressed_bytes,
                }
                for payload in self.payloads
            ],
        }


@dataclass(frozen=True)
class ArchiveWriteResult:
    manifest: ArchiveManifestV1
    manifest_sha256: str


class _HashingWriter:
    def __init__(self, stream) -> None:
        self._stream = stream
        self._hash = hashlib.sha256()
        self.bytes_written = 0

    def write(self, content: bytes) -> int:
        written = self._stream.write(content)
        if written is None:
            written = len(content)
        self._hash.update(content[:written])
        self.bytes_written += written
        return written

    def flush(self) -> None:
        self._stream.flush()

    def hexdigest(self) -> str:
        return self._hash.hexdigest()


class ArchiveWriter:
    def __init__(self, store: ArchiveStore) -> None:
        self._store = store

    def write_payload(
        self,
        workspace: ArchiveWorkspace,
        filename: str,
        records: Iterable[ArchiveRecord],
        *,
        declared_entity_types: tuple[ArchiveEntityType, ...] = (),
    ) -> ArchivePayloadManifest:
        record_count = 0
        candidate_count = 0
        dependency_count = 0
        uncompressed_bytes = 0
        oldest: datetime | None = None
        newest: datetime | None = None
        seen_entity_types = set(declared_entity_types)
        with self._store.open_payload_writer(workspace, filename) as raw_stream:
            hashing_stream = _HashingWriter(raw_stream)
            with gzip.GzipFile(
                filename="",
                mode="wb",
                fileobj=hashing_stream,
                compresslevel=9,
                mtime=0,
            ) as compressed:
                for record in records:
                    line = canonical_json_bytes(record) + b"\n"
                    if len(line) > MAX_ARCHIVE_LINE_BYTES:
                        raise ArchiveExportError("archive_record_too_large")
                    compressed.write(line)
                    record_count += 1
                    uncompressed_bytes += len(line)
                    if record.archive_role == "retention_candidate":
                        candidate_count += 1
                    else:
                        dependency_count += 1
                    timestamp = utc_datetime(record.recorded_at)
                    oldest = timestamp if oldest is None else min(oldest, timestamp)
                    newest = timestamp if newest is None else max(newest, timestamp)
                    seen_entity_types.add(record.entity_type)
            hashing_stream.flush()
            sha256 = hashing_stream.hexdigest()
            compressed_bytes = hashing_stream.bytes_written
        return ArchivePayloadManifest(
            filename=filename,
            entity_types=tuple(sorted(seen_entity_types)),
            record_count=record_count,
            candidate_count=candidate_count,
            dependency_count=dependency_count,
            compressed_bytes=compressed_bytes,
            uncompressed_bytes=uncompressed_bytes,
            sha256=sha256,
            oldest_record_at=oldest,
            newest_record_at=newest,
        )

    def write_manifest(
        self,
        workspace: ArchiveWorkspace,
        manifest: ArchiveManifestV1,
    ) -> ArchiveWriteResult:
        manifest_bytes = canonical_json_bytes(manifest)
        checksum = hashlib.sha256(manifest_bytes).hexdigest()
        self._store.write_manifest(workspace, manifest_bytes, checksum)
        return ArchiveWriteResult(manifest, checksum)


class ArchiveVerifier:
    def __init__(self, store: ArchiveStore) -> None:
        self._store = store

    def verify(
        self,
        archive_id: str,
        *,
        workspace: ArchiveWorkspace | None = None,
    ) -> ArchiveVerificationResult:
        expected_files = set(EXPECTED_PAYLOAD_FILES) | set(ARCHIVE_METADATA_FILES)
        if set(self._store.list_files(archive_id, workspace=workspace)) != expected_files:
            raise ArchiveIntegrityError("archive_file_set_invalid")
        manifest_bytes = self._store.read_small_file(
            archive_id,
            MANIFEST_FILENAME,
            workspace=workspace,
        )
        sidecar = self._store.read_small_file(
            archive_id,
            MANIFEST_CHECKSUM_FILENAME,
            workspace=workspace,
        )
        try:
            checksum = sidecar.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise ArchiveIntegrityError("archive_manifest_checksum_invalid") from exc
        if not SHA256_PATTERN.fullmatch(checksum):
            raise ArchiveIntegrityError("archive_manifest_checksum_invalid")
        if hashlib.sha256(manifest_bytes).hexdigest() != checksum:
            raise ArchiveIntegrityError("archive_manifest_checksum_mismatch")
        try:
            manifest = ArchiveManifestV1.model_validate_json(manifest_bytes)
        except (ValidationError, ValueError) as exc:
            raise ArchiveIntegrityError("archive_manifest_invalid") from exc
        if canonical_json_bytes(manifest) != manifest_bytes:
            raise ArchiveIntegrityError("archive_manifest_not_canonical")
        if manifest.archive_id != archive_id:
            raise ArchiveIntegrityError("archive_manifest_id_mismatch")

        duplicate_database = sqlite3.connect("")
        try:
            duplicate_database.execute(
                "CREATE TABLE archive_keys ("
                "entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, "
                "PRIMARY KEY (entity_type, entity_id))"
            )
            for payload in manifest.payloads:
                self._verify_payload(
                    archive_id,
                    payload,
                    duplicate_database,
                    workspace,
                )
        finally:
            duplicate_database.close()
        return ArchiveVerificationResult(archive_id, manifest, checksum)

    def assert_stable(
        self,
        archive_id: str,
        snapshot: ArchiveStabilitySnapshot,
    ) -> None:
        expected_files = set(EXPECTED_PAYLOAD_FILES) | set(ARCHIVE_METADATA_FILES)
        if set(self._store.list_files(archive_id)) != expected_files:
            raise ArchiveIntegrityError("archive_file_set_changed")
        manifest_bytes = self._store.read_small_file(archive_id, MANIFEST_FILENAME)
        sidecar = self._store.read_small_file(
            archive_id,
            MANIFEST_CHECKSUM_FILENAME,
        )
        try:
            sidecar_checksum = sidecar.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise ArchiveIntegrityError("archive_manifest_changed") from exc
        if (
            sidecar_checksum != snapshot.manifest_sha256
            or hashlib.sha256(manifest_bytes).hexdigest()
            != snapshot.manifest_sha256
        ):
            raise ArchiveIntegrityError("archive_manifest_changed")
        for payload in snapshot.payloads:
            if self._store.file_size(archive_id, payload.filename) != payload.compressed_bytes:
                raise ArchiveIntegrityError("archive_payload_changed")

    def _verify_payload(
        self,
        archive_id: str,
        payload: ArchivePayloadManifest,
        duplicate_database: sqlite3.Connection,
        workspace: ArchiveWorkspace | None,
    ) -> None:
        compressed_hash = hashlib.sha256()
        compressed_bytes = 0
        with self._store.open_payload_reader(
            archive_id,
            payload.filename,
            workspace=workspace,
        ) as raw_stream:
            while chunk := raw_stream.read(64 * 1024):
                compressed_hash.update(chunk)
                compressed_bytes += len(chunk)
        if (
            compressed_hash.hexdigest() != payload.sha256
            or compressed_bytes != payload.compressed_bytes
            or compressed_bytes
            != self._store.file_size(
                archive_id,
                payload.filename,
                workspace=workspace,
            )
        ):
            raise ArchiveIntegrityError("archive_payload_checksum_mismatch")

        record_count = 0
        candidate_count = 0
        dependency_count = 0
        uncompressed_bytes = 0
        oldest: datetime | None = None
        newest: datetime | None = None
        previous_candidate_cursor: tuple[datetime, str] | None = None
        try:
            with self._store.open_payload_reader(
                archive_id,
                payload.filename,
                workspace=workspace,
            ) as raw_stream:
                with gzip.GzipFile(fileobj=raw_stream, mode="rb") as compressed:
                    while True:
                        line = compressed.readline(MAX_ARCHIVE_LINE_BYTES + 1)
                        if not line:
                            break
                        if len(line) > MAX_ARCHIVE_LINE_BYTES:
                            raise ArchiveIntegrityError("archive_record_too_large")
                        if not line.endswith(b"\n"):
                            raise ArchiveIntegrityError("archive_ndjson_line_invalid")
                        uncompressed_bytes += len(line)
                        try:
                            record = ArchiveRecord.model_validate_json(line)
                        except (ValidationError, ValueError) as exc:
                            raise ArchiveIntegrityError("archive_record_invalid") from exc
                        self._validate_payload_role(payload.filename, record)
                        if record.entity_type not in payload.entity_types:
                            raise ArchiveIntegrityError("archive_payload_entity_mismatch")
                        try:
                            duplicate_database.execute(
                                "INSERT INTO archive_keys(entity_type, entity_id) "
                                "VALUES (?, ?)",
                                (record.entity_type, record.entity_id),
                            )
                        except sqlite3.IntegrityError as exc:
                            raise ArchiveIntegrityError("archive_record_duplicate") from exc
                        record_count += 1
                        if record.archive_role == "retention_candidate":
                            candidate_count += 1
                        else:
                            dependency_count += 1
                        timestamp = utc_datetime(record.recorded_at)
                        if payload.filename != "dependent_records.ndjson.gz":
                            cursor = (timestamp, record.entity_id)
                            if (
                                previous_candidate_cursor is not None
                                and cursor <= previous_candidate_cursor
                            ):
                                raise ArchiveIntegrityError(
                                    "archive_candidate_order_invalid"
                                )
                            previous_candidate_cursor = cursor
                        oldest = timestamp if oldest is None else min(oldest, timestamp)
                        newest = timestamp if newest is None else max(newest, timestamp)
        except ArchiveIntegrityError:
            raise
        except (EOFError, gzip.BadGzipFile, OSError) as exc:
            raise ArchiveIntegrityError("archive_payload_gzip_invalid") from exc

        if (
            record_count != payload.record_count
            or candidate_count != payload.candidate_count
            or dependency_count != payload.dependency_count
            or uncompressed_bytes != payload.uncompressed_bytes
            or oldest != payload.oldest_record_at
            or newest != payload.newest_record_at
        ):
            raise ArchiveIntegrityError("archive_payload_metadata_mismatch")

    @staticmethod
    def _validate_payload_role(filename: str, record: ArchiveRecord) -> None:
        candidate_files = {
            "canonical_events.ndjson.gz": "canonical_event",
            "detection_signals.ndjson.gz": "detection_signal",
            "ingestion_jobs.ndjson.gz": "ingestion_job",
            "incidents.ndjson.gz": "incident",
            "audit_events.ndjson.gz": "audit_event",
        }
        if filename == "dependent_records.ndjson.gz":
            if record.archive_role != "dependency":
                raise ArchiveIntegrityError("archive_dependency_role_invalid")
            return
        if (
            record.archive_role != "retention_candidate"
            or record.entity_type != candidate_files.get(filename)
        ):
            raise ArchiveIntegrityError("archive_candidate_role_invalid")


class ArchiveReader:
    def __init__(self, store: ArchiveStore) -> None:
        self._store = store

    def read_manifest(
        self,
        archive_id: str,
        *,
        workspace: ArchiveWorkspace | None = None,
    ) -> ArchiveManifestV1:
        manifest_bytes = self._store.read_small_file(
            archive_id,
            MANIFEST_FILENAME,
            workspace=workspace,
        )
        try:
            return ArchiveManifestV1.model_validate_json(manifest_bytes)
        except (ValidationError, ValueError) as exc:
            raise ArchiveIntegrityError("archive_manifest_invalid") from exc

    def iter_records(
        self,
        archive_id: str,
        *,
        workspace: ArchiveWorkspace | None = None,
    ) -> Iterator[ArchiveRecord]:
        manifest = self.read_manifest(archive_id, workspace=workspace)
        for payload in manifest.payloads:
            try:
                with self._store.open_payload_reader(
                    archive_id,
                    payload.filename,
                    workspace=workspace,
                ) as raw_stream:
                    with gzip.GzipFile(fileobj=raw_stream, mode="rb") as compressed:
                        while True:
                            line = compressed.readline(MAX_ARCHIVE_LINE_BYTES + 1)
                            if not line:
                                break
                            if len(line) > MAX_ARCHIVE_LINE_BYTES:
                                raise ArchiveIntegrityError("archive_record_too_large")
                            yield ArchiveRecord.model_validate_json(line)
            except ArchiveIntegrityError:
                raise
            except (EOFError, gzip.BadGzipFile, OSError, ValidationError) as exc:
                raise ArchiveIntegrityError("archive_record_read_failed") from exc


def assert_supported_record_schema(record: ArchiveRecord) -> None:
    if record.schema_version != ARCHIVE_RECORD_SCHEMA_VERSION:
        raise ArchiveIntegrityError("archive_record_schema_unsupported")
