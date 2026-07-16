from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
import os
from pathlib import Path
import sqlite3
import tempfile

from agent.archive.io import ArchiveIntegrityError, ArchiveReader
from agent.archive.schemas import ArchiveManifestV1, utc_datetime
from agent.archive.storage import ArchiveStore


@dataclass(frozen=True)
class ArchiveCandidateRef:
    recorded_at: datetime
    entity_id: str


class ArchiveMembershipIndex:
    """Ephemeral, permission-restricted index containing no archived record bodies."""

    def __init__(
        self,
        temporary_directory: tempfile.TemporaryDirectory[str],
        connection: sqlite3.Connection,
    ) -> None:
        self._temporary_directory = temporary_directory
        self._connection = connection
        self._closed = False

    @classmethod
    def build(
        cls,
        store: ArchiveStore,
        archive_id: str,
        manifest: ArchiveManifestV1,
        *,
        temporary_root: str,
    ) -> ArchiveMembershipIndex:
        temporary_directory = tempfile.TemporaryDirectory(
            prefix=".cleanup-index-",
            dir=temporary_root,
        )
        directory = Path(temporary_directory.name)
        try:
            if os.name != "nt":
                directory.chmod(0o700)
            database_path = directory / "membership.sqlite3"
            connection = sqlite3.connect(database_path)
            if os.name != "nt":
                database_path.chmod(0o600)
            connection.execute(
                "CREATE TABLE archive_records ("
                "entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, "
                "archive_role TEXT NOT NULL, recorded_at TEXT NOT NULL, "
                "PRIMARY KEY (entity_type, entity_id), "
                "CHECK (archive_role IN ('retention_candidate', 'dependency')))"
            )
            connection.execute(
                "CREATE INDEX archive_candidate_cursor ON archive_records "
                "(archive_role, entity_type, recorded_at, entity_id)"
            )
            candidate_count = 0
            dependency_count = 0
            pending = 0
            for record in ArchiveReader(store).iter_records(archive_id):
                recorded_at = utc_datetime(record.recorded_at).isoformat(
                    timespec="microseconds"
                )
                try:
                    connection.execute(
                        "INSERT INTO archive_records "
                        "(entity_type, entity_id, archive_role, recorded_at) "
                        "VALUES (?, ?, ?, ?)",
                        (
                            record.entity_type,
                            record.entity_id,
                            record.archive_role,
                            recorded_at,
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ArchiveIntegrityError("archive_index_duplicate") from exc
                if record.archive_role == "retention_candidate":
                    candidate_count += 1
                else:
                    dependency_count += 1
                pending += 1
                if pending >= 1_000:
                    connection.commit()
                    pending = 0
            connection.commit()
            if (
                candidate_count != manifest.candidate_record_count
                or dependency_count != manifest.dependency_record_count
            ):
                raise ArchiveIntegrityError("archive_index_count_mismatch")
            return cls(temporary_directory, connection)
        except Exception:
            if "connection" in locals():
                connection.close()
            temporary_directory.cleanup()
            raise

    def candidate_batch(
        self,
        entity_type: str,
        *,
        last_recorded_at: datetime | None,
        last_entity_id: str | None,
        batch_size: int,
    ) -> tuple[ArchiveCandidateRef, ...]:
        if not 1 <= batch_size <= 5_000:
            raise ValueError("cleanup_batch_size_invalid")
        if (last_recorded_at is None) != (last_entity_id is None):
            raise ArchiveIntegrityError("cleanup_cursor_invalid")
        parameters: list[object] = [entity_type]
        cursor_clause = ""
        if last_recorded_at is not None and last_entity_id is not None:
            recorded_at = utc_datetime(last_recorded_at).isoformat(
                timespec="microseconds"
            )
            cursor_exists = self._connection.execute(
                "SELECT 1 FROM archive_records WHERE archive_role = "
                "'retention_candidate' AND entity_type = ? AND recorded_at = ? "
                "AND entity_id = ?",
                (entity_type, recorded_at, last_entity_id),
            ).fetchone()
            if cursor_exists is None:
                raise ArchiveIntegrityError("cleanup_cursor_invalid")
            cursor_clause = (
                " AND (recorded_at > ? OR "
                "(recorded_at = ? AND entity_id > ?))"
            )
            parameters.extend((recorded_at, recorded_at, last_entity_id))
        parameters.append(batch_size)
        rows = self._connection.execute(
            "SELECT recorded_at, entity_id FROM archive_records "
            "WHERE archive_role = 'retention_candidate' AND entity_type = ?"
            f"{cursor_clause} ORDER BY recorded_at, entity_id LIMIT ?",
            parameters,
        ).fetchall()
        return tuple(
            ArchiveCandidateRef(
                recorded_at=datetime.fromisoformat(str(row[0])),
                entity_id=str(row[1]),
            )
            for row in rows
        )

    def contains_all_dependencies(
        self,
        keys: Iterable[tuple[str, str]],
    ) -> bool:
        unique_keys = tuple(dict.fromkeys(keys))
        for entity_type, entity_id in unique_keys:
            row = self._connection.execute(
                "SELECT 1 FROM archive_records WHERE archive_role = 'dependency' "
                "AND entity_type = ? AND entity_id = ?",
                (entity_type, entity_id),
            ).fetchone()
            if row is None:
                return False
        return True

    def close(self) -> None:
        if self._closed:
            return
        self._connection.close()
        self._temporary_directory.cleanup()
        self._closed = True

    def __enter__(self) -> ArchiveMembershipIndex:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
