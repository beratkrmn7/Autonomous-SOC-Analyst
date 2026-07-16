from __future__ import annotations

from datetime import timedelta
import inspect as python_inspect

import pytest
from sqlalchemy import func, select

from agent.application.cleanup import CleanupOperationError
from agent.persistence.cleanup_repository import RetentionCleanupRepository
from agent.persistence.orm_models import (
    AuditEvent,
    RetentionCleanupProgress,
    RetentionCleanupRun,
)
from tests.archive.conftest import ARCHIVE_ID, NOW, make_environment
from tests.cleanup.conftest import CleanupEnvironment


def _audit_environment(tmp_path, count: int, *, cleanup_batch_size: int):
    archive = make_environment(tmp_path)
    archive.settings.retention_archive_batch_size = 1_000
    with archive.session_factory() as session:
        for start in range(0, count, 1_000):
            session.add_all(
                [
                    AuditEvent(
                        audit_event_id=f"audit-smoke-{index:05d}",
                        timestamp=NOW
                        - timedelta(days=500, seconds=count - index),
                        event_type="smoke-old",
                        action="old",
                    )
                    for index in range(start, min(start + 1_000, count))
                ]
            )
            session.commit()
    archive.service().create()
    settings = archive.settings.model_copy(
        update={
            "retention_cleanup_batch_size": cleanup_batch_size,
            "retention_cleanup_lease_seconds": 300,
        }
    )
    return CleanupEnvironment(archive, settings)


def test_ten_thousand_candidates_are_deleted_in_bounded_batches(tmp_path) -> None:
    environment = _audit_environment(tmp_path, 10_000, cleanup_batch_size=500)
    committed_batches: list[int] = []

    result = environment.service(
        batch_committed_hook=committed_batches.append
    ).execute(ARCHIVE_ID)

    assert result.deleted_record_count == 10_000
    assert result.protected_record_count == 0
    assert result.missing_record_count == 0
    assert len(committed_batches) == 20
    with environment.archive.session_factory() as session:
        assert session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.event_type == "smoke-old")
        ) == 0
        run = session.scalar(select(RetentionCleanupRun))
        assert run is not None
        progress = session.get(
            RetentionCleanupProgress,
            (run.cleanup_run_id, "audit_event"),
        )
        assert progress is not None
        assert progress.scanned_count == 10_000
        assert progress.deleted_count == 10_000
    source = python_inspect.getsource(RetentionCleanupRepository)
    assert ".offset(" not in source
    assert ".all(" not in source
    environment.archive.engine.dispose()


@pytest.mark.parametrize("raise_after_progress", [False, True])
def test_delete_and_progress_failure_roll_back_whole_batch(
    tmp_path,
    monkeypatch,
    raise_after_progress,
) -> None:
    environment = _audit_environment(tmp_path, 2, cleanup_batch_size=2)
    original = RetentionCleanupRepository.apply_batch

    def fail(self, *args, **kwargs):
        if raise_after_progress:
            original(self, *args, **kwargs)
        raise RuntimeError("private database exception")

    monkeypatch.setattr(RetentionCleanupRepository, "apply_batch", fail)
    with pytest.raises(CleanupOperationError):
        environment.service().execute(ARCHIVE_ID)

    with environment.archive.session_factory() as session:
        assert session.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.event_type == "smoke-old")
        ) == 2
        run = session.scalar(select(RetentionCleanupRun))
        assert run is not None
        assert run.status == "failed"
        assert run.deleted_record_count == 0
        progress = session.get(
            RetentionCleanupProgress,
            (run.cleanup_run_id, "audit_event"),
        )
        assert progress is not None
        assert progress.scanned_count == 0
        assert progress.deleted_count == 0
        assert progress.last_entity_id is None
    environment.archive.engine.dispose()
