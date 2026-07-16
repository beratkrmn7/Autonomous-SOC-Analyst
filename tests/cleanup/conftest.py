from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from agent.application.cleanup import RetentionCleanupService
from agent.config import Settings
from agent.persistence.unit_of_work import UnitOfWork
from tests.archive.conftest import (
    ARCHIVE_ID,
    NOW,
    ArchiveEnvironment,
    make_environment,
    seed_archive_graph,
)


@dataclass(frozen=True)
class CleanupEnvironment:
    archive: ArchiveEnvironment
    settings: Settings

    def service(self, **kwargs) -> RetentionCleanupService:
        clock = kwargs.pop("clock", lambda: NOW)
        return RetentionCleanupService(
            lambda: UnitOfWork(self.archive.session_factory),
            self.archive.store,
            self.settings,
            clock=clock,
            cleanup_run_id_factory=lambda: (
                "CLN-0123456789abcdef0123456789abcdef"
            ),
            **kwargs,
        )


def make_cleanup_environment(
    root: Path,
    *,
    seed_graph: bool = True,
    cleanup_batch_size: int = 2,
) -> CleanupEnvironment:
    archive = make_environment(root)
    settings = archive.settings.model_copy(
        update={
            "retention_cleanup_batch_size": cleanup_batch_size,
            "retention_cleanup_lease_seconds": 300,
        }
    )
    if seed_graph:
        seed_archive_graph(archive)
    archive.service().create()
    return CleanupEnvironment(archive, settings)


@pytest.fixture
def cleanup_env(tmp_path) -> CleanupEnvironment:
    environment = make_cleanup_environment(tmp_path)
    yield environment
    environment.archive.engine.dispose()


__all__ = [
    "ARCHIVE_ID",
    "NOW",
    "CleanupEnvironment",
    "make_cleanup_environment",
]
