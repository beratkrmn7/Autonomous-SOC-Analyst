from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from contextlib import suppress
from datetime import datetime
import sys
from typing import TextIO

from sqlalchemy import Engine

from agent.application.cleanup import CleanupOperationResult, RetentionCleanupService
from agent.archive.schemas import validate_archive_id
from agent.archive.storage import ArchiveStore, LocalArchiveStore
from agent.config import Settings, get_settings
from agent.persistence.database import create_engine_factory, create_session_factory
from agent.persistence.unit_of_work import UnitOfWork


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Execute verified, bounded retention cleanup",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    execute = commands.add_parser("execute", help="Execute or resume cleanup")
    execute.add_argument("--archive-id")
    execute.add_argument("--confirm-archive-id")
    return parser


def _print_result(result: CleanupOperationResult, output: TextIO) -> None:
    print(f"Cleanup run ID: {result.cleanup_run_id}", file=output)
    print(f"Archive ID: {result.archive_id}", file=output)
    print(f"Status: {result.status}", file=output)
    print(f"Deleted records: {result.deleted_record_count}", file=output)
    print(f"Protected records: {result.protected_record_count}", file=output)
    print(f"Missing records: {result.missing_record_count}", file=output)
    print(f"Skipped records: {result.skipped_record_count}", file=output)
    print(
        "Completed entity phases: "
        + ",".join(result.completed_entity_phases),
        file=output,
    )
    print(f"Resumed: {'yes' if result.resumed else 'no'}", file=output)


def main(
    argv: Sequence[str] | None = None,
    *,
    settings: Settings | None = None,
    store: ArchiveStore | None = None,
    uow_factory: Callable[[], UnitOfWork] | None = None,
    clock: Callable[[], datetime] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    args = _build_parser().parse_args(argv)
    output = stdout or sys.stdout
    error_output = stderr or sys.stderr
    archive_id = args.archive_id
    confirmation = args.confirm_archive_id
    try:
        if (
            not isinstance(archive_id, str)
            or not isinstance(confirmation, str)
            or archive_id != confirmation
        ):
            raise ValueError("cleanup_confirmation_invalid")
        validate_archive_id(archive_id)
        validate_archive_id(confirmation)
    except (TypeError, ValueError):
        print("Retention cleanup failed safely.", file=error_output)
        return 2

    engine: Engine | None = None
    try:
        active_settings = settings or get_settings()
        active_store = store or LocalArchiveStore(
            active_settings.retention_archive_root
        )
        make_uow: Callable[[], UnitOfWork]
        if uow_factory is None:
            engine = create_engine_factory(active_settings)
            session_factory = create_session_factory(engine)

            def default_uow() -> UnitOfWork:
                return UnitOfWork(session_factory)

            make_uow = default_uow
        else:
            make_uow = uow_factory
        result = RetentionCleanupService(
            make_uow,
            active_store,
            active_settings,
            clock=clock,
        ).execute(archive_id)
        _print_result(result, output)
        return 0
    except Exception:
        print("Retention cleanup failed safely.", file=error_output)
        return 1
    finally:
        if engine is not None:
            with suppress(Exception):
                engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
