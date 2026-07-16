from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import TextIO

from sqlalchemy import Engine

from agent.application.retention import RetentionPlan, RetentionPlanner, RetentionPolicy
from agent.config import Settings, get_settings
from agent.persistence.database import create_engine_factory, create_session_factory
from agent.persistence.unit_of_work import UnitOfWork


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a read-only retention candidate plan",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="Plan candidates without modifying data (default)",
    )
    mode.add_argument(
        "--execute",
        action="store_true",
        help="Unsupported safety guard; no retention execution exists",
    )
    return parser


def _timestamp(value: datetime | None) -> str:
    return value.isoformat() if value is not None else "-"


def _print_plan(plan: RetentionPlan, output: TextIO) -> None:
    print("Retention dry-run plan", file=output)
    print(f"Policy version: {plan.policy_version}", file=output)
    print(f"Generated at: {_timestamp(plan.generated_at)}", file=output)
    for summary in plan.candidates:
        print(
            " ".join(
                (
                    f"entity={summary.entity_type}",
                    f"cutoff={_timestamp(summary.cutoff)}",
                    f"candidates={summary.candidate_count}",
                    f"oldest={_timestamp(summary.oldest_candidate_at)}",
                    f"newest={_timestamp(summary.newest_candidate_at)}",
                    "protected_active="
                    f"{summary.protected_by_active_relationship_count}",
                    f"protected_hold={summary.protected_by_legal_hold_count}",
                )
            ),
            file=output,
        )
    print(f"Total candidates: {plan.total_candidate_count}", file=output)
    print("No records were modified.", file=output)


def main(
    argv: Sequence[str] | None = None,
    *,
    settings: Settings | None = None,
    uow_factory: Callable[[], UnitOfWork] | None = None,
    clock: Callable[[], datetime] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    args = _build_parser().parse_args(argv)
    output = stdout or sys.stdout
    error_output = stderr or sys.stderr
    if args.execute:
        print("Retention execution is not supported; use --dry-run.", file=error_output)
        return 2

    active_settings = settings or get_settings()
    engine: Engine | None = None
    make_uow: Callable[[], UnitOfWork]
    if uow_factory is None:
        engine = create_engine_factory(active_settings)
        session_factory = create_session_factory(engine)

        def default_uow() -> UnitOfWork:
            return UnitOfWork(session_factory)

        make_uow = default_uow
    else:
        make_uow = uow_factory

    try:
        with make_uow() as uow:
            planner = RetentionPlanner(
                uow.retention,
                RetentionPolicy.from_settings(active_settings),
                clock=clock,
            )
            plan = planner.plan()
        _print_plan(plan, output)
        return 0
    except Exception:
        print("Retention planning failed safely.", file=error_output)
        return 1
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
