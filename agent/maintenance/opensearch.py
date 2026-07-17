from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import asdict
import json
import sys
from typing import TextIO

from agent.config import Settings, get_settings
from agent.opensearch.client import OpenSearchClientFactory
from agent.opensearch.manager import (
    OpenSearchFoundationManager,
    OpenSearchHealthService,
)
from agent.opensearch.models import (
    OpenSearchFoundationError,
    OpenSearchGateway,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect or safely initialize the OpenSearch foundation",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check", help="Check cluster and foundation health")
    commands.add_parser("plan", help="Print a read-only bootstrap plan")
    commands.add_parser(
        "bootstrap",
        help="Create only missing foundation indices and aliases",
    )
    return parser


def _write_json(value: object, output: TextIO) -> None:
    print(
        json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True),
        file=output,
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    settings: Settings | None = None,
    gateway_factory: Callable[[], OpenSearchGateway] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    args = _parser().parse_args(argv)
    output = stdout or sys.stdout
    error_output = stderr or sys.stderr
    gateway: OpenSearchGateway | None = None
    configuration_ready = False
    try:
        active_settings = settings or get_settings()
        make_gateway: Callable[[], OpenSearchGateway]
        if gateway_factory is None:
            client_factory = OpenSearchClientFactory(active_settings)
            make_gateway = client_factory.create
        else:
            make_gateway = gateway_factory
        configuration_ready = True

        if args.command == "check":
            health_result = OpenSearchHealthService(
                active_settings,
                make_gateway,
            ).check()
            _write_json(asdict(health_result), output)
            return (
                0
                if health_result.status in {"disabled", "healthy", "degraded"}
                else 1
            )

        if not active_settings.opensearch_enabled:
            _write_json({"error_code": "opensearch_disabled"}, error_output)
            return 2

        gateway = make_gateway()
        manager = OpenSearchFoundationManager(active_settings, gateway)
        if args.command == "plan":
            plan = manager.plan()
            _write_json(asdict(plan), output)
            return 0
        bootstrap_result = manager.bootstrap()
        _write_json(asdict(bootstrap_result), output)
        return 0
    except OpenSearchFoundationError as exc:
        error_code = (
            exc.code
            if configuration_ready
            else "opensearch_configuration_invalid"
        )
        _write_json({"error_code": error_code}, error_output)
        return 2
    except Exception:
        _write_json(
            {
                "error_code": (
                    "opensearch_maintenance_failed"
                    if configuration_ready
                    else "opensearch_configuration_invalid"
                )
            },
            error_output,
        )
        return 1
    finally:
        if gateway is not None:
            with suppress(Exception):
                gateway.close()


if __name__ == "__main__":
    raise SystemExit(main())
