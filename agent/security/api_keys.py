import argparse
import datetime
from collections.abc import Callable, Sequence

from agent.application.authentication import (
    ApiKeyAuthenticationService,
    CredentialNotFoundError,
)
from agent.persistence.unit_of_work import UnitOfWork


def _optional_timestamp(value: datetime.datetime | None) -> str:
    return value.isoformat() if value is not None else "-"


def _parse_expiry(value: str) -> datetime.datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Administer SOC API credentials")
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create", help="Create an API credential")
    create.add_argument("--name", required=True)
    create.add_argument("--description")
    create.add_argument(
        "--expires-at",
        type=_parse_expiry,
        help="UTC ISO-8601 expiration timestamp",
    )

    commands.add_parser("list", help="List API credentials without secrets")

    revoke = commands.add_parser("revoke", help="Revoke an API credential")
    revoke.add_argument("credential_id")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    uow_factory: Callable[[], UnitOfWork] | None = None,
) -> int:
    args = _build_parser().parse_args(argv)
    make_uow = uow_factory or UnitOfWork
    service = ApiKeyAuthenticationService(make_uow())

    try:
        if args.command == "create":
            generated = service.generate_credential(
                name=args.name,
                description=args.description,
                expires_at=args.expires_at,
            )
            credential = generated.credential
            print(f"Credential ID: {credential.credential_id}")
            print(f"Name: {credential.name}")
            print(f"Prefix: {credential.key_prefix}")
            print(f"Status: {credential.status}")
            print(f"Expires at: {_optional_timestamp(credential.expires_at)}")
            print(f"API key (shown once): {generated.api_key}")
            return 0

        if args.command == "list":
            print(
                "credential_id\tname\tprefix\tstatus\tcreated_at\t"
                "expires_at\tlast_used_at"
            )
            for credential in service.list_credentials():
                print("\t".join((
                    credential.credential_id,
                    credential.name,
                    credential.key_prefix,
                    credential.status,
                    credential.created_at.isoformat(),
                    _optional_timestamp(credential.expires_at),
                    _optional_timestamp(credential.last_used_at),
                )))
            return 0

        credential = service.revoke_credential(args.credential_id)
        print(f"Credential ID: {credential.credential_id}")
        print(f"Status: {credential.status}")
        return 0
    except CredentialNotFoundError:
        print("credential_not_found")
        return 1
    except (RuntimeError, ValueError):
        print("credential_operation_failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
