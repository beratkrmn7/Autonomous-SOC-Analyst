from collections.abc import Sequence
from ipaddress import ip_address
from typing import Any

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from agent.config import Settings


CORS_ALLOWED_METHODS = ("GET", "POST", "PATCH", "OPTIONS")
CORS_ALLOWED_HEADERS = (
    "Accept",
    "Authorization",
    "Content-Type",
    "If-Match",
    "X-Request-ID",
)


def _header_values(scope: Scope, name: bytes) -> list[str]:
    values: list[str] = []
    for raw_name, raw_value in scope.get("headers", []):
        if raw_name.lower() != name:
            continue
        try:
            values.append(raw_value.decode("ascii"))
        except UnicodeDecodeError:
            return []
    return values


def _hostname_from_host_header(value: str) -> str | None:
    if not value or any(ord(character) < 33 for character in value):
        return None

    if value.startswith("["):
        closing_bracket = value.find("]")
        if closing_bracket < 0:
            return None
        hostname = value[1:closing_bracket]
        suffix = value[closing_bracket + 1:]
        if suffix and (not suffix.startswith(":") or not suffix[1:].isdigit()):
            return None
        if suffix and not 0 < int(suffix[1:]) <= 65535:
            return None
        try:
            return str(ip_address(hostname))
        except ValueError:
            return None

    if value.count(":") > 1:
        return None
    hostname, separator, port = value.rpartition(":")
    if separator:
        if (
            not hostname
            or not port.isdigit()
            or not 0 < int(port) <= 65535
        ):
            return None
    else:
        hostname = value
    return hostname.lower().rstrip(".")


def _host_is_allowed(hostname: str, allowed_hosts: Sequence[str]) -> bool:
    for pattern in allowed_hosts:
        if pattern == "*" or hostname == pattern:
            return True
        if pattern.startswith("*.") and hostname.endswith(pattern[1:]):
            return True
    return False


class DeploymentBoundaryMiddleware:
    """Enforces trusted Host and HTTPS policy before API request handling."""

    def __init__(self, app: ASGIApp, settings: Settings):
        self.app = app
        self.allowed_hosts = tuple(settings.trusted_hosts)
        self.https_required = settings.https_required
        self.forwarded_headers_enabled = settings.forwarded_headers_enabled
        self.trusted_proxy_ips = frozenset(settings.trusted_proxy_ips)

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        host_values = _header_values(scope, b"host")
        hostname = (
            _hostname_from_host_header(host_values[0])
            if len(host_values) == 1
            else None
        )
        if hostname is None or not _host_is_allowed(
            hostname,
            self.allowed_hosts,
        ):
            await self._send_error(
                scope,
                receive,
                send,
                status_code=400,
                code="invalid_host",
                message="The request host is not allowed.",
            )
            return

        scheme = self._request_scheme(scope)
        if scheme is None:
            await self._send_error(
                scope,
                receive,
                send,
                status_code=400,
                code="forwarded_scheme_invalid",
                message="The forwarded request scheme is invalid.",
            )
            return
        if self.https_required and scheme != "https":
            await self._send_error(
                scope,
                receive,
                send,
                status_code=400,
                code="https_required",
                message="HTTPS is required.",
            )
            return

        await self.app(scope, receive, send)

    def _request_scheme(self, scope: Scope) -> str | None:
        scheme = str(scope.get("scheme", "http")).lower()
        if not self.forwarded_headers_enabled:
            return scheme

        client = scope.get("client")
        client_host = client[0] if client is not None else None
        if client_host not in self.trusted_proxy_ips:
            return scheme

        forwarded_proto = _header_values(scope, b"x-forwarded-proto")
        if not forwarded_proto:
            return scheme
        if len(forwarded_proto) != 1:
            return None
        normalized = forwarded_proto[0].lower()
        if normalized not in {"http", "https"}:
            return None
        return normalized

    @staticmethod
    async def _send_error(
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        status_code: int,
        code: str,
        message: str,
    ) -> None:
        response = JSONResponse(
            status_code=status_code,
            content={"code": code, "message": message},
        )
        await response(scope, receive, send)


def docs_urls(settings: Settings) -> dict[str, Any]:
    if settings.api_docs_enabled:
        return {
            "docs_url": "/docs",
            "redoc_url": "/redoc",
            "openapi_url": "/openapi.json",
        }
    return {"docs_url": None, "redoc_url": None, "openapi_url": None}
