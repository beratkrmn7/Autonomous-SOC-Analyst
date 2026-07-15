import json
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import urlsplit

import httpx
import jwt

if TYPE_CHECKING:
    from agent.config import Settings


MAX_METADATA_BYTES = 64 * 1024
MAX_JWKS_BYTES = 1024 * 1024
MAX_JWKS_KEYS = 100
MAX_KEY_ID_LENGTH = 256


class OidcProviderError(Exception):
    """Safe internal failure category for discovery and JWKS operations."""


@dataclass(frozen=True)
class OidcConfiguration:
    issuer: str
    audience: str
    discovery_url: str
    allowed_algorithms: tuple[str, ...]
    clock_skew_seconds: int
    http_timeout_seconds: float
    metadata_cache_ttl_seconds: int
    jwks_cache_ttl_seconds: int
    token_use_claim: str
    access_token_use_value: str
    require_access_token_indicator: bool
    roles_claim: str
    role_mapping: tuple[tuple[str, str], ...]
    display_name_claim: str
    require_https: bool

    @classmethod
    def from_settings(cls, settings: "Settings") -> "OidcConfiguration":
        if (
            settings.oidc_issuer is None
            or settings.oidc_audience is None
            or settings.oidc_discovery_url is None
        ):
            raise ValueError("oidc_configuration_incomplete")
        return cls(
            issuer=settings.oidc_issuer,
            audience=settings.oidc_audience,
            discovery_url=settings.oidc_discovery_url,
            allowed_algorithms=tuple(settings.oidc_allowed_algorithms),
            clock_skew_seconds=settings.oidc_clock_skew_seconds,
            http_timeout_seconds=settings.oidc_http_timeout_seconds,
            metadata_cache_ttl_seconds=(
                settings.oidc_metadata_cache_ttl_seconds
            ),
            jwks_cache_ttl_seconds=settings.oidc_jwks_cache_ttl_seconds,
            token_use_claim=settings.oidc_token_use_claim,
            access_token_use_value=settings.oidc_access_token_use_value,
            require_access_token_indicator=(
                settings.oidc_require_access_token_indicator
            ),
            roles_claim=settings.oidc_roles_claim,
            role_mapping=tuple(sorted(settings.oidc_role_mapping.items())),
            display_name_claim=settings.oidc_display_name_claim,
            require_https=settings.oidc_require_https,
        )


class OidcHttpClient(Protocol):
    def get_json(
        self,
        url: str,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> Mapping[str, Any]: ...


class HttpxOidcHttpClient:
    """Fetches bounded OIDC JSON documents without following redirects."""

    def get_json(
        self,
        url: str,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> Mapping[str, Any]:
        try:
            timeout = httpx.Timeout(timeout_seconds)
            with httpx.Client(
                timeout=timeout,
                follow_redirects=False,
            ) as client:
                with client.stream(
                    "GET",
                    url,
                    headers={"Accept": "application/json"},
                ) as response:
                    response.raise_for_status()
                    content_length = response.headers.get("Content-Length")
                    if (
                        content_length is not None
                        and int(content_length) > max_response_bytes
                    ):
                        raise OidcProviderError("oidc_document_too_large")

                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) > max_response_bytes:
                            raise OidcProviderError("oidc_document_too_large")

            document = json.loads(body.decode("utf-8"))
        except OidcProviderError:
            raise
        except (
            httpx.HTTPError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ):
            raise OidcProviderError("oidc_provider_unavailable") from None

        if not isinstance(document, dict):
            raise OidcProviderError("oidc_document_invalid")
        return document


@dataclass(frozen=True)
class OidcMetadata:
    issuer: str
    jwks_uri: str


def _validate_provider_url(url: str, *, require_https: bool) -> str:
    parsed = urlsplit(url)
    schemes = {"https"} if require_https else {"http", "https"}
    if (
        parsed.scheme.lower() not in schemes
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise OidcProviderError("oidc_provider_url_invalid")
    return url


class OidcMetadataProvider:
    def __init__(
        self,
        configuration: OidcConfiguration,
        http_client: OidcHttpClient,
        *,
        monotonic=time.monotonic,
    ):
        self.configuration = configuration
        self.http_client = http_client
        self.monotonic = monotonic
        self._lock = threading.RLock()
        self._cached_metadata: OidcMetadata | None = None
        self._cache_expires_at = 0.0

    def get_metadata(self, *, force_refresh: bool = False) -> OidcMetadata:
        with self._lock:
            now = self.monotonic()
            if (
                not force_refresh
                and self._cached_metadata is not None
                and now < self._cache_expires_at
            ):
                return self._cached_metadata

            document = self.http_client.get_json(
                self.configuration.discovery_url,
                timeout_seconds=self.configuration.http_timeout_seconds,
                max_response_bytes=MAX_METADATA_BYTES,
            )
            issuer = document.get("issuer")
            jwks_uri = document.get("jwks_uri")
            if (
                not isinstance(issuer, str)
                or issuer != self.configuration.issuer
                or not isinstance(jwks_uri, str)
            ):
                raise OidcProviderError("oidc_metadata_invalid")

            metadata = OidcMetadata(
                issuer=issuer,
                jwks_uri=_validate_provider_url(
                    jwks_uri,
                    require_https=self.configuration.require_https,
                ),
            )
            self._cached_metadata = metadata
            self._cache_expires_at = (
                now + self.configuration.metadata_cache_ttl_seconds
            )
            return metadata

    def check_available(self) -> None:
        self.get_metadata()


class SigningKeyResolver(Protocol):
    def resolve(self, key_id: str, algorithm: str) -> Any: ...

    def check_available(self) -> None: ...


class OidcSigningKeyResolver:
    def __init__(
        self,
        configuration: OidcConfiguration,
        metadata_provider: OidcMetadataProvider,
        http_client: OidcHttpClient,
        *,
        monotonic=time.monotonic,
    ):
        self.configuration = configuration
        self.metadata_provider = metadata_provider
        self.http_client = http_client
        self.monotonic = monotonic
        self._lock = threading.RLock()
        self._cached_keys: dict[str, dict[str, Any]] | None = None
        self._cache_expires_at = 0.0

    @staticmethod
    def _parse_jwks(document: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
        keys = document.get("keys")
        if (
            not isinstance(keys, list)
            or not keys
            or len(keys) > MAX_JWKS_KEYS
        ):
            raise OidcProviderError("oidc_jwks_invalid")

        parsed_keys: dict[str, dict[str, Any]] = {}
        private_fields = {"d", "p", "q", "dp", "dq", "qi", "k"}
        for raw_key in keys:
            if not isinstance(raw_key, dict):
                raise OidcProviderError("oidc_jwks_invalid")
            if private_fields.intersection(raw_key):
                raise OidcProviderError("oidc_jwks_invalid")

            key_use = raw_key.get("use")
            if key_use is not None and key_use != "sig":
                continue
            key_ops = raw_key.get("key_ops")
            if key_ops is not None:
                if not isinstance(key_ops, list) or "verify" not in key_ops:
                    continue

            key_id = raw_key.get("kid")
            key_type = raw_key.get("kty")
            declared_algorithm = raw_key.get("alg")
            if (
                not isinstance(key_id, str)
                or not key_id
                or len(key_id) > MAX_KEY_ID_LENGTH
                or key_id in parsed_keys
                or key_type not in ("RSA", "EC")
                or (
                    declared_algorithm is not None
                    and not isinstance(declared_algorithm, str)
                )
            ):
                raise OidcProviderError("oidc_jwks_invalid")
            if key_type == "RSA" and not {
                "n",
                "e",
            }.issubset(raw_key):
                raise OidcProviderError("oidc_jwks_invalid")
            if key_type == "EC" and not {
                "crv",
                "x",
                "y",
            }.issubset(raw_key):
                raise OidcProviderError("oidc_jwks_invalid")
            parsed_keys[key_id] = dict(raw_key)

        if not parsed_keys:
            raise OidcProviderError("oidc_jwks_invalid")
        return parsed_keys

    def _get_keys(self, *, force_refresh: bool = False) -> dict[str, dict[str, Any]]:
        with self._lock:
            now = self.monotonic()
            if (
                not force_refresh
                and self._cached_keys is not None
                and now < self._cache_expires_at
            ):
                return self._cached_keys

            metadata = self.metadata_provider.get_metadata()
            document = self.http_client.get_json(
                metadata.jwks_uri,
                timeout_seconds=self.configuration.http_timeout_seconds,
                max_response_bytes=MAX_JWKS_BYTES,
            )
            parsed_keys = self._parse_jwks(document)
            self._ensure_usable_signing_key(parsed_keys)
            self._cached_keys = parsed_keys
            self._cache_expires_at = (
                now + self.configuration.jwks_cache_ttl_seconds
            )
            return parsed_keys

    def _ensure_usable_signing_key(
        self,
        keys: Mapping[str, Mapping[str, Any]],
    ) -> None:
        for raw_key in keys.values():
            for algorithm in self.configuration.allowed_algorithms:
                expected_key_type = (
                    "EC" if algorithm.startswith("ES") else "RSA"
                )
                if raw_key.get("kty") != expected_key_type:
                    continue
                declared_algorithm = raw_key.get("alg")
                if (
                    declared_algorithm is not None
                    and declared_algorithm != algorithm
                ):
                    continue
                try:
                    jwt.PyJWK.from_dict(
                        dict(raw_key), algorithm=algorithm
                    ).key
                except (jwt.PyJWTError, ValueError, TypeError):
                    continue
                return
        raise OidcProviderError("oidc_signing_key_invalid")

    def _select_key(
        self,
        keys: Mapping[str, Mapping[str, Any]],
        key_id: str,
        algorithm: str,
    ) -> Any | None:
        raw_key = keys.get(key_id)
        if raw_key is None:
            return None

        expected_key_type = "EC" if algorithm.startswith("ES") else "RSA"
        if raw_key.get("kty") != expected_key_type:
            raise OidcProviderError("oidc_signing_key_invalid")
        declared_algorithm = raw_key.get("alg")
        if declared_algorithm is not None and declared_algorithm != algorithm:
            raise OidcProviderError("oidc_signing_key_invalid")
        try:
            return jwt.PyJWK.from_dict(
                dict(raw_key), algorithm=algorithm
            ).key
        except (jwt.PyJWTError, ValueError, TypeError):
            raise OidcProviderError("oidc_signing_key_invalid") from None

    def resolve(self, key_id: str, algorithm: str) -> Any:
        if (
            not key_id
            or len(key_id) > MAX_KEY_ID_LENGTH
            or algorithm not in self.configuration.allowed_algorithms
        ):
            raise OidcProviderError("oidc_signing_key_invalid")

        selected = self._select_key(self._get_keys(), key_id, algorithm)
        if selected is not None:
            return selected

        selected = self._select_key(
            self._get_keys(force_refresh=True),
            key_id,
            algorithm,
        )
        if selected is None:
            raise OidcProviderError("oidc_signing_key_unknown")
        return selected

    def check_available(self) -> None:
        self.metadata_provider.check_available()
        self._get_keys()
