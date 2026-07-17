from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path
import re
from typing import Literal, Optional
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from agent.ingestion.limits import DEFAULT_MAX_UPLOAD_BYTES, IngestionLimits
from agent.security.authorization import Role


OIDC_ASYMMETRIC_ALGORITHMS = frozenset({
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
})
TRUSTED_HOST_PATTERN = re.compile(
    r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
RATE_LIMIT_PREFIX_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
OPENSEARCH_INDEX_PREFIX_PATTERN = re.compile(
    r"^[a-z0-9]+(?:-[a-z0-9]+)*$"
)
OPENSEARCH_SCHEMA_VERSION_PATTERN = re.compile(r"^v[1-9][0-9]{0,5}$")
DEFAULT_MAX_REQUEST_BODY_BYTES = 52 * 1024 * 1024


def _validate_oidc_url(value: str, *, require_https: bool, field: str) -> str:
    normalized = value.strip()
    parsed = urlsplit(normalized)
    allowed_schemes = {"https"} if require_https else {"http", "https"}
    if (
        parsed.scheme.lower() not in allowed_schemes
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError(f"{field}_invalid")
    return normalized


def _normalize_trusted_host(value: str) -> str:
    normalized = value.strip().lower()
    if normalized == "*":
        return normalized
    try:
        return str(ip_address(normalized))
    except ValueError:
        pass
    if (
        len(normalized) > 253
        or not TRUSTED_HOST_PATTERN.fullmatch(normalized)
    ):
        raise ValueError("trusted_hosts_invalid")
    return normalized


def _normalize_cors_origin(value: str) -> str:
    normalized = value.strip()
    if normalized == "*":
        return normalized
    parsed = urlsplit(normalized)
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("cors_allowed_origins_invalid")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _normalize_opensearch_host(value: str) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > 2048:
        raise ValueError("opensearch_hosts_invalid")
    parsed = urlsplit(normalized)
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("opensearch_hosts_invalid")
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("opensearch_hosts_invalid") from None
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    effective_port = port or (443 if parsed.scheme.lower() == "https" else 80)
    return f"{parsed.scheme.lower()}://{host}:{effective_port}"


class Settings(BaseSettings):
    app_env: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"
    security_headers_enabled: bool = True
    trusted_hosts: list[str] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1", "testserver"]
    )
    cors_allowed_origins: list[str] = Field(default_factory=list)
    cors_allow_credentials: bool = False
    forwarded_headers_enabled: bool = False
    trusted_proxy_ips: list[str] = Field(default_factory=list)
    https_required: bool = False
    api_docs_enabled: bool | None = None
    max_request_body_bytes: int = Field(
        default=DEFAULT_MAX_REQUEST_BODY_BYTES,
        ge=1024,
        le=1024 * 1024 * 1024,
    )
    max_upload_bytes: int = Field(
        default=DEFAULT_MAX_UPLOAD_BYTES,
        ge=1024,
        le=1024 * 1024 * 1024,
    )
    hsts_max_age_seconds: int = Field(default=86400, ge=0, le=31536000)
    auth_mode: Literal["disabled", "api_key", "oidc", "hybrid"] = "disabled"
    oidc_issuer: Optional[str] = None
    oidc_audience: Optional[str] = None
    oidc_discovery_url: Optional[str] = None
    oidc_allowed_algorithms: list[str] = Field(default_factory=lambda: ["RS256"])
    oidc_clock_skew_seconds: int = Field(default=30, ge=0, le=300)
    oidc_http_timeout_seconds: float = Field(default=5, gt=0, le=30)
    oidc_metadata_cache_ttl_seconds: int = Field(default=300, ge=1, le=86400)
    oidc_jwks_cache_ttl_seconds: int = Field(default=300, ge=1, le=86400)
    oidc_token_use_claim: str = Field(
        default="token_use", min_length=1, max_length=128
    )
    oidc_access_token_use_value: str = Field(
        default="access", min_length=1, max_length=128
    )
    oidc_require_access_token_indicator: bool = True
    oidc_roles_claim: str = Field(default="roles", min_length=1, max_length=128)
    oidc_role_mapping: dict[str, str] = Field(default_factory=dict)
    oidc_display_name_claim: str = Field(
        default="preferred_username", min_length=1, max_length=128
    )
    oidc_require_https: bool = True

    # Phase 5C.4B: transient request-rate and abuse protection.
    rate_limiting_enabled: bool = True
    rate_limit_backend: Literal["memory", "redis"] = "memory"
    rate_limit_redis_url: str = "redis://localhost:6379/1"
    rate_limit_key_secret: SecretStr | None = None
    rate_limit_general_requests: int = Field(default=120, ge=1, le=1_000_000)
    rate_limit_general_window_seconds: int = Field(default=60, ge=1, le=86400)
    rate_limit_auth_failures: int = Field(default=10, ge=1, le=1_000_000)
    rate_limit_auth_failure_window_seconds: int = Field(default=60, ge=1, le=86400)
    rate_limit_job_submissions: int = Field(default=5, ge=1, le=1_000_000)
    rate_limit_job_submission_window_seconds: int = Field(default=60, ge=1, le=86400)
    rate_limit_mutations: int = Field(default=30, ge=1, le=1_000_000)
    rate_limit_mutation_window_seconds: int = Field(default=60, ge=1, le=86400)
    rate_limit_reads: int = Field(default=120, ge=1, le=1_000_000)
    rate_limit_read_window_seconds: int = Field(default=60, ge=1, le=86400)
    rate_limit_prefix: str = "soc-rate-limit"
    rate_limit_fail_closed: bool = True

    # Phase 5D.1: structured database search.
    search_cursor_secret: SecretStr | None = None
    search_default_page_size: int = Field(default=50, ge=1, le=200)
    search_max_page_size: int = Field(default=200, ge=1, le=200)

    # Phase 5D.2A: retention planning. Execution is intentionally unsupported.
    retention_policy_version: str = Field(
        default="v1",
        min_length=1,
        max_length=32,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )
    retention_canonical_event_days: int = Field(default=30, ge=1, le=36_500)
    retention_detection_signal_days: int = Field(default=90, ge=1, le=36_500)
    retention_completed_job_days: int = Field(default=90, ge=1, le=36_500)
    retention_terminal_incident_days: int = Field(default=365, ge=1, le=36_500)
    retention_audit_event_days: int = Field(default=365, ge=1, le=36_500)

    # Phase 5D.2B: non-destructive operational retention archives.
    retention_archive_backend: Literal["local"] = "local"
    retention_archive_root: str = Field(
        default="./var/retention-archives",
        min_length=1,
        max_length=4096,
    )
    retention_archive_batch_size: int = Field(default=1000, ge=1, le=10_000)
    retention_archive_schema_version: Literal[
        "retention-archive/v1"
    ] = "retention-archive/v1"

    # Phase 5D.2C: verified, bounded retention cleanup.
    retention_cleanup_batch_size: int = Field(default=500, ge=1, le=5_000)
    retention_cleanup_lease_seconds: int = Field(default=300, ge=30, le=86_400)

    # Phase 5D.3A: optional secondary OpenSearch foundation.
    opensearch_enabled: bool = False
    opensearch_required: bool = False
    opensearch_hosts: list[str] = Field(
        default_factory=lambda: ["https://localhost:9200"]
    )
    opensearch_username: str | None = None
    opensearch_password: SecretStr | None = None
    opensearch_ca_certs: str | None = None
    opensearch_client_cert: str | None = None
    opensearch_client_key: str | None = None
    opensearch_verify_certs: bool = True
    opensearch_connect_timeout_seconds: float = Field(default=3, gt=0, le=30)
    opensearch_read_timeout_seconds: float = Field(default=10, gt=0, le=120)
    opensearch_max_retries: int = Field(default=2, ge=0, le=5)
    opensearch_pool_maxsize: int = Field(default=10, ge=1, le=100)
    opensearch_index_prefix: str = Field(default="agentic-soc", min_length=1, max_length=48)
    opensearch_schema_version: str = Field(default="v1", min_length=2, max_length=8)
    opensearch_number_of_shards: int = Field(default=1, ge=1, le=20)
    opensearch_number_of_replicas: int = Field(default=0, ge=0, le=20)
    opensearch_mapping_total_fields_limit: int = Field(default=256, ge=32, le=1_000)
    opensearch_bootstrap_on_startup: bool = False
    opensearch_outbox_max_payload_bytes: int = Field(default=65536, ge=1024, le=10_485_760)

    llm_enabled: bool = True
    llm_provider: Literal["groq"] = "groq"
    llm_model: str = "llama-3.3-70b-versatile"
    groq_api_key: Optional[SecretStr] = None
    
    pipeline_version: str = "1.0.0"

    llm_parser_fallback_enabled: bool = False

    ingestion: IngestionLimits = Field(default_factory=IngestionLimits)

    # Phase 4: Secure Agentic Triage Settings
    max_agent_iterations: int = Field(default=5, ge=1, le=20)
    max_search_calls: int = Field(default=3, ge=0, le=20)
    max_search_results: int = Field(default=10, ge=1, le=100)
    max_search_query_chars: int = Field(default=100, ge=1, le=1000)
    max_prompt_tokens: int = Field(default=30000, gt=0)
    max_completion_tokens: int = Field(default=2000, gt=0)
    max_context_events: int = Field(default=50, ge=0, le=500)
    max_candidate_evidence: int = Field(default=20, ge=0, le=200)
    max_event_preview_chars: int = Field(default=1000, ge=100, le=5000)
    triage_timeout_seconds: int = Field(default=120, gt=0)
    llm_max_retries: int = Field(default=3, ge=0, le=10)
    llm_retry_base_seconds: float = Field(default=1.0, gt=0)
    llm_retry_max_seconds: float = Field(default=10.0, gt=0)
    circuit_breaker_failure_threshold: int = Field(default=5, ge=1)
    circuit_breaker_reset_seconds: int = Field(default=60, ge=1)
    triage_cache_enabled: bool = True
    triage_cache_ttl_seconds: int = Field(default=3600, ge=0)
    triage_prompt_version: str = "1.0.0"
    triage_schema_version: str = "1.0.0"

    # Phase 5A: Persistence Settings
    database_url: str = "sqlite:///soc_triage.db"
    database_echo: bool = False
    database_pool_size: int = Field(default=5, ge=1)
    database_max_overflow: int = Field(default=10, ge=0)
    database_pool_timeout: int = Field(default=30, ge=1)
    
    # Phase 5B: Task Queue Settings
    task_queue_backend: Literal["database", "celery"] = "database"
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_queue_name: str = "soc-analysis"
    staging_dir: str = "/tmp/agent_staging"
    
    job_max_attempts: int = Field(default=3, ge=1)
    job_retry_base_seconds: int = Field(default=5, ge=1)
    job_retry_max_seconds: int = Field(default=60, ge=1)
    job_processing_lease_seconds: int = Field(default=300, ge=1)
    
    worker_heartbeat_interval_seconds: int = Field(default=15, ge=1)
    worker_heartbeat_stale_seconds: int = Field(default=60, ge=1)

    @model_validator(mode="after")
    def validate_settings(self) -> "Settings":
        if not self.retention_archive_root.strip():
            raise ValueError("retention_archive_root_invalid")
        archive_root = Path(self.retention_archive_root).resolve(strict=False)
        staging_root = Path(self.staging_dir).resolve(strict=False)
        if (
            archive_root == staging_root
            or archive_root.is_relative_to(staging_root)
            or staging_root.is_relative_to(archive_root)
        ):
            raise ValueError("retention_archive_root_conflicts_with_staging")

        if not self.trusted_hosts or len(self.trusted_hosts) > 100:
            raise ValueError("trusted_hosts_invalid")
        self.trusted_hosts = list(dict.fromkeys(
            _normalize_trusted_host(host) for host in self.trusted_hosts
        ))

        if len(self.cors_allowed_origins) > 100:
            raise ValueError("cors_allowed_origins_invalid")
        self.cors_allowed_origins = list(dict.fromkeys(
            _normalize_cors_origin(origin)
            for origin in self.cors_allowed_origins
        ))
        if "*" in self.cors_allowed_origins and self.cors_allow_credentials:
            raise ValueError("cors_wildcard_credentials_forbidden")

        normalized_proxy_ips: list[str] = []
        for proxy_ip in self.trusted_proxy_ips:
            try:
                normalized_proxy_ips.append(str(ip_address(proxy_ip.strip())))
            except ValueError:
                raise ValueError("trusted_proxy_ips_invalid") from None
        self.trusted_proxy_ips = list(dict.fromkeys(normalized_proxy_ips))
        if self.forwarded_headers_enabled and not self.trusted_proxy_ips:
            raise ValueError("trusted_proxy_ips_required")

        if self.max_request_body_bytes < self.max_upload_bytes:
            raise ValueError("request_body_limit_below_upload_limit")
        self.ingestion.MAX_UPLOAD_BYTES = self.max_upload_bytes

        if self.api_docs_enabled is None:
            self.api_docs_enabled = self.app_env != "production"

        self.rate_limit_prefix = self.rate_limit_prefix.strip()
        if not RATE_LIMIT_PREFIX_PATTERN.fullmatch(self.rate_limit_prefix):
            raise ValueError("rate_limit_prefix_invalid")
        parsed_rate_limit_url = urlsplit(self.rate_limit_redis_url)
        if (
            parsed_rate_limit_url.scheme.lower() not in {"redis", "rediss"}
            or not parsed_rate_limit_url.hostname
            or parsed_rate_limit_url.fragment
        ):
            raise ValueError("rate_limit_redis_url_invalid")
        if self.rate_limit_key_secret is not None:
            secret_value = self.rate_limit_key_secret.get_secret_value()
            if len(secret_value.encode("utf-8")) < 32:
                raise ValueError("rate_limit_key_secret_too_short")
        if self.search_default_page_size > self.search_max_page_size:
            raise ValueError("search_default_page_size_exceeds_maximum")
        if self.search_cursor_secret is not None:
            cursor_secret = self.search_cursor_secret.get_secret_value()
            if len(cursor_secret.encode("utf-8")) < 32:
                raise ValueError("search_cursor_secret_too_short")

        if len(self.opensearch_hosts) > 10:
            raise ValueError("opensearch_hosts_invalid")
        self.opensearch_hosts = list(dict.fromkeys(
            _normalize_opensearch_host(host) for host in self.opensearch_hosts
        ))
        if self.opensearch_enabled and not self.opensearch_hosts:
            raise ValueError("opensearch_hosts_required")
        if self.opensearch_required and not self.opensearch_enabled:
            raise ValueError("opensearch_required_requires_enabled")

        username = (self.opensearch_username or "").strip()
        password = (
            self.opensearch_password.get_secret_value()
            if self.opensearch_password is not None
            else ""
        )
        if bool(username) != bool(password):
            raise ValueError("opensearch_basic_auth_pair_required")
        self.opensearch_username = username or None
        if not password:
            self.opensearch_password = None

        self.opensearch_ca_certs = (self.opensearch_ca_certs or "").strip() or None
        self.opensearch_client_cert = (
            (self.opensearch_client_cert or "").strip() or None
        )
        self.opensearch_client_key = (
            (self.opensearch_client_key or "").strip() or None
        )
        if bool(self.opensearch_client_cert) != bool(self.opensearch_client_key):
            raise ValueError("opensearch_client_certificate_pair_required")

        self.opensearch_index_prefix = self.opensearch_index_prefix.strip()
        if not OPENSEARCH_INDEX_PREFIX_PATTERN.fullmatch(
            self.opensearch_index_prefix
        ):
            raise ValueError("opensearch_index_prefix_invalid")
        self.opensearch_schema_version = self.opensearch_schema_version.strip()
        if not OPENSEARCH_SCHEMA_VERSION_PATTERN.fullmatch(
            self.opensearch_schema_version
        ):
            raise ValueError("opensearch_schema_version_invalid")
        if self.opensearch_bootstrap_on_startup:
            raise ValueError("opensearch_bootstrap_on_startup_unsupported")

        if self.app_env == "production":
            if self.auth_mode == "disabled":
                raise ValueError("production_auth_mode_required")
            if any("*" in host for host in self.trusted_hosts):
                raise ValueError("production_wildcard_trusted_host_forbidden")
            if "*" in self.cors_allowed_origins:
                raise ValueError("production_wildcard_cors_forbidden")
            if not self.security_headers_enabled:
                raise ValueError("production_security_headers_required")
            if not self.https_required:
                raise ValueError("production_https_required")
            if (
                self.auth_mode in ("oidc", "hybrid")
                and not self.oidc_require_https
            ):
                raise ValueError("production_oidc_https_required")
            if not self.rate_limiting_enabled:
                raise ValueError("production_rate_limiting_required")
            if self.rate_limit_backend != "redis":
                raise ValueError("production_redis_rate_limit_required")
            if self.rate_limit_key_secret is None:
                raise ValueError("production_rate_limit_key_secret_required")
            if not self.rate_limit_fail_closed:
                raise ValueError("production_rate_limit_fail_closed_required")
            if self.search_cursor_secret is None:
                raise ValueError("production_search_cursor_secret_required")
            if any(host.startswith("http://") for host in self.opensearch_hosts):
                raise ValueError("production_opensearch_https_required")
            if not self.opensearch_verify_certs:
                raise ValueError("production_opensearch_verify_certs_required")

        if self.auth_mode not in ("oidc", "hybrid"):
            return self

        if not self.oidc_issuer or not self.oidc_issuer.strip():
            raise ValueError("oidc_issuer_required")
        if not self.oidc_audience or not self.oidc_audience.strip():
            raise ValueError("oidc_audience_required")

        self.oidc_issuer = _validate_oidc_url(
            self.oidc_issuer,
            require_https=self.oidc_require_https,
            field="oidc_issuer",
        )
        discovery_url = self.oidc_discovery_url or (
            f"{self.oidc_issuer.rstrip('/')}"
            "/.well-known/openid-configuration"
        )
        self.oidc_discovery_url = _validate_oidc_url(
            discovery_url,
            require_https=self.oidc_require_https,
            field="oidc_discovery_url",
        )
        self.oidc_audience = self.oidc_audience.strip()
        if len(self.oidc_audience) > 256:
            raise ValueError("oidc_audience_invalid")

        algorithms = tuple(dict.fromkeys(self.oidc_allowed_algorithms))
        if not algorithms or any(
            algorithm not in OIDC_ASYMMETRIC_ALGORITHMS
            for algorithm in algorithms
        ):
            raise ValueError("oidc_allowed_algorithms_invalid")
        self.oidc_allowed_algorithms = list(algorithms)

        token_use_claim = self.oidc_token_use_claim.strip()
        access_token_use_value = self.oidc_access_token_use_value.strip()
        if not token_use_claim or not access_token_use_value:
            raise ValueError("oidc_access_token_indicator_invalid")
        if not self.oidc_require_access_token_indicator:
            raise ValueError("oidc_access_token_indicator_required")
        self.oidc_token_use_claim = token_use_claim
        self.oidc_access_token_use_value = access_token_use_value

        if len(self.oidc_role_mapping) > 100:
            raise ValueError("oidc_role_mapping_invalid")
        valid_internal_roles = {role.value for role in Role}
        for external_role, internal_role in self.oidc_role_mapping.items():
            if (
                not external_role.strip()
                or len(external_role) > 128
                or internal_role not in valid_internal_roles
            ):
                raise ValueError("oidc_role_mapping_invalid")
        return self
    
    @property
    def safe_database_url(self) -> str:
        """Returns the database URL with the password redacted for safe logging."""
        if not self.database_url:
            return ""
        if "@" in self.database_url:
            try:
                # e.g., postgresql://user:pass@host/db
                scheme_user, rest = self.database_url.split(":", 1)
                if "//" in scheme_user: # Handle format scheme://user:pass
                    scheme, user = scheme_user.split("//", 1)
                    if "@" in rest:
                        password, host_db = rest.split("@", 1)
                        return f"{scheme}//{user}:***@{host_db}"
            except Exception:
                return "***redacted***"
        return self.database_url

    @property
    def safe_celery_broker_url(self) -> str:
        """Returns the Celery broker URL with the password redacted for safe logging."""
        if not self.celery_broker_url:
            return ""
        if "@" in self.celery_broker_url:
            try:
                scheme_user, rest = self.celery_broker_url.split(":", 1)
                if "//" in scheme_user:
                    scheme, user = scheme_user.split("//", 1)
                    if "@" in rest:
                        password, host_db = rest.split("@", 1)
                        return f"{scheme}//{user}:***@{host_db}"
            except Exception:
                return "***redacted***"
        return self.celery_broker_url

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        hide_input_in_errors=True,
    )

@lru_cache
def get_settings() -> Settings:
    return Settings()
