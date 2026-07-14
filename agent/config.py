from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import SecretStr, Field
from agent.ingestion.limits import IngestionLimits
from typing import Literal, Optional
from functools import lru_cache

class Settings(BaseSettings):
    app_env: str = "development"
    log_level: str = "INFO"

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

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

@lru_cache
def get_settings() -> Settings:
    return Settings()
