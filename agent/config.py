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
    
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

@lru_cache
def get_settings() -> Settings:
    return Settings()
