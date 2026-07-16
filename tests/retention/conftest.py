from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import sessionmaker

from agent.config import Settings
from agent.persistence.orm_models import Base


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)


@dataclass(frozen=True)
class RetentionEnvironment:
    settings: Settings
    session_factory: sessionmaker
    engine: Engine


def make_environment(database_path: Path) -> RetentionEnvironment:
    settings = Settings(
        _env_file=None,
        app_env="test",
        database_url=f"sqlite:///{database_path}",
        staging_dir=str(database_path.parent / "staging-private"),
        groq_api_key="private-retention-test-secret",
    )
    engine = create_engine(
        settings.database_url,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return RetentionEnvironment(settings, factory, engine)


@pytest.fixture
def retention_env(tmp_path) -> RetentionEnvironment:
    environment = make_environment(tmp_path / "retention.db")
    yield environment
    environment.engine.dispose()
