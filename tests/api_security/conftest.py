from collections.abc import Callable
from dataclasses import dataclass

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agent.api.deps import (
    get_optional_oidc_authentication_service,
    get_uow,
)
from agent.config import Settings, get_settings
from agent.persistence.database import Base
from agent.persistence.unit_of_work import UnitOfWork
from server import create_app
from tests.api_security.helpers import make_settings


@pytest.fixture
def session_factory(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'api-security.db'}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    yield factory
    engine.dispose()


@pytest.fixture
def app_factory(session_factory) -> Callable:
    def factory(
        settings: Settings | None = None,
        *,
        oidc_service=None,
    ):
        selected_settings = settings or make_settings()
        application = create_app(selected_settings)
        application.dependency_overrides[get_settings] = (
            lambda: selected_settings
        )
        application.dependency_overrides[get_uow] = (
            lambda: UnitOfWork(session_factory)
        )
        if oidc_service is not None:
            application.dependency_overrides[
                get_optional_oidc_authentication_service
            ] = lambda: oidc_service
        return application

    return factory


@dataclass(frozen=True)
class SecretSentinels:
    api_key: str
    jwt: str
    authorization: str
    database_url: str
    redis_url: str
    oidc_url: str
    windows_path: str
    linux_path: str

    @property
    def values(self) -> tuple[str, ...]:
        return (
            self.api_key,
            self.jwt,
            self.authorization,
            self.database_url,
            self.redis_url,
            self.oidc_url,
            self.windows_path,
            self.linux_path,
        )

    @property
    def blob(self) -> str:
        return " | ".join(self.values)


@pytest.fixture
def secret_sentinels() -> SecretSentinels:
    api_key = "soc_deadbeefdead_" + "A" * 43
    jwt_token = "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiJzZWNyZXQifQ.signature"
    return SecretSentinels(
        api_key=api_key,
        jwt=jwt_token,
        authorization=f"Bearer {jwt_token}",
        database_url="postgresql://secret-user:secret-pass@db.internal/soc",
        redis_url="redis://:secret-pass@redis.internal:6379/0",
        oidc_url="https://identity.internal/jwks?tenant=secret",
        windows_path=r"C:\secret\private\events.jsonl",
        linux_path="/srv/secret/private/events.jsonl",
    )
