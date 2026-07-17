from __future__ import annotations

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agent.api.deps import get_opensearch_health_service, get_uow
from agent.config import Settings, get_settings
from agent.opensearch.models import OpenSearchHealthResult
from agent.persistence.database import Base
from agent.persistence.unit_of_work import UnitOfWork
from server import create_app


class StubHealthService:
    def check(self) -> OpenSearchHealthResult:
        return OpenSearchHealthResult(
            status="degraded",
            required=False,
            cluster_version="3.2",
            bootstrap_compatible=True,
            error_code="opensearch_foundation_missing",
        )


@pytest.mark.parametrize(
    ("required", "expected_code", "expected_status"),
    [(False, 200, "ready"), (True, 503, "not_ready")],
)
def test_readiness_honors_optional_and_required_modes(
    tmp_path,
    required: bool,
    expected_code: int,
    expected_status: str,
) -> None:
    settings = Settings(
        _env_file=None,
        app_env="test",
        llm_enabled=False,
        opensearch_enabled=True,
        opensearch_required=required,
        trusted_hosts=["testserver"],
    )
    engine = create_engine(f"sqlite:///{tmp_path / 'readiness.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    application = create_app(settings)
    application.dependency_overrides[get_settings] = lambda: settings
    application.dependency_overrides[get_uow] = lambda: UnitOfWork(session_factory)
    application.dependency_overrides[get_opensearch_health_service] = (
        StubHealthService
    )

    try:
        with TestClient(application) as client:
            response = client.get("/health/ready")
    finally:
        engine.dispose()

    assert response.status_code == expected_code
    assert response.json()["status"] == expected_status
    assert response.json()["components"]["opensearch"] == "degraded"
