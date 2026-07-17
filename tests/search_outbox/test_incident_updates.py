from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

from fastapi import HTTPException, Request
import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from agent.api.v1.incidents import StatusUpdateRequest, update_status
from agent.application.authentication import AuthenticatedPrincipal
from agent.config import Settings
from agent.persistence.database import Base
from agent.persistence.orm_models import AuditEvent, Incident, SearchIndexOutbox
from agent.persistence.unit_of_work import UnitOfWork


NOW = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def database():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    yield factory
    engine.dispose()


def _settings(*, enabled: bool = True) -> Settings:
    return Settings(_env_file=None, opensearch_enabled=enabled)


def _principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        subject_id="user-1",
        subject_type="analyst",
        display_name="User One",
        authentication_method="api_key",
        roles=("analyst",),
        credential_id="credential-1",
    )


def _request() -> Request:
    request = MagicMock(spec=Request)
    request.state.request_id = "request-1"
    return request


def _uow(factory, *, enabled: bool = True) -> UnitOfWork:
    return UnitOfWork(session_factory=factory, settings=_settings(enabled=enabled))


def _seed_incident(factory, *, enabled: bool = True, incident_id: str = "incident-1"):
    uow = _uow(factory, enabled=enabled)
    with uow:
        uow.session.add(
            Incident(
                incident_id=incident_id,
                title="Test Incident",
                status="new",
                version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )
    return uow


def _database_state(factory, incident_id: str) -> tuple[str, int, int, int]:
    with factory() as session:
        incident = session.get(Incident, incident_id)
        return (
            str(incident.status),
            int(incident.version),
            session.execute(
                select(func.count()).select_from(SearchIndexOutbox)
            ).scalar_one(),
            session.execute(select(func.count()).select_from(AuditEvent)).scalar_one(),
        )


def test_status_update_enqueues_higher_version_projection(database) -> None:
    uow = _seed_incident(database)

    response = update_status(
        incident_id="incident-1",
        req=StatusUpdateRequest(status="triaged", expected_version=1),
        request=_request(),
        principal=_principal(),
        uow=uow,
    )

    assert response == {"status": "success", "new_status": "triaged", "version": 2}
    with database() as session:
        row = session.execute(select(SearchIndexOutbox)).scalar_one()
        assert row.document_version == 2
        assert isinstance(row.payload, dict)
        assert row.payload["status"] == "triaged"
        assert row.payload["document_version"] == 2


def test_expected_version_conflict_changes_nothing_and_enqueues_nothing(database) -> None:
    uow = _seed_incident(database, incident_id="incident-conflict")

    with pytest.raises(HTTPException) as caught:
        update_status(
            incident_id="incident-conflict",
            req=StatusUpdateRequest(status="triaged", expected_version=99),
            request=_request(),
            principal=_principal(),
            uow=uow,
        )

    assert caught.value.detail["code"] == "incident_version_conflict"
    assert _database_state(database, "incident-conflict") == ("new", 1, 0, 0)


def test_invalid_transition_changes_nothing_and_enqueues_nothing(database) -> None:
    uow = _seed_incident(database, incident_id="incident-invalid")

    with pytest.raises(HTTPException) as caught:
        update_status(
            incident_id="incident-invalid",
            req=StatusUpdateRequest(status="resolved", expected_version=1),
            request=_request(),
            principal=_principal(),
            uow=uow,
        )

    assert caught.value.detail["code"] == "invalid_incident_transition"
    assert _database_state(database, "incident-invalid") == ("new", 1, 0, 0)


def test_no_op_transition_does_not_increment_or_enqueue(database) -> None:
    uow = _seed_incident(database, incident_id="incident-noop")

    response = update_status(
        incident_id="incident-noop",
        req=StatusUpdateRequest(status="new", expected_version=1),
        request=_request(),
        principal=_principal(),
        uow=uow,
    )

    assert response["version"] == 1
    assert _database_state(database, "incident-noop") == ("new", 1, 0, 0)


def test_disabled_mode_updates_source_without_outbox(database) -> None:
    uow = _seed_incident(database, enabled=False, incident_id="incident-disabled")

    update_status(
        incident_id="incident-disabled",
        req=StatusUpdateRequest(status="triaged", expected_version=1),
        request=_request(),
        principal=_principal(),
        uow=uow,
    )

    assert _database_state(database, "incident-disabled") == ("triaged", 2, 0, 1)
