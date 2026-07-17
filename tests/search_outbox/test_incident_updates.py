import pytest
from datetime import datetime, timezone
import json
from unittest.mock import MagicMock

from agent.api.v1.incidents import update_status, StatusUpdateRequest
from agent.persistence.unit_of_work import UnitOfWork
from agent.persistence.orm_models import SearchIndexOutbox, Incident
from agent.application.authentication import AuthenticatedPrincipal
from sqlalchemy import create_engine
from agent.persistence.database import Base
from fastapi import Request

@pytest.fixture
def uow():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    from sqlalchemy.orm import sessionmaker
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return UnitOfWork(session_factory=SessionLocal)

def test_incident_update_enqueues_outbox(uow, monkeypatch):
    from agent.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "opensearch_enabled", True)
    monkeypatch.setattr(settings, "opensearch_schema_version", "v1")
    
    import agent.config
    monkeypatch.setattr(agent.config, "get_settings", lambda: settings)
    
    with uow:
        incident = Incident(
            incident_id="inc-1",
            title="Test Incident",
            status="new",
            version=1,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        uow.incidents.add(incident)
        uow.commit()
        
    req = StatusUpdateRequest(status="triaged", expected_version=1)
    
    request_mock = MagicMock(spec=Request)
    request_mock.state.request_id = "test-req-1"
    
    principal = AuthenticatedPrincipal(
        subject_id="user1",
        subject_type="analyst",
        display_name="User One",
        authentication_method="api_key",
        roles=("analyst",),
        credential_id="cred-1"
    )
    
    res = update_status(
        incident_id="inc-1",
        req=req,
        request=request_mock,
        principal=principal,
        uow=uow
    )
    
    assert res["status"] == "success"
    assert res["new_status"] == "triaged"
    assert res["version"] == 2
    
    with uow:
        outbox_events = uow.session.query(SearchIndexOutbox).all()
        assert len(outbox_events) == 1
        assert outbox_events[0].entity_type == "incident"
        assert outbox_events[0].entity_id == "inc-1"
        assert outbox_events[0].document_version == 2
        
        payload = json.loads(outbox_events[0].payload)
        assert payload["status"] == "triaged"
        assert payload["document_version"] == 2

def test_incident_update_skips_outbox_when_disabled(uow, monkeypatch):
    from agent.config import get_settings
    settings = get_settings()
    monkeypatch.setattr(settings, "opensearch_enabled", False)
    
    import agent.config
    monkeypatch.setattr(agent.config, "get_settings", lambda: settings)
    
    with uow:
        incident = Incident(
            incident_id="inc-2",
            title="Test Incident 2",
            status="new",
            version=1,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        uow.incidents.add(incident)
        uow.commit()
        
    req = StatusUpdateRequest(status="triaged", expected_version=1)
    
    request_mock = MagicMock(spec=Request)
    request_mock.state.request_id = "test-req-2"
    
    principal = AuthenticatedPrincipal(
        subject_id="user1",
        subject_type="analyst",
        display_name="User One",
        authentication_method="api_key",
        roles=("analyst",),
        credential_id="cred-1"
    )
    
    update_status(
        incident_id="inc-2",
        req=req,
        request=request_mock,
        principal=principal,
        uow=uow
    )
    
    with uow:
        outbox_events = uow.session.query(SearchIndexOutbox).all()
        assert len(outbox_events) == 0
