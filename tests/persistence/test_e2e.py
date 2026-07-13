import pytest
import tempfile
import json
import os
from fastapi.testclient import TestClient
from alembic.config import Config
from alembic import command
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from server import app
from agent.config import get_settings
from agent.api.deps import get_uow
from agent.persistence.unit_of_work import UnitOfWork
from agent.persistence.orm_models import Incident

def setup_test_db(db_path: str):
    # Set config to point to this temp DB
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    get_settings.cache_clear()
    
    # Run migrations
    alembic_cfg = Config("alembic.ini")
    alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    command.upgrade(alembic_cfg, "head")
    
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return engine, SessionLocal

@pytest.fixture
def isolated_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name
    
    engine, SessionLocal = setup_test_db(db_path)
    
    # Override FastAPI dependency
    def override_get_uow():
        return UnitOfWork(session_factory=SessionLocal)
    
    app.dependency_overrides[get_uow] = override_get_uow
    
    yield db_path, SessionLocal
    
    app.dependency_overrides.clear()
    engine.dispose()
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except PermissionError:
            pass

@pytest.fixture
def test_client(isolated_db):
    return TestClient(app)

def test_api_to_db_flow_and_durability(isolated_db):
    db_path, SessionLocal = isolated_db
    
    # Deterministic source IP
    src_ip = "1.2.3.4"
    logs = []
    # Include a SENTINEL_SECRET to ensure it's not persisted raw
    for port in range(1, 15):
        logs.append(json.dumps({
            "timestamp": f"2023-01-01T12:00:{port:02d}Z",
            "src_ip": src_ip, 
            "dst_ip": "10.0.0.1",
            "dst_port": port,
            "protocol": "tcp",
            "tcp_flags": "SYN",
            "action": "block",
            "secret_key": "SENTINEL_SECRET" 
        }))
    log_content = "\n".join(logs) + "\n"
    
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".jsonl") as tf:
        tf.write(log_content)
        tf_name = tf.name
        
    # First app instance
    with TestClient(app) as client:
        with open(tf_name, "rb") as f:
            res = client.post("/analyze/file", files={"file": f})
            
        assert res.status_code == 200, res.text
        data = res.json()
        assert data["incidents_generated"] > 0
        incident_id = data["incidents"][0]["incident_id"]
        
        # Test missing expected_version logic -> 422
        res = client.patch(f"/api/v1/incidents/{incident_id}/status", json={"status": "invalid_status"})
        assert res.status_code == 422

        # Test stale expected_version -> 409
        res = client.patch(f"/api/v1/incidents/{incident_id}/status", json={"status": "invalid_status", "expected_version": 99})
        assert res.status_code == 409
        assert res.json()["detail"]["code"] == "incident_version_conflict"

        # Test invalid transition -> 409
        # Assuming current version is 2 because triage was run, fetch to be sure
        res_get = client.get(f"/api/v1/incidents/{incident_id}")
        res_get.json().get("version", 2)  # Wait, IncidentResponse doesn't have version yet, let's just use 2
        
        # Actually IncidentResponse doesn't return version. We know it's 2 after triage.
        res = client.patch(f"/api/v1/incidents/{incident_id}/status", json={"status": "invalid_status", "expected_version": 2})
        assert res.status_code == 409
        assert res.json()["detail"]["code"] == "invalid_incident_transition"
        
        res = client.patch(f"/api/v1/incidents/{incident_id}/status", json={"status": "investigating", "expected_version": 2})
        assert res.status_code == 200
        assert res.json()["version"] == 3
    
    os.remove(tf_name)
    
    # Verify data durability by accessing the DB directly with a new session
    # Simulate app restart
    new_engine, NewSessionLocal = setup_test_db(db_path)
    
    with NewSessionLocal() as session:
        orm_inc = session.query(Incident).filter(Incident.incident_id == incident_id).first()
        assert orm_inc is not None
        assert orm_inc.status == "investigating"
        
        # Verify Sentinel Secret is NOT in canonical events
        from agent.persistence.orm_models import CanonicalEvent
        events = session.query(CanonicalEvent).filter(CanonicalEvent.src_ip == src_ip).all()
        assert len(events) > 0
        for ev in events:
            # Check excerpt doesn't contain SENTINEL_SECRET if filtered, or check we dropped source_line
            assert not ev.safe_message_excerpt or "SENTINEL_SECRET" not in ev.safe_message_excerpt
            
    # Verify via API again
    def new_override():
        return UnitOfWork(session_factory=NewSessionLocal)
    app.dependency_overrides[get_uow] = new_override
    
    with TestClient(app) as client:
        res = client.get(f"/api/v1/incidents/{incident_id}")
        assert res.status_code == 200
        assert res.json()["status"] == "investigating"
        
        res = client.get(f"/api/v1/incidents/{incident_id}/report")
        assert res.status_code == 200
        assert "incident_id" in res.json()
        
    new_engine.dispose()

