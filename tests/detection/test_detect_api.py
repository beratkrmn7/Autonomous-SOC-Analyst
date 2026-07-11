from fastapi.testclient import TestClient
from server import app

client = TestClient(app)

def test_detect_api(tmp_path):
    log_file = tmp_path / "test.jsonl"
    log_file.write_text('{"src_ip": "1.2.3.4", "action": "block"}')
    with open(log_file, "rb") as f:
        response = client.post("/detect/file", files={"file": ("test.jsonl", f, "application/jsonl")})
    assert response.status_code == 200
    assert "detection_metrics" in response.json()