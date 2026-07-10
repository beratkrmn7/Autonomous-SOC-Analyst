import subprocess

def test_cli_ingest_mode():
    res = subprocess.run(["python", "main.py", "--ingest-file", "tests/fixtures/mock/mock_events.jsonl"], capture_output=True, text=True)
    assert res.returncode == 0
    assert "INGESTION SUMMARY" in res.stdout
