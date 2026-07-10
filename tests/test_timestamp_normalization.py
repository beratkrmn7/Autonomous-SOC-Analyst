from agent.parsers.helpers import normalize_timestamp
from datetime import timezone

def test_iso8601():
    dt = normalize_timestamp("2026-07-10T10:00:00Z")
    assert dt.year == 2026
    assert dt.tzinfo == timezone.utc

def test_unix_seconds():
    dt = normalize_timestamp("1672531200")
    assert dt.year == 2023

def test_invalid():
    assert normalize_timestamp("invalid") is None
