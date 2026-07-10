import pytest
from agent.ingestion.readers import iter_jsonl_records
from agent.ingestion.limits import IngestionLimits
from agent.errors import RecordLimitExceededError

def test_record_limit(tmp_path):
    p = tmp_path / "test.jsonl"
    p.write_text('{"a": 1}\n{"b": 2}\n{"c": 3}')
    limits = IngestionLimits(MAX_RECORDS_PER_FILE=2)
    with pytest.raises(RecordLimitExceededError):
        list(iter_jsonl_records(p, limits))

def test_record_bytes_limit(tmp_path):
    p = tmp_path / "test.jsonl"
    p.write_text('{"a": 1}\n{"long": "' + 'A'*2000 + '"}\n{"c": 3}')
    limits = IngestionLimits(MAX_RECORD_BYTES=1000)
    records = list(iter_jsonl_records(p, limits))
    assert len(records) == 2 # Skips the long one
