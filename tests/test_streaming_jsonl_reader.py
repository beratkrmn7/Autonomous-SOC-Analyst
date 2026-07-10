from agent.ingestion.readers import iter_jsonl_records
from agent.ingestion.limits import IngestionLimits

def test_streaming_jsonl(tmp_path):
    p = tmp_path / "test.jsonl"
    p.write_text('{"a": 1}\n{"b": 2}\ninvalid\n{"c": 3}')
    limits = IngestionLimits()
    records = list(iter_jsonl_records(p, limits))
    assert len(records) == 4
    assert records[0].raw_record["a"] == 1
    assert records[1].raw_record["b"] == 2
    assert records[2].raw_record == "invalid"
    assert records[3].raw_record["c"] == 3
