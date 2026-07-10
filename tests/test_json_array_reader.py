from agent.ingestion.readers import iter_json_array_records
from agent.ingestion.limits import IngestionLimits

def test_json_array(tmp_path):
    p = tmp_path / "test.json"
    p.write_text('[{"a": 1}, {"b": 2}]')
    limits = IngestionLimits()
    records = list(iter_json_array_records(p, limits))
    assert len(records) == 2
    assert records[0].raw_record["a"] == 1
