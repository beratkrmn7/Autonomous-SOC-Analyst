from agent.ingestion.fingerprint import get_schema_fingerprint

def test_json_fingerprint():
    fp1 = get_schema_fingerprint({"b": 2, "a": 1})
    fp2 = get_schema_fingerprint({"a": 9, "b": 5})
    assert fp1 == fp2

def test_different_json_fingerprint():
    fp1 = get_schema_fingerprint({"a": 1})
    fp2 = get_schema_fingerprint({"c": 3})
    assert fp1 != fp2
