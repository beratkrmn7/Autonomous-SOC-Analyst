from agent.ingestion.pipeline import IngestionPipeline

def test_failure_isolation():
    pipe = IngestionPipeline()
    res = pipe.ingest_records([
        '{"deviceAction": "allow", "src": "1.1.1.1", "proto": "tcp"}',
        '{"invalid_json":',
        '{"deviceAction": "allow", "src": "2.2.2.2", "proto": "tcp"}'
    ], source_name="test")
    assert res.metrics.total_records == 3
    assert res.metrics.parsed_records == 2
