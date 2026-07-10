from agent.ingestion.pipeline import IngestionPipeline

def test_mixed_formats():
    pipe = IngestionPipeline()
    res = pipe.ingest_file("tests/fixtures/mixed/mixed_formats.log")
    assert res.metrics.total_records == 6
    # 5 valid, 1 invalid
    assert res.metrics.parsed_records == 5
    assert res.metrics.failed_records + res.metrics.unsupported_records == 1
    assert "mock_json" in res.metrics.parser_counts
    assert "syslog" in res.metrics.parser_counts
    assert "cef" in res.metrics.parser_counts
