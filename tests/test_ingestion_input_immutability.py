from agent.ingestion.pipeline import IngestionPipeline

def test_immutability():
    raw = {"src": "1.1.1.1", "action": "allow"}
    raw_copy = dict(raw)
    pipe = IngestionPipeline()
    pipe.ingest_records([raw], source_name="t")
    assert raw == raw_copy
