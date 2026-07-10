from agent.ingestion.pipeline import IngestionPipeline

def test_event_id_stability():
    pipe = IngestionPipeline()
    res1 = pipe.ingest_records(['{"src": "1.1.1.1", "action": "allow"}'], source_name="t")
    res2 = pipe.ingest_records(['{"src": "1.1.1.1", "action": "allow"}'], source_name="t")
    assert res1.events[0].event_id == res2.events[0].event_id
