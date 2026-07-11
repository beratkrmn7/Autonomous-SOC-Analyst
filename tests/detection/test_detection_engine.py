from agent.detection.engine import DetectionEngine
from agent.schema import CanonicalLogEvent

def test_engine_empty():
    engine = DetectionEngine()
    res = engine.analyze([])
    assert len(res.signals) == 0
    
def test_engine_invalid_event():
    engine = DetectionEngine()
    res = engine.analyze([CanonicalLogEvent(event_id="e1", parser_name="test", parse_status="success")])
    assert res.metrics.skipped_events == 1