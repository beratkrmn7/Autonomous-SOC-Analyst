from datetime import datetime, timezone
from agent.schema import CanonicalLogEvent
from agent.detection.engine import DetectionEngine
from agent.detection.config import DetectionSettings
from agent.detection.detectors.horizontal_scan import HorizontalScanRule
from agent.detection.registry import RuleRegistry

def test_order_invariance():
    registry = RuleRegistry()
    registry.register(HorizontalScanRule())
    settings = DetectionSettings(HORIZONTAL_SCAN_MIN_EVENTS=2, HORIZONTAL_SCAN_MIN_DISTINCT_TARGETS=2)
    engine = DetectionEngine(registry=registry, settings=settings)
    
    events = [
        CanonicalLogEvent(event_id="e1", timestamp=datetime(2025,1,1, tzinfo=timezone.utc), src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=80, action="block", parser_name="test", parse_status="success"),
        CanonicalLogEvent(event_id="e2", timestamp=datetime(2025,1,1, tzinfo=timezone.utc), src_ip="1.2.3.4", dst_ip="10.0.0.2", dst_port=80, action="block", parser_name="test", parse_status="success")
    ]
    
    res1 = engine.analyze(events)
    
    events_shuffled = events[::-1]
    res2 = engine.analyze(events_shuffled)
    
    assert res1.signals[0].signal_id == res2.signals[0].signal_id