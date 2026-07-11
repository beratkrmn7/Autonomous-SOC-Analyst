from datetime import datetime, timedelta
from agent.schema import CanonicalLogEvent
from agent.detection.detectors.horizontal_scan import HorizontalScanRule
from agent.detection.detectors.base import DetectionContext
from agent.detection.config import DetectionSettings

def test_horizontal_scan_positive():
    rule = HorizontalScanRule()
    settings = DetectionSettings(HORIZONTAL_SCAN_MIN_EVENTS=3, HORIZONTAL_SCAN_MIN_DISTINCT_TARGETS=2)
    ctx = DetectionContext(settings=settings, analysis_started_at=datetime.now())
    
    events = [
        CanonicalLogEvent(event_id=f"e{i}", timestamp=datetime.now() + timedelta(seconds=i), src_ip="1.2.3.4", dst_ip=f"10.0.0.{i}", dst_port=80, action="block", parser_name="test", parse_status="success")
        for i in range(3)
    ]
    signals = rule.evaluate(events, ctx)
    assert len(signals) == 1
    assert signals[0].primary_entity == "1.2.3.4"
    assert "T1046" in signals[0].mitre_techniques
    
def test_horizontal_scan_negative():
    rule = HorizontalScanRule()
    settings = DetectionSettings(HORIZONTAL_SCAN_MIN_EVENTS=3, HORIZONTAL_SCAN_MIN_DISTINCT_TARGETS=2)
    ctx = DetectionContext(settings=settings, analysis_started_at=datetime.now())
    events = [
        CanonicalLogEvent(event_id="e1", timestamp=datetime.now(), src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=80, action="block", parser_name="test", parse_status="success"),
        CanonicalLogEvent(event_id="e2", timestamp=datetime.now(), src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=80, action="block", parser_name="test", parse_status="success"),
        CanonicalLogEvent(event_id="e3", timestamp=datetime.now(), src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=80, action="block", parser_name="test", parse_status="success")
    ]
    signals = rule.evaluate(events, ctx)
    assert len(signals) == 0