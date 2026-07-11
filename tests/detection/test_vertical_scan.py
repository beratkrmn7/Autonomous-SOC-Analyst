from datetime import datetime
from agent.schema import CanonicalLogEvent
from agent.detection.detectors.vertical_scan import VerticalScanRule
from agent.detection.detectors.base import DetectionContext
from agent.detection.config import DetectionSettings

def test_vertical_scan_positive():
    rule = VerticalScanRule()
    settings = DetectionSettings(VERTICAL_SCAN_MIN_EVENTS=3, VERTICAL_SCAN_MIN_DISTINCT_PORTS=3)
    ctx = DetectionContext(settings=settings, analysis_started_at=datetime.now())
    events = [
        CanonicalLogEvent(event_id=f"e{i}", timestamp=datetime.now(), src_ip="1.2.3.4", dst_ip="10.0.0.1", dst_port=80+i, action="block", parser_name="test", parse_status="success")
        for i in range(3)
    ]
    signals = rule.evaluate(events, ctx)
    assert len(signals) == 1
    assert signals[0].target_entities == ["10.0.0.1"]