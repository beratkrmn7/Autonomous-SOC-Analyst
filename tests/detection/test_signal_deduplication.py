from datetime import datetime, timezone
from agent.schema import CanonicalLogEvent
from agent.detection.engine import DetectionEngine
from agent.detection.config import DetectionSettings
from agent.detection.registry import RuleRegistry
from agent.detection.detectors.horizontal_scan import HorizontalScanRule
from agent.detection.detectors.remote_service_probe import RemoteServiceProbeRule

def test_exact_dedup():
    DetectionEngine(settings=DetectionSettings(HORIZONTAL_SCAN_MIN_EVENTS=1, HORIZONTAL_SCAN_MIN_DISTINCT_TARGETS=1))
    pass

def test_rdp_precedence():
    registry = RuleRegistry()
    registry.register(HorizontalScanRule())
    registry.register(RemoteServiceProbeRule())
    settings = DetectionSettings(
        HORIZONTAL_SCAN_MIN_EVENTS=2, HORIZONTAL_SCAN_MIN_DISTINCT_TARGETS=2,
        REMOTE_SERVICE_MIN_EVENTS=2, REMOTE_SERVICE_MIN_DISTINCT_TARGETS=2
    )
    engine = DetectionEngine(registry=registry, settings=settings)
    events = [
        CanonicalLogEvent(event_id=f"e{i}", timestamp=datetime.now(timezone.utc), src_ip="1.2.3.4", dst_ip=f"10.0.0.{i}", dst_port=3389, action="block", parser_name="test", parse_status="success")
        for i in range(2)
    ]
    res = engine.analyze(events)
    # Both horizontal and remote service match, but RDP absorbs horizontal
    assert len(res.signals) == 1
    assert res.signals[0].signal_type == "rdp_probe"