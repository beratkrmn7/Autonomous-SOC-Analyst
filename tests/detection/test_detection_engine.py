from datetime import datetime, timezone

from agent.detection.config import DetectionSettings
from agent.detection.detectors.spi_anomaly import SPIAnomalyRule
from agent.detection.engine import DetectionEngine
from agent.detection.registry import RuleRegistry
from agent.schema import CanonicalLogEvent

def test_engine_empty():
    engine = DetectionEngine()
    res = engine.analyze([])
    assert len(res.signals) == 0
    
def test_engine_invalid_event():
    engine = DetectionEngine()
    res = engine.analyze([CanonicalLogEvent(event_id="e1", parser_name="test", parse_status="success")])
    assert res.metrics.skipped_events == 1


def test_incident_context_is_unique_bounded_and_excludes_incident_events() -> None:
    now = datetime(2026, 7, 10, 9, 51, tzinfo=timezone.utc)
    settings = DetectionSettings()
    registry = RuleRegistry()
    registry.register(SPIAnomalyRule())
    engine = DetectionEngine(registry=registry, settings=settings)
    incident_events = [
        CanonicalLogEvent(
            event_id=f"spi-{index}",
            timestamp=now,
            src_ip="192.0.2.44",
            dst_ip="198.51.100.20",
            action="block",
            parser_metadata={"spi_anomaly": True},
            parser_name="pf_firewall",
            parse_status="parsed",
        )
        for index in range(settings.SPI_ANOMALY_MIN_EVENTS)
    ]
    context_events = [incident_events[0]]
    context_events.extend(
        CanonicalLogEvent(
            event_id=f"context-{index}",
            timestamp=now,
            src_ip="192.0.2.44",
            dst_ip="198.51.100.20",
            action="pass",
            parser_name="pf_firewall",
            parse_status="parsed",
        )
        for index in range(settings.MAX_CONTEXT_EVENTS_PER_INCIDENT + 2)
    )
    context_events.append(context_events[1])

    result = engine.analyze(incident_events, context_events)

    assert len(result.incidents) == 1
    incident = result.incidents[0]
    assert len(incident.context_event_ids) == settings.MAX_CONTEXT_EVENTS_PER_INCIDENT
    assert len(incident.context_event_ids) == len(set(incident.context_event_ids))
    assert set(incident.context_event_ids).isdisjoint(incident.event_ids)
