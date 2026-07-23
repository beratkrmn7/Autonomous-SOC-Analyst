from pathlib import Path

from agent.application.analysis_service import AnalysisService


FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "firewall"
    / "phase6a1_detection_correctness.jsonl"
)


def test_pf_ingestion_and_detection_correctness_without_provider_calls(monkeypatch) -> None:
    def provider_call_forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("LLM/provider call attempted during deterministic detection")

    # Detection must never reach a provider. Per-incident graph invocation no
    # longer exists, so the only provider entry point left is the job-level
    # batch enrichment, which detect mode must not reach either.
    monkeypatch.setattr(
        "agent.triage.provider_factory.build_provider",
        provider_call_forbidden,
    )
    service = AnalysisService()

    result = service.analyze_file(str(FIXTURE), run_triage=False)

    assert result.ingestion_result is not None
    assert result.ingestion_result.metrics.total_records == 10
    assert result.ingestion_result.metrics.parsed_records == 10
    assert len(result.event_map) == 10

    roles = service.filter_engine.filter_events(result.ingestion_result.events)
    noise_ports = {event.dst_port for event in roles.noise}
    assert {53, 443} <= noise_ports

    assert result.detection_result is not None
    detection = result.detection_result
    assert detection.metrics.total_events == 10
    assert detection.metrics.eligible_events == 10
    assert {signal.rule_id for signal in detection.signals} == {"spi_anomaly_burst"}
    assert {incident.incident_type for incident in detection.incidents} == {"spi_anomaly"}

    spi_event_ids = {
        event.event_id
        for event in result.ingestion_result.events
        if event.parser_metadata and event.parser_metadata.get("spi_anomaly") is True
    }
    assert len(spi_event_ids) == 5
    assert all(
        event.parser_metadata.get("pf_event_type") == "synthetic"
        for event in result.ingestion_result.events
        if event.event_id in spi_event_ids and event.parser_metadata
    )
    for incident in detection.incidents:
        assert set(incident.event_ids) <= spi_event_ids
        assert {evidence.event_id for evidence in incident.evidence} <= spi_event_ids
