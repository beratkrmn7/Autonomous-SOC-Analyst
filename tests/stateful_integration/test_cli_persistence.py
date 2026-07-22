"""Phase 6E.4 blocker: CLI detect/analyze run through the persistent
AnalysisService (jobs/events/signals/incidents, and reports for analyze), so
stateful cross-job correlation works across separate CLI invocations. Ingest
stays ingestion-only. No migrations are run by the CLI."""

from __future__ import annotations

import main
from agent.application.analysis_service import AnalysisService
from agent.application.service_factory import (
    build_persistent_analysis_service,
    compute_file_sha256,
    compute_idempotency_key,
)
from agent.ingestion.models import IngestionMetrics, IngestionResult, InputFormat
from agent.persistence.orm_models import (
    Incident,
    IncidentCorrelationState,
    Report,
    TriageRun,
)
from agent.persistence.unit_of_work import UnitOfWork

from tests.stateful_integration.conftest import (
    campaign_job_a,
    campaign_job_b,
    make_detection_result,
    make_settings,
)


def _ingestion_result(events) -> IngestionResult:
    return IngestionResult(
        source_name="firewall.json",
        input_format=InputFormat.JSONL,
        events=list(events),
        metrics=IngestionMetrics(total_records=len(events), parsed_records=len(events)),
    )


def _patch_cli_factory(monkeypatch, session_factory, settings, campaigns):
    """Point the CLI's persistent-service factory at the test database and
    stub ingestion + detection with a queue of prebuilt campaigns."""
    queue = list(campaigns)

    def fake_factory(passed_settings=None):
        events, signal, incident = queue.pop(0)
        service = AnalysisService(
            uow=UnitOfWork(session_factory=session_factory, settings=settings)
        )
        service.ingest.ingest_file = lambda path: _ingestion_result(events)  # type: ignore[assignment]
        det = make_detection_result(events=events, signals=[signal], incidents=[incident])
        service.detection_engine.analyze = lambda ev, ctx: det  # type: ignore[assignment]
        return service

    monkeypatch.setattr(
        "agent.application.service_factory.build_persistent_analysis_service",
        fake_factory,
    )


def test_idempotency_key_matches_existing_format() -> None:
    key = compute_idempotency_key("abc123", "1.0.0", "detect")
    import hashlib

    expected = hashlib.sha256(b"abc123:1.0.0:detect").hexdigest()
    assert key == expected


def test_factory_builds_persistent_service_without_migrations() -> None:
    settings = make_settings(enabled=True)
    service = build_persistent_analysis_service(settings)
    assert isinstance(service, AnalysisService)
    assert service.uow is not None
    assert service.uow.settings.stateful_correlation_enabled is True


def test_two_cli_detect_runs_converge_on_one_canonical(
    session_factory, monkeypatch, tmp_path, fake_app
) -> None:
    settings = make_settings(enabled=True)
    _patch_cli_factory(
        monkeypatch, session_factory, settings, [campaign_job_a(), campaign_job_b()]
    )

    file_a = tmp_path / "a.jsonl"
    file_a.write_text('{"file": "A"}\n')
    file_b = tmp_path / "b.jsonl"
    file_b.write_text('{"file": "B"}\n')

    main.detect_file_only(str(file_a))
    main.detect_file_only(str(file_b))

    with session_factory() as session:
        incidents = session.query(Incident).all()
        # Both CLI detect runs converged on one canonical persistent incident.
        assert [i.incident_id for i in incidents] == ["INC-A"]
        assert {str(s.signal_id) for s in incidents[0].signals} == {"SIG-A", "SIG-B"}
        # Both separate CLI detect jobs are associated with the canonical.
        assert len(incidents[0].jobs) == 2
        # Detect makes zero provider calls and writes no report/triage rows.
        assert session.query(Report).count() == 0
        assert session.query(TriageRun).count() == 0
    assert fake_app.calls == 0


def test_cli_analyze_persists_report(session_factory, monkeypatch, tmp_path, fake_app) -> None:
    settings = make_settings(enabled=True)
    _patch_cli_factory(monkeypatch, session_factory, settings, [campaign_job_a()])

    file_a = tmp_path / "a.jsonl"
    file_a.write_text('{"file": "A"}\n')

    main.analyze_file(str(file_a))

    with session_factory() as session:
        # Analyze persisted a report for the canonical incident (the blocked RDP
        # campaign routes to a deterministic report: no provider call).
        assert session.query(Report).filter_by(incident_id="INC-A").count() == 1
    assert fake_app.calls == 0


def test_cli_disabled_mode_keeps_batch_local_behavior(
    session_factory, monkeypatch, tmp_path, fake_app
) -> None:
    settings = make_settings(enabled=False)
    _patch_cli_factory(monkeypatch, session_factory, settings, [campaign_job_a()])

    file_a = tmp_path / "a.jsonl"
    file_a.write_text('{"file": "A"}\n')

    main.detect_file_only(str(file_a))

    with session_factory() as session:
        # Batch-local path: original incident ID preserved, no correlation state.
        assert session.get(Incident, "INC-A") is not None
        assert session.query(IncidentCorrelationState).count() == 0


def test_cli_ingest_only_does_not_initialize_detection(monkeypatch, tmp_path) -> None:
    called = {"factory": False, "detection": False}

    def factory_guard(*_a, **_k):
        called["factory"] = True
        raise AssertionError("ingest-only must not build the analysis service")

    def detection_guard(*_a, **_k):
        called["detection"] = True
        raise AssertionError("ingest-only must not run detection")

    monkeypatch.setattr(
        "agent.application.service_factory.build_persistent_analysis_service",
        factory_guard,
    )
    monkeypatch.setattr(
        "agent.detection.engine.DetectionEngine.analyze", detection_guard
    )

    log = tmp_path / "in.jsonl"
    log.write_text('{"src_ip": "203.0.113.10", "dst_port": 3389, "action": "block"}\n')

    main.ingest_file_only(str(log))

    assert called == {"factory": False, "detection": False}


def test_compute_file_sha256_streams_file(tmp_path) -> None:
    import hashlib

    path = tmp_path / "x.bin"
    payload = b"hello world\n" * 100
    path.write_bytes(payload)
    assert compute_file_sha256(str(path)) == hashlib.sha256(payload).hexdigest()
