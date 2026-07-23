"""Shared fixtures/builders for the Phase 6E.4 stateful *integration* tests.

These tests exercise the real AnalysisService persistence flow end to end
(persist events/signals -> flush -> resolve -> hydrate -> route -> triage ->
outbox -> commit) rather than the resolver in isolation, which the Phase
6E.4A ``tests/stateful_correlation`` suite already covers.

Detection itself is deterministic and covered elsewhere, so a job here injects
a prebuilt ``DetectionResult`` via a thin stub over ``DetectionEngine.analyze``
while keeping the engine's real ``settings`` (the stateful profiles and the
routing rules both read those). Everything downstream of detection - the
integration under test - runs for real against an in-memory-equivalent SQLite
database.
"""

from __future__ import annotations

import datetime
import os
import tempfile
from typing import List, Optional, Sequence

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agent.application.analysis_service import AnalysisService
from agent.application.models import AnalysisResult
from agent.config import Settings
from agent.detection.models import (
    DetectionMetrics,
    DetectionResult,
    DetectionSignal,
    IncidentBundle,
)
from agent.persistence.orm_models import Base, IngestionJob
from agent.persistence.unit_of_work import UnitOfWork
from agent.schema import CanonicalLogEvent

# Reuse the Phase 6E.4A builders so the integration campaign is byte-for-byte
# the same rdp_probe identity the foundation suite already validates.
from tests.stateful_correlation.conftest import (  # noqa: F401
    make_event,
    make_incident,
    make_signal,
)

FIXED = datetime.datetime(2026, 7, 10, 6, 0, 0, tzinfo=datetime.timezone.utc)
LATER = FIXED + datetime.timedelta(minutes=10)


@pytest.fixture
def session_factory():
    """A file-backed SQLite database, safe across the several independent
    UnitOfWork transactions one integration test opens (one per job)."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_engine(
        f"sqlite:///{path}", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    yield factory
    engine.dispose()
    try:
        os.remove(path)
    except PermissionError:
        pass


def make_settings(*, enabled: bool = True, **overrides) -> Settings:
    """Settings with the stateful feature flag and a generous correlation
    window/TTL so an adjacent-file campaign is treated as one incident."""
    values = dict(
        _env_file=None,
        stateful_correlation_enabled=enabled,
        stateful_correlation_window_seconds=3600,
        stateful_correlation_state_ttl_seconds=86400,
        opensearch_enabled=True,
    )
    values.update(overrides)
    return Settings(**values)


class CountingBatchProvider:
    """Stand-in for the batch brief-enrichment provider.

    Per-incident provider calls no longer exist; an analyze job makes at most
    one logical batch call. ``calls`` therefore counts whole-job invocations,
    so a job with no selected brief rows observes ``calls == 0`` and a job
    with rows observes exactly 1.
    """

    def __init__(self) -> None:
        self.calls = 0
        self.last_item_ids: list[str] = []

    def invoke_brief_enrichment(self, request):
        self.calls += 1
        self.last_item_ids = list(request.item_ids)
        from agent.triage.provider import BriefEnrichmentProviderResponse

        return BriefEnrichmentProviderResponse(
            raw_payload={
                "items": [
                    {
                        "item_id": item_id,
                        "explanation_en": (
                            "The exposed service is reachable from outside the "
                            "perimeter and warrants confirmation."
                        ),
                        "explanation_tr": (
                            "Açığa çıkan servise çevre dışından erişilebiliyor "
                            "ve doğrulanması gerekir."
                        ),
                        "recommended_actions_en": [
                            "Confirm whether this exposure is intended.",
                            "Restrict the rule to networks that need it.",
                        ],
                        "recommended_actions_tr": [
                            "Bu açığın amaçlanıp amaçlanmadığını doğrulayın.",
                            "Kuralı ihtiyaç duyan ağlarla sınırlayın.",
                        ],
                    }
                    for item_id in request.item_ids
                ]
            },
            prompt_tokens=100,
            completion_tokens=50,
        )


@pytest.fixture
def fake_app(monkeypatch) -> CountingBatchProvider:
    """Replace the batch enrichment provider with a counting stub."""
    provider = CountingBatchProvider()
    monkeypatch.setattr(
        "agent.triage.provider_factory.build_provider", lambda *a, **k: provider
    )
    return provider


def make_detection_result(
    *,
    events: Sequence[CanonicalLogEvent],
    signals: Sequence[DetectionSignal],
    incidents: Sequence[IncidentBundle],
    suppressed: Optional[Sequence[DetectionSignal]] = None,
    uncorrelated: Optional[Sequence[str]] = None,
) -> DetectionResult:
    return DetectionResult(
        signals=list(signals),
        incidents=list(incidents),
        suppressed_signals=list(suppressed or []),
        uncorrelated_event_ids=list(uncorrelated or []),
        warnings=[],
        metrics=DetectionMetrics(
            total_events=len(events),
            signal_count=len(signals),
            incident_count=len(incidents),
            duration_ms=1.0,
        ),
    )


def seed_processing_job(session_factory, settings: Settings, job_id: str, mode: str) -> None:
    """Create the placeholder 'processing' job the analyze flow expects to
    find and flip to 'completed' at the end of the transaction."""
    with UnitOfWork(session_factory=session_factory, settings=settings) as uow:
        uow.session.add(
            IngestionJob(
                id=job_id,
                source_name="firewall.json",
                analysis_mode=mode,
                pipeline_version="pipeline-v1",
                status="processing",
            )
        )


def run_job(
    session_factory,
    settings: Settings,
    *,
    job_id: str,
    events: Sequence[CanonicalLogEvent],
    signals: Sequence[DetectionSignal],
    incidents: Sequence[IncidentBundle],
    run_triage: bool,
    suppressed: Optional[Sequence[DetectionSignal]] = None,
    uncorrelated: Optional[Sequence[str]] = None,
    stateful_correlation_enabled: Optional[bool] = None,
    llm_enabled: bool = True,
) -> AnalysisResult:
    """Run one analysis job through the shared AnalysisService flow.

    A fresh service + UnitOfWork per job mirrors real per-request/worker usage
    and prevents any stub state from leaking across jobs. Detection is stubbed
    to the supplied ``DetectionResult``; everything downstream is real.
    """
    mode = "analyze" if run_triage else "detect"
    seed_processing_job(session_factory, settings, job_id, mode)
    det_result = make_detection_result(
        events=events,
        signals=signals,
        incidents=incidents,
        suppressed=suppressed,
        uncorrelated=uncorrelated,
    )
    service = AnalysisService(
        uow=UnitOfWork(session_factory=session_factory, settings=settings),
        llm_enabled=llm_enabled,
    )
    service.detection_engine.analyze = lambda ev, ctx: det_result  # type: ignore[assignment]
    return service._process_events(
        events=list(events),
        run_triage=run_triage,
        ingestion_result=None,
        source_name="firewall.json",
        job_id=job_id,
        stateful_correlation_enabled=stateful_correlation_enabled,
    )


# --- Campaign builders: one RDP service-probing campaign across two files. ---


def campaign_job_a() -> tuple[List[CanonicalLogEvent], DetectionSignal, IncidentBundle]:
    events = [make_event("a1", ts=FIXED)]
    signal = make_signal("SIG-A", ["a1"], ts=FIXED)
    incident = make_incident("INC-A", signal, events, ts=FIXED)
    return events, signal, incident


def campaign_job_b() -> tuple[List[CanonicalLogEvent], DetectionSignal, IncidentBundle]:
    events = [make_event("b1", ts=LATER)]
    signal = make_signal("SIG-B", ["b1"], ts=LATER)
    incident = make_incident("INC-B", signal, events, ts=LATER)
    return events, signal, incident


def unsupported_incident() -> tuple[List[CanonicalLogEvent], DetectionSignal, IncidentBundle]:
    """An incident whose family/type has no safe persistent profile, so the
    resolver returns 'unsupported' and the flow must fall back to batch-local
    persistence rather than discard the detection."""
    events = [make_event("u1", ts=FIXED, dst_port=445)]
    signal = make_signal("SIG-U", ["u1"], ts=FIXED)
    signal = signal.model_copy(
        update={
            "signal_type": "credential_stuffing",
            "signal_family": "authentication",
            "rule_id": "auth_bruteforce",
        }
    )
    incident = make_incident("INC-U", signal, events, ts=FIXED)
    incident = incident.model_copy(
        update={"incident_type": "brute_force", "incident_family": "authentication"}
    )
    return events, signal, incident
