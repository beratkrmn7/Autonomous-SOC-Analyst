"""T-A: brief and full modes are two views of one persisted analysis."""

from __future__ import annotations

import agent.application.analysis_service as svc_mod
from agent.persistence.orm_models import IngestionJob, Report
from agent.triage.enrichment import REPORT_FORMAT
from agent.triage.routing import RoutingDecision

from tests.stateful_integration.conftest import campaign_job_a, make_settings
from tests.stateful_integration.test_cli_persistence import _patch_cli_factory


def _force_enrichment_eligible(monkeypatch) -> None:
    monkeypatch.setattr(
        svc_mod,
        "decide_route",
        lambda *a, **k: RoutingDecision(
            route="individual_triage",
            reason="forced-for-test",
            triage_origin="deterministic",
            llm_invoked=False,
        ),
    )


# 5. Brief and full modes reuse the same job and produce the same analysis.
def test_brief_and_full_modes_reuse_one_job(
    session_factory, fake_app, monkeypatch, tmp_path
) -> None:
    import main

    settings = make_settings(enabled=True)
    _force_enrichment_eligible(monkeypatch)
    _patch_cli_factory(
        monkeypatch,
        session_factory,
        settings,
        [campaign_job_a(), campaign_job_a()],
        llm_enabled=True,
    )

    log_file = tmp_path / "a.jsonl"
    log_file.write_text('{"file": "A"}\n')

    brief = main.analyze_file(str(log_file), report_mode="brief")
    full = main.analyze_file(str(log_file), report_mode="full")

    # One job, reused rather than recreated.
    assert brief.job_id == full.job_id
    assert full.reused is True
    with session_factory() as session:
        assert session.query(IngestionJob).count() == 1

    # The same deterministic analysis in both views.
    assert [state.get("incident_id") for state in brief.incidents] == [
        state.get("incident_id") for state in full.incidents
    ]
    assert [state.get("severity") for state in brief.incidents] == [
        state.get("severity") for state in full.incidents
    ]
    assert [state.get("triage_verdict") for state in brief.incidents] == [
        state.get("triage_verdict") for state in full.incidents
    ]

    # 3. The second run is a replay: zero provider invocations, one artifact.
    assert fake_app.calls == 1
    assert brief.routing_metrics["provider_invocation_count"] == 1
    assert full.routing_metrics["provider_invocation_count"] == 0
    with session_factory() as session:
        assert session.query(Report).filter_by(format=REPORT_FORMAT).count() == 1

    # Full mode still sees the persisted enrichment text.
    assert full.brief_enrichment is not None
    assert full.brief_enrichment.items


def test_replay_renders_either_language_without_a_provider_call(
    session_factory, fake_app, monkeypatch, tmp_path
) -> None:
    import main

    settings = make_settings(enabled=True)
    _force_enrichment_eligible(monkeypatch)
    _patch_cli_factory(
        monkeypatch,
        session_factory,
        settings,
        [campaign_job_a(), campaign_job_a(), campaign_job_a()],
        llm_enabled=True,
    )

    log_file = tmp_path / "a.jsonl"
    log_file.write_text('{"file": "A"}\n')

    main.analyze_file(str(log_file), report_mode="brief", lang="en")
    assert fake_app.calls == 1

    english = main.analyze_file(str(log_file), report_mode="brief", lang="en")
    turkish = main.analyze_file(str(log_file), report_mode="brief", lang="tr")

    # Both replays served from the one persisted bilingual artifact.
    assert fake_app.calls == 1
    assert english.routing_metrics["provider_invocation_count"] == 0
    assert turkish.routing_metrics["provider_invocation_count"] == 0
    assert english.brief_enrichment is not None
    assert turkish.brief_enrichment is not None
    assert english.brief_enrichment.items == turkish.brief_enrichment.items
    for item in turkish.brief_enrichment.items:
        assert item.explanation_en
        assert item.explanation_tr
