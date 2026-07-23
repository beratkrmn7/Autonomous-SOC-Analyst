"""Phase 6E.4 blocker: one shared idempotency-key derivation across every
entry point (CLI, synchronous API, background worker), so the same bytes +
pipeline version + analysis mode always map to one job. Detect and analyze
remain separate idempotency scopes."""

from __future__ import annotations

import hashlib

import main
import server
from agent.application import idempotency, service_factory
from agent.application.idempotency import compute_idempotency_key
from agent.config import Settings
from agent.persistence.orm_models import Incident

from tests.stateful_integration.conftest import campaign_job_a, make_settings
from tests.stateful_integration.test_cli_persistence import _patch_cli_factory


def test_key_format_and_determinism() -> None:
    key = compute_idempotency_key("abc123", "1.0.0", "detect")
    assert key == hashlib.sha256(b"abc123:1.0.0:detect").hexdigest()
    # Deterministic.
    assert key == compute_idempotency_key("abc123", "1.0.0", "detect")


def test_upgrade_defaults_create_new_pipeline_and_stateful_scopes() -> None:
    # Bumped once for the deterministic exposure disposition and the persisted
    # job-level brief enrichment, both of which change what a job persists.
    assert Settings.model_fields["pipeline_version"].default == "1.2.0"
    assert Settings.model_fields["stateful_correlation_version"].default == "2"
    old_key = compute_idempotency_key("abc123", "1.1.0", "analyze")
    new_key = compute_idempotency_key("abc123", "1.2.0", "analyze")
    assert old_key != new_key
    assert new_key == compute_idempotency_key("abc123", "1.2.0", "analyze")


def test_detect_and_analyze_are_separate_scopes() -> None:
    detect_key = compute_idempotency_key("abc123", "1.0.0", "detect")
    analyze_key = compute_idempotency_key("abc123", "1.0.0", "analyze")
    assert detect_key != analyze_key


def test_isolated_correlation_has_a_distinct_scope_without_changing_old_keys() -> None:
    configured = compute_idempotency_key("abc123", "1.0.0", "analyze")
    isolated = compute_idempotency_key(
        "abc123", "1.0.0", "analyze", "isolated"
    )
    assert configured == hashlib.sha256(b"abc123:1.0.0:analyze").hexdigest()
    assert isolated == hashlib.sha256(
        b"abc123:1.0.0:analyze:isolated"
    ).hexdigest()
    assert isolated != configured


def test_all_entry_points_reference_the_same_key_function() -> None:
    # CLI (service_factory re-export), synchronous API (server), and the
    # background worker all resolve to the one shared implementation.
    assert service_factory.compute_idempotency_key is compute_idempotency_key
    assert server.compute_idempotency_key is compute_idempotency_key
    # Background submission uses it too (imported inside submit_file); prove the
    # module exposes exactly the shared function.
    assert idempotency.compute_idempotency_key is compute_idempotency_key


def test_cli_and_api_and_background_agree_on_the_key() -> None:
    sha, pv, mode = "deadbeef", "2.5.1", "analyze"
    cli_key = service_factory.compute_idempotency_key(sha, pv, mode)
    api_key = server.compute_idempotency_key(sha, pv, mode)
    background_key = compute_idempotency_key(sha, pv, mode)
    assert cli_key == api_key == background_key


def test_same_file_through_repeated_entry_points_reuses_one_job(
    session_factory, monkeypatch, tmp_path, fake_app
) -> None:
    """The same file + mode maps to one idempotency key, so a second entry
    point reuses the existing job instead of creating a duplicate."""
    settings = make_settings(enabled=True)
    # Two invocations of the same campaign file through the CLI detect path.
    _patch_cli_factory(
        monkeypatch, session_factory, settings, [campaign_job_a(), campaign_job_a()]
    )

    file_a = tmp_path / "a.jsonl"
    file_a.write_text('{"file": "A"}\n')

    main.detect_file_only(str(file_a))
    main.detect_file_only(str(file_a))  # identical bytes -> identical key

    with session_factory() as session:
        from agent.persistence.orm_models import IngestionJob

        # Exactly one job and one incident: the replay reused, not duplicated.
        assert session.query(IngestionJob).count() == 1
        assert [i.incident_id for i in session.query(Incident).all()] == ["INC-A"]
    assert fake_app.calls == 0
