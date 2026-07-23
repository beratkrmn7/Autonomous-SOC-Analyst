"""Cross-job provenance and digest statements are language-aware.

Both render deterministic counters. Only the words around the numbers change,
and nothing persisted is rewritten.
"""

from __future__ import annotations

import pytest

import main
from agent.detection.models import DetectionEvidence, IncidentBundle
from agent.triage.localization import (
    render_deterministic_report,
    render_digest_statement,
)
from agent.triage.provenance import format_event_provenance
from agent.triage.routing import build_digest, generate_deterministic_report

from tests.fixtures.sanitized_real_log import DOCKER_EXPOSURE


#: English provenance wording that must not survive into Turkish output.
ENGLISH_PROVENANCE_PHRASES = (
    "this run",
    "from earlier job",
    "from earlier jobs",
    "earlier job",
    "earlier jobs",
)

#: The cross-job counters a promoted canonical incident carries.
CROSS_JOB_METRICS = {
    "contributing_job_count": 3,
    "current_job_event_count": 4,
    "prior_job_event_count": 6,
}


def _cross_job_incident(events) -> IncidentBundle:
    return IncidentBundle(
        incident_id="INC-XJOB",
        incident_type="critical_management_service_exposed",
        incident_family="firewall_exposure",
        title="Externally allowed critical management service",
        severity="high",
        confidence=0.8,
        first_seen=min(e.timestamp for e in events),
        last_seen=max(e.timestamp for e in events),
        primary_entity=events[0].dst_ip,
        target_entities=[],
        signal_ids=["SIG-XJOB"],
        event_ids=[e.event_id for e in events],
        context_event_ids=[],
        evidence=[
            DetectionEvidence(
                event_id=events[0].event_id,
                quote="",
                reason="allowed",
                source="detection",
                original_fields={},
                correlation_context={},
            )
        ],
        metrics=dict(CROSS_JOB_METRICS),
        mitre_techniques=[],
        merge_key="xjob",
    )


def test_english_provenance_is_unchanged() -> None:
    assert format_event_provenance(10, CROSS_JOB_METRICS) == (
        "10 (4 this run, 6 from 2 earlier jobs)"
    )
    assert format_event_provenance(
        10, {**CROSS_JOB_METRICS, "contributing_job_count": 2}
    ) == "10 (4 this run, 6 from 1 earlier job)"


def test_turkish_provenance_uses_no_english_phrases() -> None:
    rendered = format_event_provenance(10, CROSS_JOB_METRICS, "tr")
    for phrase in ENGLISH_PROVENANCE_PHRASES:
        assert phrase not in rendered, phrase


def test_provenance_preserves_the_exact_numeric_facts() -> None:
    for lang in ("en", "tr"):
        rendered = format_event_provenance(10, CROSS_JOB_METRICS, lang)
        # total, current-run, prior events and prior job count all survive.
        assert "10" in rendered
        assert "4" in rendered
        assert "6" in rendered
        assert "2" in rendered


def test_single_job_provenance_is_a_bare_count_in_both_languages() -> None:
    for lang in ("en", "tr"):
        assert format_event_provenance(7, {}, lang) == "7"


def test_turkish_cross_job_report_has_no_english_provenance(capsys) -> None:
    """Stateful regression: a promoted incident rendered in Turkish."""
    events = [DOCKER_EXPOSURE]
    incident = _cross_job_incident(events)
    lookup = {e.event_id: e for e in events}

    stored = generate_deterministic_report(incident, events)
    assert "this run" in stored  # the persisted English body is unchanged

    turkish = render_deterministic_report(incident, events, "tr")
    for phrase in ENGLISH_PROVENANCE_PHRASES:
        assert phrase not in turkish, phrase
    assert "4" in turkish and "6" in turkish

    # ...and through the full-mode print path.
    class _Detection:
        incidents = [incident]

        class metrics:
            parsed_records = 1
            signal_count = 1
            suppressed_signal_count = 0
            duplicate_signal_count = 0
            incident_count = 1

    class _Result:
        detection_result = _Detection()
        event_map = lookup
        brief_selection = None
        brief_enrichment = None

    state = {
        "incident_id": "INC-XJOB",
        "triage_route": "individual_triage",
        "triage_verdict": "suspicious_activity",
        "incident_type": "critical_management_service_exposed",
        "severity": "high",
        "iteration_count": 0,
        "final_report": stored,
    }
    main._print_incident_state(state, _Result(), lang="tr")
    output = capsys.readouterr().out

    for phrase in ENGLISH_PROVENANCE_PHRASES:
        assert phrase not in output, phrase
    assert state["final_report"] == stored  # persisted body untouched


# --- Digest statement -----------------------------------------------------


def _digest():
    from agent.triage.routing import DigestMember

    events = [DOCKER_EXPOSURE]
    return build_digest(
        "repeated_blocked_scanner",
        [
            DigestMember(
                incident_id="INC-D1",
                primary_entity="192.0.2.10",
                events=events,
                first_seen=events[0].timestamp,
                last_seen=events[0].timestamp,
            )
        ],
    )


def test_persisted_digest_statement_is_english_and_unchanged() -> None:
    digest = _digest()
    assert "No allowed connection was observed" in digest["statement"]


@pytest.mark.parametrize(
    "phrase",
    (
        "No allowed connection was observed",
        "blocked reconnaissance",
        "in this digest",
    ),
)
def test_turkish_digest_statement_has_no_english_text(phrase: str) -> None:
    assert phrase not in render_digest_statement(_digest(), "tr")


def test_digest_statement_is_derived_from_the_digest_counters() -> None:
    digest = _digest()
    blocked = digest["total_blocked_events"]
    for lang in ("en", "tr"):
        rendered = render_digest_statement(digest, lang)
        assert str(blocked) in rendered
    # The stored statement is never mutated by rendering.
    assert "No allowed connection was observed" in digest["statement"]


def test_turkish_routing_summary_does_not_print_the_english_statement(capsys) -> None:
    digest = _digest()

    class _Result:
        routing_metrics = {
            "individual_triage_count": 0,
            "deterministic_report_count": 0,
            "digest_incident_count": 1,
            "store_only_count": 0,
            "provider_invocation_count": 0,
        }
        triage_digests = [digest]

    main._print_routing_summary(_Result(), "tr")
    output = capsys.readouterr().out

    assert "No allowed connection was observed" not in output
    assert "blocked reconnaissance" not in output
    assert "engellenen keşif" in output
    # The persisted digest is untouched.
    assert "No allowed connection was observed" in digest["statement"]


def test_english_routing_summary_still_shows_its_statement(capsys) -> None:
    digest = _digest()

    class _Result:
        routing_metrics = {"digest_incident_count": 1}
        triage_digests = [digest]

    main._print_routing_summary(_Result(), "en")
    output = capsys.readouterr().out
    assert "No allowed connection was observed" in output


def test_digest_rendering_is_provider_free(monkeypatch) -> None:
    def provider_forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("provider call attempted while rendering a digest")

    monkeypatch.setattr(
        "agent.triage.provider_factory.build_provider", provider_forbidden
    )
    for lang in ("en", "tr"):
        assert render_digest_statement(_digest(), lang)
