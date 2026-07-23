"""Turkish localization of the brief and the full-mode scaffolding."""

from __future__ import annotations

import pytest
from rich.console import Console

import main
from agent.detection.models import DetectionEvidence, IncidentBundle
from agent.detection.presentation import build_brief_selection
from agent.detection.rollup import build_rollup
from agent.triage.brief import _LABELS, render_soc_brief
from agent.triage.enrichment import BriefEnrichmentResult, deterministic_fallback

from tests.fixtures.sanitized_real_log import DOCKER_EXPOSURE, SSH_SWEEP_PORT_22


#: Headings that must never survive into a Turkish brief.
ENGLISH_HEADINGS = (
    "ACT NOW",
    "INVESTIGATE",
    "BLOCKED — FYI",
    "SUPPRESSED",
    "EXPOSED ASSET INVENTORY",
    "Provider calls for this request",
)


def _squashed(text: str) -> str:
    """Drop whitespace and box-drawing characters so wrapping cannot matter."""
    return "".join(
        character
        for character in text
        if not character.isspace() and character not in "│┃|"
    )


def _incident(events, incident_id="INC-LOC") -> IncidentBundle:
    return IncidentBundle(
        incident_id=incident_id,
        incident_type="critical_management_service_exposed",
        incident_family="firewall_exposure",
        title="Externally allowed critical management service",
        severity="high",
        confidence=0.8,
        first_seen=min(e.timestamp for e in events),
        last_seen=max(e.timestamp for e in events),
        primary_entity=events[0].dst_ip,
        target_entities=[],
        signal_ids=["SIG-LOC"],
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
        metrics={},
        mitre_techniques=[],
        merge_key=incident_id,
    )


def _render(lang: str, enrichment=None) -> str:
    events = [DOCKER_EXPOSURE, *SSH_SWEEP_PORT_22]
    incident = _incident(events)
    lookup = {e.event_id: e for e in events}
    selection = build_brief_selection([incident], lookup)
    if enrichment is None:
        enrichment = BriefEnrichmentResult(
            items=tuple(deterministic_fallback(item) for item in selection.all_items)
        )
    console = Console(record=True, width=200, color_system=None)
    render_soc_brief(
        console,
        rollup=build_rollup([incident], lookup),
        event_lookup=lookup,
        source_name="firewall.json",
        job_id="job-loc",
        provider_call_count=0,
        selection=selection,
        enrichment=enrichment,
        lang=lang,
    )
    return console.export_text()


def test_english_brief_still_uses_english_headings() -> None:
    output = _render("en")
    for heading in ENGLISH_HEADINGS:
        assert heading in output


@pytest.mark.parametrize("heading", ENGLISH_HEADINGS)
def test_turkish_brief_contains_no_english_heading(heading: str) -> None:
    assert heading not in _render("tr")


def test_turkish_brief_uses_turkish_labels() -> None:
    output = _render("tr")
    labels = _LABELS["tr"]
    for key in (
        "brief_title",
        "summary_title",
        "act_now",
        "investigate",
        "blocked_fyi",
        "suppressed",
        "inventory",
        "priority",
        "evidence",
        "strength",
        "asset_destination",
        "asset_nat",
        "provider_calls",
    ):
        assert labels[key] in output, key


def test_deterministic_facts_are_never_translated() -> None:
    """IDs, addresses, ports, severities and ATT&CK IDs stay identical."""
    output = _render("tr")
    assert DOCKER_EXPOSURE.dst_ip in output
    assert "2375" in output
    assert "docker" in output
    # Severity enum values and evidence-strength values are not translated.
    assert "HIGH" in output or "high" in output
    assert "multi_packet_unidirectional" in output
    # ATT&CK identifiers are never localized.
    assert "T1046" in output or "ATT&CK" in output


def test_every_label_key_exists_in_both_languages() -> None:
    assert set(_LABELS["en"]) == set(_LABELS["tr"])
    for key, value in _LABELS["tr"].items():
        assert value.strip(), key


def test_full_mode_labels_exist_in_both_languages() -> None:
    assert set(main.FULL_MODE_LABELS["en"]) == set(main.FULL_MODE_LABELS["tr"])
    for key, value in main.FULL_MODE_LABELS["tr"].items():
        assert value.strip(), key
        # The Turkish scaffolding must not simply repeat the English string,
        # except for the deliberately identical marker punctuation.
        if key not in {"routing_summary", "analysis_summary"}:
            assert value != main.FULL_MODE_LABELS["en"][key], key


def test_full_mode_turkish_scaffolding_is_rendered(capsys) -> None:
    state = {
        "incident_id": "INC-LOC",
        "triage_route": "individual_triage",
        "triage_verdict": "suspicious_activity",
        "incident_type": "critical_management_service_exposed",
        "severity": "high",
        "iteration_count": 0,
        "detection_confidence": 0.8,
        "evidence_strength": "multi_packet_unidirectional",
    }
    main._print_incident_state(state, None, lang="tr")
    output = capsys.readouterr().out

    labels = main.FULL_MODE_LABELS["tr"]
    assert labels["final_state"] in output
    assert labels["route"] in output
    assert labels["verdict"] in output
    assert labels["severity"] in output
    assert labels["evidence_strength"] in output
    for english in ("FINAL STATE", "Verdict:", "Incident Type:", "Iterations:"):
        assert english not in output
    # Deterministic values survive untranslated.
    assert "suspicious_activity" in output
    assert "multi_packet_unidirectional" in output


def test_both_languages_reuse_one_artifact_and_call_no_provider() -> None:
    events = [DOCKER_EXPOSURE, *SSH_SWEEP_PORT_22]
    incident = _incident(events)
    lookup = {e.event_id: e for e in events}
    selection = build_brief_selection([incident], lookup)
    enrichment = BriefEnrichmentResult(
        items=tuple(deterministic_fallback(item) for item in selection.all_items),
        provider_invocation_count=1,
    )

    english = _render("en", enrichment)
    turkish = _render("tr", enrichment)

    assert english != turkish
    # One artifact served both renders; rendering never invokes a provider.
    assert enrichment.provider_invocation_count == 1
    assert enrichment.items

    # Rich wraps and interleaves table columns, so assert on distinctive
    # fragments short enough to survive on one rendered line.
    for item in enrichment.items:
        assert item.explanation_en and item.explanation_tr
    assert _squashed("The Docker daemon API") in _squashed(english)
    assert _squashed("Docker daemon API'si") in _squashed(turkish)
    # Each language shows only its own text.
    assert _squashed("The Docker daemon API") not in _squashed(turkish)
    assert _squashed("Docker daemon API'si") not in _squashed(english)
