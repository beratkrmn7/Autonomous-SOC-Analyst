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


# --- Language-aware titles and ATT&CK rendering --------------------------

#: Presentation text that must never appear in a Turkish brief.
ENGLISH_PRESENTATION_TEXT = (
    "ATT&CK context",
    "Network Service Discovery",
    "External Remote Services",
    "context only",
    "Externally allowed",
    "Fixed source port",
    "insufficient behavioral evidence",
)

#: Deterministic identifiers that must survive in every language.
PRESERVED_IDENTIFIERS = ("T1046", "TA0007")


@pytest.mark.parametrize("phrase", ENGLISH_PRESENTATION_TEXT)
def test_turkish_brief_contains_no_english_presentation_text(phrase: str) -> None:
    assert phrase not in _render("tr")


def test_turkish_brief_preserves_attack_identifiers() -> None:
    output = _render("tr")
    for identifier in PRESERVED_IDENTIFIERS:
        assert identifier in output
    assert "ATT&CK bağlamı" in output


def test_turkish_brief_does_not_show_the_canonical_english_title() -> None:
    events = [DOCKER_EXPOSURE, *SSH_SWEEP_PORT_22]
    incident = _incident(events)
    lookup = {e.event_id: e for e in events}
    selection = build_brief_selection([incident], lookup)

    # The canonical English title is still the stored identity...
    assert any("Externally allowed" in item.title for item in selection.all_items)
    # ...but it is not what the Turkish brief renders.
    assert "Externally allowed" not in _render("tr")


def test_display_titles_are_language_aware_for_every_row_kind() -> None:
    from agent.detection.fixed_source_port_cluster import FixedSourcePortCluster
    from agent.detection.presentation import (
        item_from_exposure_group,
        item_from_scan_cluster,
    )
    from agent.triage.localization import render_item_title
    from datetime import datetime, timedelta, timezone

    events = [DOCKER_EXPOSURE]
    incident = _incident(events)
    lookup = {e.event_id: e for e in events}
    selection = build_brief_selection([incident], lookup)
    incident_item = selection.all_items[0]

    from agent.detection.presentation import build_exposure_groups

    group = build_exposure_groups([incident], lookup)[0]
    group_item = item_from_exposure_group(group)

    now = datetime(2026, 7, 10, tzinfo=timezone.utc)
    cluster_item = item_from_scan_cluster(
        FixedSourcePortCluster(
            cluster_id="fsp:203.0.113.0/24:443",
            source_cidr="203.0.113.0/24",
            contributing_source_ips=("203.0.113.102", "203.0.113.111"),
            fixed_source_port=443,
            event_count=7,
            allowed_event_count=7,
            blocked_event_count=0,
            distinct_destination_ip_count=2,
            distinct_destination_port_count=6,
            destination_ports=(22, 80, 179, 443, 3306, 3389),
            sensitive_destination_ports=(22, 3306, 3389),
            event_ids=("e1",),
            first_seen=now,
            last_seen=now + timedelta(seconds=1),
            severity="high",
        )
    )

    for item in (incident_item, group_item, cluster_item):
        english = render_item_title(item, "en")
        turkish = render_item_title(item, "tr")
        assert english and turkish
        assert english != turkish, item.kind

    # Deterministic values survive inside the localized titles.
    assert "443" in render_item_title(cluster_item, "tr")
    assert "docker" in render_item_title(group_item, "tr")


def test_attack_context_ids_are_never_translated() -> None:
    from agent.triage.attack_context import (
        AttackContext,
        UNSUPPORTED,
        render_attack_context,
    )

    discovery = AttackContext("T1046", "TA0007", "behavioral")
    remote = AttackContext("T1133", "TA0001", "context")

    for context in (discovery, remote):
        for lang in ("en", "tr"):
            rendered = render_attack_context(context, lang)
            assert context.technique in rendered
            assert context.tactic in rendered

    assert "Network Service Discovery" in render_attack_context(discovery, "en")
    assert "Network Service Discovery" not in render_attack_context(discovery, "tr")
    assert "External Remote Services" not in render_attack_context(remote, "tr")
    assert "context only" not in render_attack_context(remote, "tr")

    assert "insufficient behavioral evidence" in render_attack_context(
        UNSUPPORTED, "en"
    )
    assert "insufficient behavioral evidence" not in render_attack_context(
        UNSUPPORTED, "tr"
    )


def test_english_brief_output_is_unchanged_by_localization() -> None:
    """The English brief still uses its original wording."""
    output = _render("en")
    for phrase in (
        "SOC TRIAGE BRIEF",
        "ANALYST SUMMARY",
        "§1 ACT NOW",
        "§5 EXPOSED ASSET INVENTORY",
        "Provider calls for this request",
        "ATT&CK context",
    ):
        assert phrase in output


# --- Full mode ------------------------------------------------------------

#: Analysis-summary labels that must not appear in Turkish full mode.
ENGLISH_SUMMARY_LABELS = (
    "--- ANALYSIS SUMMARY ---",
    "Parsed/valid events",
    "Detected signals",
    "Suppressed signals",
    "Duplicate signals removed",
    "Final incidents",
    "Reports:",
    "Starting File Analysis",
    "--- TRIAGE ROUTING SUMMARY ---",
)

#: Deterministic-report headings that must not be printed untranslated.
ENGLISH_REPORT_HEADINGS = (
    "Deterministic Report",
    "Observed activity",
    "Distinct targets",
    "were blocked by the firewall",
)


class _Metrics:
    parsed_records = 10
    signal_count = 3
    suppressed_signal_count = 1
    duplicate_signal_count = 2
    incident_count = 1


class _Ingestion:
    metrics = _Metrics()


class _Detection:
    metrics = _Metrics()

    def __init__(self, incidents=()):
        self.incidents = list(incidents)


class _Result:
    def __init__(self, incidents=(), event_map=None, states=()):
        self.ingestion_result = _Ingestion()
        self.detection_result = _Detection(incidents)
        self.event_map = event_map or {}
        self.incidents = list(states)
        self.routing_metrics = {
            "individual_triage_count": 1,
            "deterministic_report_count": 0,
            "digest_incident_count": 0,
            "store_only_count": 0,
            "provider_invocation_count": 1,
        }
        self.triage_digests = []
        self.brief_selection = None
        self.brief_enrichment = None


def test_turkish_full_mode_uses_no_english_summary_labels(capsys) -> None:
    result = _Result()
    main._print_analysis_summary(result, "tr")
    main._print_routing_summary(result, "tr")
    output = capsys.readouterr().out

    for label in ENGLISH_SUMMARY_LABELS:
        assert label not in output, label
    turkish = main.FULL_MODE_LABELS["tr"]
    for key in (
        "analysis_summary",
        "parsed_events",
        "detected_signals",
        "suppressed_signals",
        "duplicate_signals",
        "final_incidents",
        "reports",
        "routing_summary",
        "batch_eligible",
    ):
        assert turkish[key] in output, key


def test_english_full_mode_summary_is_unchanged(capsys) -> None:
    result = _Result()
    main._print_analysis_summary(result, "en")
    main._print_routing_summary(result, "en")
    output = capsys.readouterr().out
    for label in (
        "--- ANALYSIS SUMMARY ---",
        "Parsed/valid events",
        "Detected signals",
        "Final incidents",
        "Reports:",
    ):
        assert label in output, label


def test_turkish_full_mode_does_not_print_the_english_report_body(capsys) -> None:
    from agent.triage.routing import generate_deterministic_report

    events = [DOCKER_EXPOSURE]
    incident = _incident(events, incident_id="INC-REPORT")
    lookup = {e.event_id: e for e in events}
    stored = generate_deterministic_report(incident, events)
    # The persisted body is English, as written at analysis time.
    assert "Deterministic Report" in stored

    state = {
        "incident_id": "INC-REPORT",
        "triage_route": "individual_triage",
        "triage_verdict": "suspicious_activity",
        "incident_type": "critical_management_service_exposed",
        "severity": "high",
        "iteration_count": 0,
        "final_report": stored,
    }
    result = _Result(incidents=[incident], event_map=lookup, states=[state])

    main._print_incident_state(state, result, lang="tr")
    output = capsys.readouterr().out

    for heading in ENGLISH_REPORT_HEADINGS:
        assert heading not in output, heading
    assert "Deterministik Rapor" in output
    # Deterministic facts still appear untranslated.
    assert DOCKER_EXPOSURE.dst_ip in output
    assert "2375" in output

    # The stored report itself was not rewritten.
    assert state["final_report"] == stored


def test_english_full_mode_still_prints_the_persisted_report(capsys) -> None:
    from agent.triage.routing import generate_deterministic_report

    events = [DOCKER_EXPOSURE]
    incident = _incident(events, incident_id="INC-REPORT")
    lookup = {e.event_id: e for e in events}
    stored = generate_deterministic_report(incident, events)
    state = {
        "incident_id": "INC-REPORT",
        "triage_route": "individual_triage",
        "triage_verdict": "suspicious_activity",
        "incident_type": "critical_management_service_exposed",
        "severity": "high",
        "iteration_count": 0,
        "final_report": stored,
    }
    result = _Result(incidents=[incident], event_map=lookup, states=[state])

    main._print_incident_state(state, result, lang="en")
    output = capsys.readouterr().out
    assert "Deterministic Report" in output
    assert "Deterministik Rapor" not in output


def test_localized_report_render_is_provider_free(monkeypatch) -> None:
    from agent.triage.localization import render_deterministic_report

    def provider_forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("provider call attempted while rendering")

    monkeypatch.setattr(
        "agent.triage.provider_factory.build_provider", provider_forbidden
    )
    events = [DOCKER_EXPOSURE]
    incident = _incident(events, incident_id="INC-REPORT")
    for lang in ("en", "tr"):
        assert render_deterministic_report(incident, events, lang)
