"""T-A: the batch enrichment contract, validation and bilingual rendering."""

from __future__ import annotations

from rich.console import Console

from agent.application.brief_enrichment_service import enrich_brief_items
from agent.detection.models import DetectionEvidence, IncidentBundle
from agent.detection.presentation import build_brief_selection
from agent.detection.rollup import build_rollup
from agent.triage.brief import render_soc_brief
from agent.triage.enrichment import (
    MAX_ACTIONS,
    MAX_BATCH_ITEMS,
    MAX_EXPLANATION_CHARS,
    MIN_ACTIONS,
    BriefEnrichmentResult,
    build_enrichment_request,
    deserialize_result,
    serialize_result,
    validate_enrichment_payload,
)
from agent.triage.provider import BriefEnrichmentProviderResponse

from tests.fixtures.sanitized_real_log import (
    DOCKER_EXPOSURE,
    REDIS_EXPOSURE_MULTI_PACKET,
    SSH_SWEEP_PORT_22,
)


def _incident(events, incident_id="INC-1", severity="high") -> IncidentBundle:
    return IncidentBundle(
        incident_id=incident_id,
        incident_type="inbound_sensitive_service_allowed",
        incident_family="firewall_exposure",
        title="Externally allowed sensitive service",
        severity=severity,
        confidence=0.8,
        first_seen=min(e.timestamp for e in events),
        last_seen=max(e.timestamp for e in events),
        primary_entity=events[0].dst_ip,
        target_entities=[],
        signal_ids=["SIG-1"],
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


def _selection(events, **kwargs):
    incident = _incident(events, **kwargs)
    lookup = {e.event_id: e for e in events}
    return build_brief_selection([incident], lookup), lookup


class RecordingProvider:
    def __init__(self, payload=None, error=None):
        self.calls = 0
        self.payload = payload
        self.error = error
        self.last_request = None

    def invoke_brief_enrichment(self, request):
        self.calls += 1
        self.last_request = request
        if self.error:
            raise self.error
        payload = self.payload
        if payload is None:
            payload = {
                "items": [
                    {
                        "item_id": item_id,
                        "explanation_en": "The service is externally reachable.",
                        "explanation_tr": "Servise dışarıdan erişilebiliyor.",
                        "recommended_actions_en": ["Confirm intent.", "Restrict access."],
                        "recommended_actions_tr": ["Amacı doğrulayın.", "Erişimi kısıtlayın."],
                    }
                    for item_id in request.item_ids
                ]
            }
        return BriefEnrichmentProviderResponse(raw_payload=payload)


# 1 / 2. A fresh brief with rows and an available provider makes exactly one
# logical batch invocation.
def test_selected_rows_make_exactly_one_logical_invocation() -> None:
    selection, _ = _selection(list(SSH_SWEEP_PORT_22))
    provider = RecordingProvider()

    result = enrich_brief_items(
        selection.all_items, llm_enabled=True, provider_builder=lambda: provider
    )

    assert provider.calls == 1
    assert result.provider_invocation_count == 1
    assert len(result.items) == len(selection.all_items)


# 4. LLM disabled: zero invocations, complete service-specific fallback.
def test_disabled_llm_makes_zero_invocations_with_complete_fallback() -> None:
    selection, _ = _selection([DOCKER_EXPOSURE])
    provider = RecordingProvider()

    result = enrich_brief_items(
        selection.all_items, llm_enabled=False, provider_builder=lambda: provider
    )

    assert provider.calls == 0
    assert result.provider_invocation_count == 0
    assert result.enrichment_failure_reason == "llm_disabled"
    entry = result.items[0]
    assert entry.deterministic_fallback is True
    # Service-specific, not a generic placeholder.
    assert "Docker" in entry.explanation_en
    assert "Docker" in entry.explanation_tr
    assert MIN_ACTIONS <= len(entry.recommended_actions_en) <= MAX_ACTIONS
    assert MIN_ACTIONS <= len(entry.recommended_actions_tr) <= MAX_ACTIONS


def test_no_selected_rows_make_zero_invocations() -> None:
    provider = RecordingProvider()
    result = enrich_brief_items(
        [], llm_enabled=True, provider_builder=lambda: provider
    )
    assert provider.calls == 0
    assert result.provider_invocation_count == 0
    assert result.items == ()


def test_provider_failure_counts_one_attempt_and_falls_back() -> None:
    selection, _ = _selection([REDIS_EXPOSURE_MULTI_PACKET])
    provider = RecordingProvider(error=RuntimeError("circuit open"))

    result = enrich_brief_items(
        selection.all_items, llm_enabled=True, provider_builder=lambda: provider
    )

    assert provider.calls == 1
    assert result.provider_invocation_count == 1
    assert result.enrichment_failure_reason == "RuntimeError"
    assert all(item.deterministic_fallback for item in result.items)


# 7. An unseen IP/hostname/port rejects only that item.
def test_unseen_facts_reject_only_the_offending_item() -> None:
    # Two different services, so they are two distinct rows rather than one
    # source/service group.
    ssh_events = list(SSH_SWEEP_PORT_22[:2])
    docker_events = [DOCKER_EXPOSURE]
    incident_a = _incident(ssh_events, incident_id="INC-A")
    incident_b = _incident(docker_events, incident_id="INC-B")
    lookup = {e.event_id: e for e in ssh_events + docker_events}
    selection = build_brief_selection([incident_a, incident_b], lookup)
    items = selection.all_items
    assert len(items) == 2

    payload = {
        "items": [
            {
                "item_id": items[0].item_id,
                "explanation_en": "Traffic reached 9.9.9.9 unexpectedly.",
                "explanation_tr": "Trafik beklenmedik şekilde 9.9.9.9 adresine ulaştı.",
                "recommended_actions_en": ["Check it.", "Restrict it."],
                "recommended_actions_tr": ["Kontrol edin.", "Kısıtlayın."],
            },
            {
                "item_id": items[1].item_id,
                "explanation_en": "The service is externally reachable.",
                "explanation_tr": "Servise dışarıdan erişilebiliyor.",
                "recommended_actions_en": ["Confirm intent.", "Restrict access."],
                "recommended_actions_tr": ["Amacı doğrulayın.", "Erişimi kısıtlayın."],
            },
        ]
    }
    accepted, rejected = validate_enrichment_payload(payload, items)

    assert rejected[items[0].item_id] == "unseen_ip_address"
    assert [entry.item_id for entry in accepted] == [items[1].item_id]


def test_unsupported_claims_are_rejected() -> None:
    selection, _ = _selection([DOCKER_EXPOSURE])
    items = selection.all_items
    for text in (
        "The host was compromised by the attacker.",
        "The attacker successfully authenticated to the service.",
        "This was exploited to gain shell access.",
        "Malware was installed on the host.",
        "This will cause significant financial loss.",
    ):
        payload = {
            "items": [
                {
                    "item_id": items[0].item_id,
                    "explanation_en": text,
                    "explanation_tr": "Servise dışarıdan erişilebiliyor.",
                    "recommended_actions_en": ["Confirm intent.", "Restrict access."],
                    "recommended_actions_tr": ["Amacı doğrulayın.", "Erişimi kısıtlayın."],
                }
            ]
        }
        _, rejected = validate_enrichment_payload(payload, items)
        assert rejected[items[0].item_id] == "unsupported_claim", text


# 8. Unknown item IDs are dropped.
def test_unknown_item_ids_are_dropped() -> None:
    selection, _ = _selection([DOCKER_EXPOSURE])
    items = selection.all_items
    payload = {
        "items": [
            {
                "item_id": "not-a-real-id",
                "explanation_en": "Something.",
                "explanation_tr": "Bir şey.",
                "recommended_actions_en": ["A.", "B."],
                "recommended_actions_tr": ["A.", "B."],
            }
        ]
    }
    accepted, rejected = validate_enrichment_payload(payload, items)
    assert accepted == ()
    assert "not-a-real-id" not in rejected
    assert rejected[items[0].item_id] == "missing_item"


# 9. A missing item receives deterministic fallback.
def test_missing_item_receives_deterministic_fallback() -> None:
    selection, _ = _selection([DOCKER_EXPOSURE])
    provider = RecordingProvider(payload={"items": []})

    result = enrich_brief_items(
        selection.all_items, llm_enabled=True, provider_builder=lambda: provider
    )

    assert len(result.items) == len(selection.all_items)
    assert all(item.deterministic_fallback for item in result.items)


# 10. Deterministic values never depend on the model response.
def test_deterministic_values_are_unchanged_by_model_output() -> None:
    selection, _ = _selection([DOCKER_EXPOSURE])
    before = selection.all_items[0]

    provider = RecordingProvider(
        payload={
            "items": [
                {
                    "item_id": before.item_id,
                    "explanation_en": "Everything is fine and low risk.",
                    "explanation_tr": "Her şey yolunda.",
                    "recommended_actions_en": ["Ignore.", "Close."],
                    "recommended_actions_tr": ["Yoksayın.", "Kapatın."],
                }
            ]
        }
    )
    enrich_brief_items(
        selection.all_items, llm_enabled=True, provider_builder=lambda: provider
    )

    after = selection.all_items[0]
    assert after.severity == before.severity == "high"
    assert after.verdict == before.verdict
    assert after.confidence == before.confidence
    assert after.event_count == before.event_count
    assert after.packet_count == before.packet_count == 56
    assert after.evidence_ids == before.evidence_ids


def test_request_is_bounded_and_carries_no_raw_records() -> None:
    events = list(SSH_SWEEP_PORT_22) * 6
    incidents = [
        _incident([event], incident_id=f"INC-{index}")
        for index, event in enumerate(events)
    ]
    lookup = {e.event_id: e for e in events}
    selection = build_brief_selection(
        [*incidents], lookup, max_items_per_section=20
    )
    request = build_enrichment_request(selection.all_items)

    assert len(request.items) <= MAX_BATCH_ITEMS
    serialized = request.model_dump_json()
    assert "parser_metadata" not in serialized
    assert "safe_message_excerpt" not in serialized
    assert "raw_record_hash" not in serialized


def test_bounds_are_enforced_on_the_response() -> None:
    selection, _ = _selection([DOCKER_EXPOSURE])
    items = selection.all_items
    too_long = "x" * (MAX_EXPLANATION_CHARS + 1)
    payload = {
        "items": [
            {
                "item_id": items[0].item_id,
                "explanation_en": too_long,
                "explanation_tr": "Kısa.",
                "recommended_actions_en": ["A.", "B."],
                "recommended_actions_tr": ["A.", "B."],
            }
        ]
    }
    _, rejected = validate_enrichment_payload(payload, items)
    assert rejected[items[0].item_id] == "explanation_too_long"

    one_action = {
        "items": [
            {
                "item_id": items[0].item_id,
                "explanation_en": "Fine.",
                "explanation_tr": "Tamam.",
                "recommended_actions_en": ["Only one."],
                "recommended_actions_tr": ["Sadece bir."],
            }
        ]
    }
    _, rejected = validate_enrichment_payload(one_action, items)
    assert rejected[items[0].item_id] == "action_count_out_of_bounds"


def test_markdown_tables_and_urls_are_rejected() -> None:
    selection, _ = _selection([DOCKER_EXPOSURE])
    items = selection.all_items
    for text, reason in (
        ("| col | col |", "markdown_table"),
        ("See https://example.com for details.", "url"),
    ):
        payload = {
            "items": [
                {
                    "item_id": items[0].item_id,
                    "explanation_en": text,
                    "explanation_tr": "Tamam.",
                    "recommended_actions_en": ["A.", "B."],
                    "recommended_actions_tr": ["A.", "B."],
                }
            ]
        }
        _, rejected = validate_enrichment_payload(payload, items)
        assert rejected[items[0].item_id] == reason


# 6. English and Turkish come from the same persisted artifact.
def test_both_languages_render_from_one_persisted_artifact() -> None:
    events = [DOCKER_EXPOSURE]
    incident = _incident(events)
    lookup = {e.event_id: e for e in events}
    selection = build_brief_selection([incident], lookup)
    provider = RecordingProvider()
    enrichment = enrich_brief_items(
        selection.all_items, llm_enabled=True, provider_builder=lambda: provider
    )
    assert provider.calls == 1

    # Round-trip through the persisted artifact form.
    restored = deserialize_result(serialize_result(enrichment))
    assert restored is not None

    rollup = build_rollup([incident], lookup)
    outputs = {}
    for lang in ("en", "tr"):
        console = Console(record=True, width=160, color_system=None)
        render_soc_brief(
            console,
            rollup=rollup,
            event_lookup=lookup,
            source_name="firewall.json",
            job_id="job-1",
            provider_call_count=0,
            selection=selection,
            enrichment=restored,
            lang=lang,
        )
        outputs[lang] = console.export_text()

    assert "The service is externally reachable." in outputs["en"]
    assert "Servise dışarıdan erişilebiliyor." in outputs["tr"]
    # Rendering a second language triggered no additional provider call.
    assert provider.calls == 1


# 11. Every needs_review item is visible in INVESTIGATE.
def test_needs_review_items_are_visible_in_investigate() -> None:
    incident = _incident(list(SSH_SWEEP_PORT_22))
    # An exposure incident with no resolvable canonical events is the genuine
    # deterministic review condition.
    selection = build_brief_selection([incident], {})
    review_items = [
        item for item in selection.all_items if item.verdict == "needs_review"
    ]
    assert review_items
    assert all(item in selection.investigate for item in review_items)
    assert len(selection.investigate) >= len(review_items)


def test_artifact_round_trip_rejects_a_foreign_schema_version() -> None:
    result = BriefEnrichmentResult(items=())
    payload = serialize_result(result).replace(
        result.schema_version, "some-other-version"
    )
    assert deserialize_result(payload) is None


# --- Validator keeps useful enrichment (blocker 5) -----------------------


def test_normal_safe_response_is_accepted_not_forced_to_fallback() -> None:
    """A realistic, careful answer must survive validation intact."""
    selection, _ = _selection([DOCKER_EXPOSURE])
    provider = RecordingProvider(
        payload={
            "items": [
                {
                    "item_id": selection.all_items[0].item_id,
                    "explanation_en": (
                        "The container management API grants administrative "
                        "control over the host that runs it, so reachability "
                        "from outside the perimeter is significant on its own. "
                        "The observed evidence does not prove compromise."
                    ),
                    "explanation_tr": (
                        "Konteyner yönetim API'si, üzerinde çalıştığı sunucu "
                        "üzerinde yönetimsel denetim sağlar; bu nedenle çevre "
                        "dışından erişilebilir olması tek başına önemlidir."
                    ),
                    "recommended_actions_en": [
                        "Confirm whether this management API should be published.",
                        "Bind the daemon to a local socket and require mutual TLS.",
                        "Review the host for unexpected container activity.",
                    ],
                    "recommended_actions_tr": [
                        "Bu yönetim API'sinin yayınlanması gerekip gerekmediğini doğrulayın.",
                        "Daemon'ı yerel sokete bağlayın ve karşılıklı TLS zorunlu kılın.",
                        "Sunucuda beklenmeyen konteyner etkinliğini inceleyin.",
                    ],
                }
            ]
        }
    )

    result = enrich_brief_items(
        selection.all_items, llm_enabled=True, provider_builder=lambda: provider
    )

    assert provider.calls == 1
    assert result.enrichment_failure_reason is None
    entry = result.items[0]
    assert entry.deterministic_fallback is False
    assert "container management API" in entry.explanation_en
    assert len(entry.recommended_actions_en) == 3
    assert len(entry.recommended_actions_tr) == 3


def test_safe_negated_phrasing_is_not_rejected() -> None:
    selection, _ = _selection([DOCKER_EXPOSURE])
    items = selection.all_items
    for text in (
        "The firewall permitted the traffic; this does not prove compromise.",
        "Nothing observed proves exploitation of the service.",
        "This is not evidence of malware on the host.",
        "No compromise was proven by these records.",
    ):
        payload = {
            "items": [
                {
                    "item_id": items[0].item_id,
                    "explanation_en": text,
                    "explanation_tr": "Servise dışarıdan erişilebiliyor.",
                    "recommended_actions_en": ["Confirm intent.", "Restrict access."],
                    "recommended_actions_tr": ["Amacı doğrulayın.", "Erişimi kısıtlayın."],
                }
            ]
        }
        accepted, rejected = validate_enrichment_payload(payload, items)
        assert not rejected, (text, rejected)
        assert len(accepted) == 1


def test_affirmative_claims_are_still_rejected_after_negation_support() -> None:
    selection, _ = _selection([DOCKER_EXPOSURE])
    items = selection.all_items
    for text in (
        "The host was compromised through this exposure.",
        "An attacker exploited the service.",
        "The session shows the attacker authenticated successfully.",
        "Malware was deployed to the host.",
        "Expect material financial loss from this incident.",
    ):
        payload = {
            "items": [
                {
                    "item_id": items[0].item_id,
                    "explanation_en": text,
                    "explanation_tr": "Servise dışarıdan erişilebiliyor.",
                    "recommended_actions_en": ["Confirm intent.", "Restrict access."],
                    "recommended_actions_tr": ["Amacı doğrulayın.", "Erişimi kısıtlayın."],
                }
            ]
        }
        _, rejected = validate_enrichment_payload(payload, items)
        assert rejected.get(items[0].item_id) == "unsupported_claim", text
