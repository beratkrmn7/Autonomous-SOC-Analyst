"""The unsupported-claim guardrail applies in every language.

The validator checks Turkish fields, so it must also know Turkish claim
vocabulary - otherwise an affirmative Turkish claim reaches the brief while
its English twin is refused. Both pattern sets are applied to every generated
text field, which also covers mixed-language sentences.
"""

from __future__ import annotations

import pytest

from agent.application.brief_enrichment_service import enrich_brief_items
from agent.detection.models import DetectionEvidence, IncidentBundle
from agent.detection.presentation import BriefActionItem, build_brief_selection
from agent.triage.disposition import EvidenceStrength
from agent.triage.enrichment import (
    _SERVICE_TEXT_EN,
    _rejection_reason,
    deterministic_fallback,
    validate_enrichment_payload,
)
from agent.triage.provider import BriefEnrichmentProviderResponse

from tests.fixtures.sanitized_real_log import DOCKER_EXPOSURE, SSH_SWEEP_PORT_22


#: Affirmative Turkish claims a firewall log can never support.
TURKISH_UNSUPPORTED_CLAIMS = (
    "Sunucu ele geçirildi.",
    "Servis başarıyla istismar edildi.",
    "Kimlik doğrulama başarılı oldu.",
    "Sunucuya zararlı yazılım yerleştirildi.",
    "Veriler dışarı sızdırıldı.",
    "Güvenlik ihlali yaşandı.",
    "Fidye yazılımı tespit edildi.",
    "Arka kapı kuruldu.",
    "Parolalar çalındı.",
    "Kimlik bilgileri çalındı.",
    "Mali kayıp bekleniyor.",
    "Finansal kayıp oluştu.",
    "İş etkisi büyüktür.",
    "Kabuk erişimi elde edildi.",
    "Kök erişimi sağlandı.",
    "Oturum açıldı.",
    "Giriş başarılı oldu.",
    "Sistem sömürüldü.",
)

#: Negated Turkish forms. The policy allows no negation exception in either
#: language, so these are refused as well.
TURKISH_NEGATED_CLAIMS = (
    "Sunucu ele geçirilmedi.",
    "İstismar kanıtlanmadı.",
    "Zararlı yazılım bulunmadı.",
    "Kimlik doğrulama başarılı olmadı.",
    "Veriler sızdırılmadı.",
)

MIXED_LANGUAGE_CLAIMS = (
    "The host was compromised ve sunucu ele geçirildi.",
    "Servis exploited edildi.",
    "Bu bir malware bulgusudur.",
    "Sunucu ele geçirildi and data was exfiltrated.",
)


def _incident(events, incident_id="INC-ML") -> IncidentBundle:
    return IncidentBundle(
        incident_id=incident_id,
        incident_type="inbound_sensitive_service_allowed",
        incident_family="firewall_exposure",
        title="Externally allowed sensitive service",
        severity="high",
        confidence=0.8,
        first_seen=min(e.timestamp for e in events),
        last_seen=max(e.timestamp for e in events),
        primary_entity=events[0].dst_ip,
        target_entities=[],
        signal_ids=["SIG-ML"],
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


def _items(events=None):
    events = events or [DOCKER_EXPOSURE]
    lookup = {e.event_id: e for e in events}
    return build_brief_selection([_incident(events)], lookup).all_items


SAFE_EN = "The service is externally reachable."
SAFE_TR = "Servise dışarıdan erişilebiliyor."


def _payload(item_id, *, explanation_en=SAFE_EN, explanation_tr=SAFE_TR):
    return {
        "items": [
            {
                "item_id": item_id,
                "explanation_en": explanation_en,
                "explanation_tr": explanation_tr,
                "recommended_actions_en": ["Confirm intent.", "Restrict access."],
                "recommended_actions_tr": [
                    "Amacı doğrulayın.",
                    "Erişimi kısıtlayın.",
                ],
            }
        ]
    }


class RecordingProvider:
    def __init__(self, payload):
        self.calls = 0
        self.payload = payload

    def invoke_brief_enrichment(self, request):
        self.calls += 1
        return BriefEnrichmentProviderResponse(raw_payload=self.payload)


# 1. Every affirmative Turkish claim is rejected.
@pytest.mark.parametrize("claim", TURKISH_UNSUPPORTED_CLAIMS)
def test_turkish_unsupported_claims_are_rejected(claim: str) -> None:
    items = _items()
    accepted, rejected = validate_enrichment_payload(
        _payload(items[0].item_id, explanation_tr=claim), items
    )
    assert rejected.get(items[0].item_id) == "unsupported_claim", claim
    assert accepted == ()


# 2. Negated Turkish forms are rejected too.
@pytest.mark.parametrize("claim", TURKISH_NEGATED_CLAIMS)
def test_negated_turkish_claims_are_also_rejected(claim: str) -> None:
    items = _items()
    _, rejected = validate_enrichment_payload(
        _payload(items[0].item_id, explanation_tr=claim), items
    )
    assert rejected.get(items[0].item_id) == "unsupported_claim", claim


def test_turkish_claims_are_caught_in_the_english_field_too() -> None:
    """Both pattern sets apply to every field, whatever its nominal language."""
    items = _items()
    _, rejected = validate_enrichment_payload(
        _payload(items[0].item_id, explanation_en="Sunucu ele geçirildi."), items
    )
    assert rejected.get(items[0].item_id) == "unsupported_claim"


def test_english_claims_are_still_caught_in_the_turkish_field() -> None:
    items = _items()
    _, rejected = validate_enrichment_payload(
        _payload(items[0].item_id, explanation_tr="The host was compromised."),
        items,
    )
    assert rejected.get(items[0].item_id) == "unsupported_claim"


def test_turkish_claims_in_recommended_actions_are_rejected() -> None:
    items = _items()
    payload = _payload(items[0].item_id)
    payload["items"][0]["recommended_actions_tr"] = [
        "Sunucu ele geçirildi, inceleyin.",
        "Erişimi kısıtlayın.",
    ]
    _, rejected = validate_enrichment_payload(payload, items)
    assert rejected.get(items[0].item_id) == "unsupported_claim"


# 4. Mixed-language claims are rejected.
@pytest.mark.parametrize("claim", MIXED_LANGUAGE_CLAIMS)
def test_mixed_language_unsupported_claim_is_rejected(claim: str) -> None:
    items = _items()
    _, rejected = validate_enrichment_payload(
        _payload(items[0].item_id, explanation_tr=claim), items
    )
    assert rejected.get(items[0].item_id) == "unsupported_claim", claim


# 3. A realistic safe Turkish explanation is accepted.
def test_safe_turkish_explanation_is_accepted() -> None:
    items = _items()
    payload = {
        "items": [
            {
                "item_id": items[0].item_id,
                "explanation_en": (
                    "The container management API grants administrative "
                    "control over the host that runs it, so reachability from "
                    "outside the perimeter is significant on its own."
                ),
                "explanation_tr": (
                    "Konteyner yönetim arayüzü, üzerinde çalıştığı sunucu "
                    "üzerinde yönetimsel denetim sağlar. Güvenlik duvarı "
                    "bağlantı denemesine izin verdi; kayıtlar yalnızca ağ "
                    "erişilebilirliğini gösterir."
                ),
                "recommended_actions_en": [
                    "Confirm whether this management API should be published.",
                    "Bind the daemon to a local socket and require mutual TLS.",
                ],
                "recommended_actions_tr": [
                    "Bu yönetim arayüzünün yayınlanması gerekip gerekmediğini "
                    "doğrulayın.",
                    "Servisi yalnızca iç ağlara açacak şekilde sınırlayın.",
                ],
            }
        ]
    }
    accepted, rejected = validate_enrichment_payload(payload, items)
    assert not rejected
    assert len(accepted) == 1
    assert accepted[0].deterministic_fallback is False
    assert "Konteyner yönetim" in accepted[0].explanation_tr


# 5. A rejected Turkish item does not reject safe siblings.
def test_rejected_turkish_item_does_not_reject_siblings() -> None:
    ssh_events = list(SSH_SWEEP_PORT_22[:2])
    docker_events = [DOCKER_EXPOSURE]
    lookup = {e.event_id: e for e in ssh_events + docker_events}
    selection = build_brief_selection(
        [
            _incident(ssh_events, incident_id="INC-A"),
            _incident(docker_events, incident_id="INC-B"),
        ],
        lookup,
    )
    items = selection.all_items
    assert len(items) == 2

    payload = {
        "items": [
            _payload(items[0].item_id, explanation_tr="Sunucu ele geçirildi.")[
                "items"
            ][0],
            _payload(items[1].item_id)["items"][0],
        ]
    }
    accepted, rejected = validate_enrichment_payload(payload, items)

    assert rejected == {items[0].item_id: "unsupported_claim"}
    assert [entry.item_id for entry in accepted] == [items[1].item_id]

    # End to end: only the rejected row falls back.
    provider = RecordingProvider(payload)
    result = enrich_brief_items(
        items, llm_enabled=True, provider_builder=lambda: provider
    )
    assert provider.calls == 1
    by_id = {entry.item_id: entry for entry in result.items}
    assert by_id[items[0].item_id].deterministic_fallback is True
    assert by_id[items[1].item_id].deterministic_fallback is False


def test_deterministic_fallback_text_satisfies_the_guardrail_it_enforces() -> None:
    """Our own generated text must never trip either pattern set."""
    for service in list(_SERVICE_TEXT_EN) + [None]:
        for strength in EvidenceStrength:
            for kind, family in (
                ("incident", "firewall_exposure"),
                ("scan_cluster", "network_scanning"),
            ):
                item = BriefActionItem(
                    item_id="probe",
                    kind=kind,
                    member_incident_ids=("A",),
                    title="t",
                    incident_type="t",
                    incident_family=family,
                    service=service,
                    evidence_strength=strength,
                )
                entry = deterministic_fallback(item)
                for field in (
                    entry.explanation_en,
                    entry.explanation_tr,
                    *entry.recommended_actions_en,
                    *entry.recommended_actions_tr,
                ):
                    assert _rejection_reason(field, item) is None, (
                        service,
                        strength,
                        field,
                    )


def test_english_patterns_are_not_weakened() -> None:
    """The original English prohibitions still hold."""
    items = _items()
    for text in (
        "The host was compromised.",
        "The attacker successfully authenticated.",
        "This was exploited to gain access.",
        "Malware was installed.",
        "Expect material financial loss.",
        "The host was not merely scanned but compromised.",
    ):
        _, rejected = validate_enrichment_payload(
            _payload(items[0].item_id, explanation_en=text), items
        )
        assert rejected.get(items[0].item_id) == "unsupported_claim", text


def test_prompt_prohibits_the_turkish_vocabulary_too() -> None:
    from agent.triage.enrichment_prompt import build_enrichment_system_prompt

    prompt = build_enrichment_system_prompt()
    for phrase in (
        "ele geçirildi",
        "zararlı yazılım",
        "istismar",
        "kimlik doğrulama başarılı",
        "mali kayıp",
    ):
        assert phrase in prompt, phrase
