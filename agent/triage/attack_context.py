"""Deterministic ATT&CK mapping for brief rows.

Rendered from Python, never chosen by a model, and never forced. Technique and
tactic are separate values throughout; a tactic ID must never end up inside a
techniques collection.

Mapping is conservative on purpose:

* Actual scan or service-enumeration behaviour maps to ``T1046`` under
  ``TA0007``.
* A genuine external remote-access service - SSH, RDP, VPN, Telnet - reached
  from outside may be shown as ``T1133`` *context*, because that is what the
  technique describes.
* A single permitted SYN to Redis, MongoDB, Elasticsearch, IPMI or similar
  proves an open port and nothing about behaviour, so it maps to nothing.

When no behavioural technique is supported the caller renders
``ATT&CK context: insufficient behavioral evidence`` rather than attaching a
technique to every open service.
"""

from __future__ import annotations

from typing import NamedTuple, Optional

from agent.triage.disposition import EvidenceStrength


DISCOVERY_TECHNIQUE = "T1046"
DISCOVERY_TACTIC = "TA0007"
EXTERNAL_REMOTE_SERVICES_TECHNIQUE = "T1133"
INITIAL_ACCESS_TACTIC = "TA0001"

INSUFFICIENT_EVIDENCE_TEXT = "insufficient behavioral evidence"

#: Services whose external exposure is what T1133 actually describes.
REMOTE_ACCESS_SERVICES = frozenset({"ssh", "rdp", "telnet", "vpn"})

#: Families whose detection is itself enumeration behaviour.
ENUMERATION_FAMILIES = frozenset(
    {"network_scanning", "service_probing", "lateral_movement_candidate"}
)

_WEAK_STRENGTHS = frozenset(
    {EvidenceStrength.SYN_ONLY, EvidenceStrength.SINGLE_PACKET_NON_SYN}
)


class AttackContext(NamedTuple):
    technique: Optional[str]
    tactic: Optional[str]
    #: How the technique applies: "behavioral" when the behaviour was actually
    #: observed, "context" when the mapping only describes the exposed service.
    kind: str = "unsupported"

    @property
    def supported(self) -> bool:
        return self.technique is not None


UNSUPPORTED = AttackContext(None, None, "unsupported")


def derive_attack_context(
    *,
    incident_family: str,
    service: Optional[str],
    evidence_strength: Optional[EvidenceStrength],
    distinct_port_count: int = 0,
    distinct_destination_count: int = 0,
) -> AttackContext:
    """Map deterministic facts to an ATT&CK context, or to nothing.

    Enumeration behaviour is established by the detection family or by the
    observed breadth (several ports or several destinations from one source).
    """
    enumerating = incident_family in ENUMERATION_FAMILIES or (
        distinct_port_count >= 3 or distinct_destination_count >= 3
    )
    if enumerating:
        return AttackContext(DISCOVERY_TECHNIQUE, DISCOVERY_TACTIC, "behavioral")

    if service in REMOTE_ACCESS_SERVICES:
        # External use of a real remote-access service is what T1133 covers.
        # It is shown as context, not as a proven executed technique.
        return AttackContext(
            EXTERNAL_REMOTE_SERVICES_TECHNIQUE, INITIAL_ACCESS_TACTIC, "context"
        )

    # A permitted database/management SYN proves an open port, not behaviour.
    if evidence_strength is None or evidence_strength in _WEAK_STRENGTHS:
        return UNSUPPORTED
    return UNSUPPORTED


def render_attack_context(context: AttackContext, lang: str = "en") -> str:
    """The single rendering used by every brief row.

    Technique and tactic IDs are printed verbatim in every language; only the
    surrounding words are localized.
    """
    from agent.triage.localization import ATTACK_LABELS

    labels = ATTACK_LABELS.get(lang, ATTACK_LABELS["en"])
    if context.technique is None:
        return f"{labels['prefix']}: {labels['insufficient']}"

    name = labels.get(context.technique, "")
    body = f"{context.technique}"
    if name:
        body += f" {name}"
    if context.tactic:
        body += f" ({context.tactic})"
    if context.kind == "context":
        body += f" - {labels['context_only']}"
    return f"{labels['prefix']}: {body}"
