"""Deterministic exposure disposition for firewall exposure/policy incidents.

The verdict, severity, confidence and evidence IDs of a firewall exposure are
pure functions of canonical, already-detected event facts. No provider ever
chooses them, so the same canonical incident always disposes identically -
across processes, across hash seeds, and regardless of whether a language
model was reachable.

Deterministic verdict policy
----------------------------
A valid externally allowed sensitive-service exposure is always
``suspicious_activity``. A firewall pass proves *policy exposure* only; it
never proves authentication, exploitation or compromise, so no deterministic
path here may emit ``confirmed_incident``.

``needs_review`` is reserved for a genuine deterministic ambiguity or
inconsistency in the canonical data itself (for example an exposure-family
incident that carries no usable canonical event). A provider failure, a
missing batch enrichment or an unreachable model must never move an incident
to ``needs_review`` and must never reduce its severity to ``none`` - those
conditions are recorded in bounded artifact/job metadata instead.

Deterministic severity policy
-----------------------------
=========================== ================================ ==========
service class               evidence strength                severity
=========================== ================================ ==========
critical management         syn_only / single_packet_non_syn high
critical management         multi_packet_unidirectional      high
critical management         bidirectional / application      critical
sensitive remote service    syn_only / single_packet_non_syn medium
sensitive remote service    multi_packet / bidirectional     high
DNAT sensitive exposure     any                              >= high
=========================== ================================ ==========
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from agent.detection.context_matching import events_are_bidirectionally_related
from agent.detection.detectors.exposure_helpers import (
    effective_destination_ip,
    effective_destination_port,
    has_destination_translation,
    has_private_destination_translation,
    has_public_to_private_destination_translation,
    is_critical_management_port,
    sensitive_service_for_port,
)
from agent.detection.detectors.scan_helpers import (
    event_tcp_flag_tokens,
    is_allowed,
    is_blocked,
)
from agent.detection.models import IncidentBundle
from agent.schema import CanonicalLogEvent


EXPOSURE_FAMILIES = frozenset({"firewall_exposure", "firewall_policy"})

# Bounds keep every derived collection small enough to persist and to render
# without truncating unpredictably.
MAX_REPRESENTATIVE_EVIDENCE_IDS = 5
MAX_DISPOSITION_ENTITIES = 10

_APPLICATION_FLAGS = frozenset({"PSH", "URG"})
_RESPONSE_FLAGS = frozenset({"ACK", "RST", "FIN"})


class EvidenceStrength(str, Enum):
    """How much the observed network evidence actually supports.

    Ordered weakest to strongest. The category is derived from packet counts
    and TCP flags, never from a non-zero duration: a firewall may report a
    multi-second duration for a single unanswered SYN, so duration alone can
    never establish that a peer replied.
    """

    SYN_ONLY = "syn_only"
    SINGLE_PACKET_NON_SYN = "single_packet_non_syn"
    MULTI_PACKET_UNIDIRECTIONAL = "multi_packet_unidirectional"
    BIDIRECTIONAL_TRANSPORT = "bidirectional_transport"
    APPLICATION_EVIDENCE = "application_evidence"


EVIDENCE_STRENGTH_RANK = {
    EvidenceStrength.SYN_ONLY: 0,
    EvidenceStrength.SINGLE_PACKET_NON_SYN: 1,
    EvidenceStrength.MULTI_PACKET_UNIDIRECTIONAL: 2,
    EvidenceStrength.BIDIRECTIONAL_TRANSPORT: 3,
    EvidenceStrength.APPLICATION_EVIDENCE: 4,
}

_WEAK_STRENGTHS = frozenset(
    {EvidenceStrength.SYN_ONLY, EvidenceStrength.SINGLE_PACKET_NON_SYN}
)
_TRANSPORT_PROVEN_STRENGTHS = frozenset(
    {EvidenceStrength.BIDIRECTIONAL_TRANSPORT, EvidenceStrength.APPLICATION_EVIDENCE}
)


class ExposureDisposition(BaseModel):
    """Typed, frozen deterministic disposition for one exposure incident."""

    model_config = ConfigDict(frozen=True)

    incident_id: str
    verdict: str
    severity: str
    detection_confidence: float = Field(ge=0.0, le=1.0)
    evidence_strength: EvidenceStrength
    allowed_event_count: int = Field(ge=0)
    blocked_event_count: int = Field(ge=0)
    unique_event_count: int = Field(ge=0)
    packet_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)
    max_duration_ms: int = Field(ge=0)
    transport_direction: str
    nat_observed: bool
    nat_type: Optional[str] = None
    service: Optional[str] = None
    service_sensitivity: str
    effective_destination_ip: Optional[str] = None
    effective_destination_port: Optional[int] = None
    representative_evidence_ids: tuple[str, ...] = ()
    review_reason: Optional[str] = None


def _packets(event: CanonicalLogEvent) -> int:
    value = event.packets
    return value if isinstance(value, int) and value > 0 else 0


def _unique_events(
    events: Sequence[CanonicalLogEvent],
) -> list[CanonicalLogEvent]:
    """Deduplicate by event_id and order deterministically.

    Sorting by event_id (not by timestamp alone) keeps the result identical
    under any input ordering and any PYTHONHASHSEED.
    """
    unique: dict[str, CanonicalLogEvent] = {}
    for event in events:
        unique.setdefault(event.event_id, event)
    return [unique[event_id] for event_id in sorted(unique)]


def _has_application_evidence(events: Sequence[CanonicalLogEvent]) -> bool:
    return any(bool(event_tcp_flag_tokens(event) & _APPLICATION_FLAGS) for event in events)


def _has_bidirectional_evidence(events: Sequence[CanonicalLogEvent]) -> bool:
    """True only when a peer demonstrably answered.

    Two independent deterministic signals qualify: a single flow that carries
    both SYN and a response-oriented flag (a completed or answered handshake),
    or two canonical events that context matching recognizes as the two
    directions of one flow.
    """
    for event in events:
        tokens = event_tcp_flag_tokens(event)
        if "SYN" in tokens and tokens & _RESPONSE_FLAGS:
            return True
        if not tokens & {"SYN"} and tokens & _RESPONSE_FLAGS and _packets(event) > 1:
            return True

    for index, event in enumerate(events):
        for other in events[index + 1 :]:
            if events_are_bidirectionally_related(event, other):
                return True
    return False


def classify_evidence_strength(
    events: Sequence[CanonicalLogEvent],
) -> EvidenceStrength:
    """Classify how strong the observed transport evidence is.

    A one-packet SYN is ``syn_only``. A high packet count is never
    ``syn_only`` even when the only recorded flag is SYN, because the
    retransmissions or payload packets are themselves observed facts. Duration
    is deliberately ignored.
    """
    unique = _unique_events(events)
    if not unique:
        return EvidenceStrength.SYN_ONLY

    if _has_application_evidence(unique):
        return EvidenceStrength.APPLICATION_EVIDENCE
    if _has_bidirectional_evidence(unique):
        return EvidenceStrength.BIDIRECTIONAL_TRANSPORT

    total_packets = sum(_packets(event) for event in unique)
    # A firewall that omits packet counts still reports one record per flow;
    # treat each such record as at least one observed packet.
    effective_packets = total_packets if total_packets else len(unique)
    if effective_packets > 1:
        return EvidenceStrength.MULTI_PACKET_UNIDIRECTIONAL

    tokens = event_tcp_flag_tokens(unique[0])
    if tokens == frozenset({"SYN"}):
        return EvidenceStrength.SYN_ONLY
    return EvidenceStrength.SINGLE_PACKET_NON_SYN


def _service_sensitivity(port: Optional[int]) -> str:
    if is_critical_management_port(port):
        return "critical_management"
    if sensitive_service_for_port(port) is not None:
        return "sensitive_remote_service"
    return "other"


def _transport_direction(
    events: Sequence[CanonicalLogEvent],
    strength: EvidenceStrength,
) -> str:
    if strength in _TRANSPORT_PROVEN_STRENGTHS:
        return "bidirectional_observed"
    if any(_packets(event) > 1 for event in events):
        return "outbound_only_multi_packet"
    return "outbound_only_single_packet"


def _severity_for(
    sensitivity: str,
    strength: EvidenceStrength,
    *,
    dnat_exposure: bool,
) -> str:
    if sensitivity == "critical_management":
        severity = "critical" if strength in _TRANSPORT_PROVEN_STRENGTHS else "high"
    elif sensitivity == "sensitive_remote_service":
        severity = "medium" if strength in _WEAK_STRENGTHS else "high"
    else:
        severity = "medium" if strength in _WEAK_STRENGTHS else "high"

    if dnat_exposure and severity in {"informational", "low", "medium"}:
        # A destination-translated exposure publishes an internal asset to the
        # internet; that is at least high regardless of evidence strength.
        severity = "high"
    return severity


def derive_exposure_disposition(
    incident: IncidentBundle,
    incident_events: Sequence[CanonicalLogEvent],
) -> ExposureDisposition:
    """Derive the deterministic disposition of one exposure incident.

    Evidence IDs are incident-owned: they come from the canonical detection
    evidence already attached to the incident, never from a model selection.
    """
    unique = _unique_events(incident_events)
    allowed_events = [event for event in unique if is_allowed(event)]
    blocked_count = sum(1 for event in unique if is_blocked(event))

    # Disposition facts describe the exposure itself, so they are measured on
    # the allowed events when any exist.
    measured = allowed_events or unique
    strength = classify_evidence_strength(measured)

    destination_port = None
    destination_ip = None
    nat_type = None
    if measured:
        primary = measured[0]
        destination_port = effective_destination_port(primary)
        destination_ip = effective_destination_ip(primary)
        nat_type = primary.nat_type

    sensitivity = _service_sensitivity(destination_port)
    service = sensitive_service_for_port(destination_port)
    # An inbound flow whose destination is translated to a private internal
    # address publishes that internal asset. Keying on the translation itself
    # rather than on the pre-translation address being globally routable keeps
    # the classification correct for captures where the perimeter address is
    # not in globally routable space.
    dnat_exposure = any(
        has_private_destination_translation(event)
        or has_public_to_private_destination_translation(event)
        for event in measured
    )
    nat_observed = any(has_destination_translation(event) for event in measured)

    evidence_ids = tuple(
        sorted({item.event_id for item in incident.evidence if item.event_id})
    )[:MAX_REPRESENTATIVE_EVIDENCE_IDS]
    if not evidence_ids:
        # Fall back to the incident's own canonical event IDs so a valid
        # exposure is never left without citable evidence.
        evidence_ids = tuple(sorted(event.event_id for event in measured))[
            :MAX_REPRESENTATIVE_EVIDENCE_IDS
        ]

    if not unique:
        # Genuine canonical-data ambiguity: an exposure incident with no usable
        # canonical event cannot be disposed deterministically.
        return ExposureDisposition(
            incident_id=incident.incident_id,
            verdict="needs_review",
            severity=incident.severity,
            detection_confidence=incident.confidence,
            evidence_strength=EvidenceStrength.SYN_ONLY,
            allowed_event_count=0,
            blocked_event_count=0,
            unique_event_count=0,
            packet_count=0,
            byte_count=0,
            max_duration_ms=0,
            transport_direction="unknown",
            nat_observed=False,
            service=None,
            service_sensitivity="other",
            representative_evidence_ids=evidence_ids,
            review_reason="canonical_events_unavailable",
        )

    if not allowed_events:
        # Fully blocked exposure-family incident: the policy held. Keep the
        # deterministic detection severity rather than escalating.
        return ExposureDisposition(
            incident_id=incident.incident_id,
            verdict="suspicious_activity",
            severity=incident.severity,
            detection_confidence=incident.confidence,
            evidence_strength=strength,
            allowed_event_count=0,
            blocked_event_count=blocked_count,
            unique_event_count=len(unique),
            packet_count=sum(_packets(event) for event in unique),
            byte_count=sum(event.bytes or 0 for event in unique),
            max_duration_ms=max((event.duration_ms or 0) for event in unique),
            transport_direction=_transport_direction(unique, strength),
            nat_observed=nat_observed,
            nat_type=nat_type,
            service=service,
            service_sensitivity=sensitivity,
            effective_destination_ip=destination_ip,
            effective_destination_port=destination_port,
            representative_evidence_ids=evidence_ids,
        )

    severity = _severity_for(sensitivity, strength, dnat_exposure=dnat_exposure)
    return ExposureDisposition(
        incident_id=incident.incident_id,
        verdict="suspicious_activity",
        severity=severity,
        detection_confidence=incident.confidence,
        evidence_strength=strength,
        allowed_event_count=len(allowed_events),
        blocked_event_count=blocked_count,
        unique_event_count=len(unique),
        packet_count=sum(_packets(event) for event in measured),
        byte_count=sum(event.bytes or 0 for event in measured),
        max_duration_ms=max((event.duration_ms or 0) for event in measured),
        transport_direction=_transport_direction(measured, strength),
        nat_observed=nat_observed,
        nat_type=nat_type,
        service=service,
        service_sensitivity=sensitivity,
        effective_destination_ip=destination_ip,
        effective_destination_port=destination_port,
        representative_evidence_ids=evidence_ids,
    )


def is_exposure_incident(incident: IncidentBundle) -> bool:
    return incident.incident_family in EXPOSURE_FAMILIES
