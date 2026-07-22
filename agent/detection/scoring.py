from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Literal, Mapping, cast

from agent.detection.config import DetectionSettings
from agent.detection.detectors.exposure_helpers import (
    CRITICAL_MANAGEMENT_PORTS,
    SENSITIVE_SERVICE_PORTS,
    effective_destination_ip,
    effective_destination_port,
)
from agent.detection.detectors.scan_helpers import is_allowed, is_blocked
from agent.detection.models import DetectionSignal
from agent.schema import CanonicalLogEvent


Severity = Literal["informational", "low", "medium", "high", "critical"]
AssetValue = Literal["standard", "sensitive", "critical"]
Targeting = Literal["targeted", "broad"]

_SEVERITY_TO_VALUE = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_VALUE_TO_SEVERITY: dict[int, Severity] = {
    0: "informational",
    1: "low",
    2: "medium",
    3: "high",
    4: "critical",
}
_ASSET_RANK = {"standard": 0, "sensitive": 1, "critical": 2}
_RECON_FAMILIES = frozenset({"network_scanning", "service_probing"})
_EVENT_AWARE_FAMILIES = frozenset(
    {
        *_RECON_FAMILIES,
        "firewall_exposure",
        "firewall_policy",
        "network_intrusion_candidate",
    }
)


def _metric_int(value: object) -> int:
    return int(str(value))


@dataclass(frozen=True)
class IncidentSeverityFacts:
    """Typed, bounded facts derived where canonical incident events exist."""

    family: str
    total_event_count: int
    allowed_event_count: int
    blocked_event_count: int
    distinct_destination_count: int
    asset_value: AssetValue
    targeting: Targeting
    max_sensitive_ports_per_destination: int

    def as_metrics(self) -> dict[str, int | str]:
        return {
            "severity_family": self.family,
            "severity_total_event_count": self.total_event_count,
            "allowed_event_count": self.allowed_event_count,
            "blocked_event_count": self.blocked_event_count,
            "distinct_destination_count": self.distinct_destination_count,
            "asset_value": self.asset_value,
            "targeting": self.targeting,
            "max_sensitive_ports_per_destination": (
                self.max_sensitive_ports_per_destination
            ),
        }

    @classmethod
    def from_metrics(
        cls, metrics: Mapping[str, object]
    ) -> IncidentSeverityFacts | None:
        required = (
            "severity_family",
            "severity_total_event_count",
            "allowed_event_count",
            "blocked_event_count",
            "distinct_destination_count",
            "asset_value",
            "targeting",
            "max_sensitive_ports_per_destination",
        )
        if any(key not in metrics for key in required):
            return None
        asset_value = str(metrics["asset_value"])
        targeting = str(metrics["targeting"])
        if asset_value not in _ASSET_RANK or targeting not in {"targeted", "broad"}:
            return None
        return cls(
            family=str(metrics["severity_family"]),
            total_event_count=_metric_int(metrics["severity_total_event_count"]),
            allowed_event_count=_metric_int(metrics["allowed_event_count"]),
            blocked_event_count=_metric_int(metrics["blocked_event_count"]),
            distinct_destination_count=_metric_int(
                metrics["distinct_destination_count"]
            ),
            asset_value=cast(AssetValue, asset_value),
            targeting=cast(Targeting, targeting),
            max_sensitive_ports_per_destination=_metric_int(
                metrics["max_sensitive_ports_per_destination"]
            ),
        )


def derive_incident_severity_facts(
    events: list[CanonicalLogEvent], *, family: str
) -> IncidentSeverityFacts:
    unique_events = {event.event_id: event for event in events}.values()
    ordered_events = list(unique_events)
    allowed_events = [event for event in ordered_events if is_allowed(event)]
    blocked_events = [event for event in ordered_events if is_blocked(event)]
    destinations = {
        destination
        for event in ordered_events
        if (destination := effective_destination_ip(event))
    }

    asset_value: AssetValue = "standard"
    allowed_ports = {
        port
        for event in allowed_events
        if (port := effective_destination_port(event)) is not None
    }
    if allowed_ports & CRITICAL_MANAGEMENT_PORTS:
        asset_value = "critical"
    elif allowed_ports & SENSITIVE_SERVICE_PORTS:
        asset_value = "sensitive"

    sensitive_ports_by_destination: dict[str, set[int]] = {}
    for event in allowed_events:
        destination = effective_destination_ip(event)
        port = effective_destination_port(event)
        if destination and port in SENSITIVE_SERVICE_PORTS:
            sensitive_ports_by_destination.setdefault(destination, set()).add(port)

    max_sensitive_ports = max(
        (len(ports) for ports in sensitive_ports_by_destination.values()), default=0
    )
    distinct_destination_count = len(destinations)
    return IncidentSeverityFacts(
        family=family,
        total_event_count=len(ordered_events),
        allowed_event_count=len(allowed_events),
        blocked_event_count=len(blocked_events),
        distinct_destination_count=distinct_destination_count,
        asset_value=asset_value,
        targeting="targeted" if distinct_destination_count <= 2 else "broad",
        max_sensitive_ports_per_destination=max_sensitive_ports,
    )


def is_internal_ip(ip_str: str, internal_networks: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in internal_networks:
            if ip in ipaddress.ip_network(net):
                return True
        return False
    except ValueError:
        return False


def calculate_signal_confidence(
    event_count: int,
    threshold_count: int,
    base_confidence: float = 0.5,
    max_confidence: float = 0.95,
) -> float:
    """Increase confidence deterministically as events exceed the threshold."""
    if threshold_count <= 0:
        return base_confidence
    ratio = event_count / threshold_count
    if ratio < 1.0:
        return base_confidence * ratio

    extra = ratio - 1.0
    boost = (1.0 - (1.0 / (1.0 + extra * 0.5))) * (
        max_confidence - base_confidence
    )
    return min(base_confidence + boost, max_confidence)


def _legacy_signal_severity(signals: list[DetectionSignal]) -> int:
    return max(
        (_SEVERITY_TO_VALUE.get(signal.severity, 0) for signal in signals),
        default=0,
    )


def calculate_incident_severity(
    signals: list[DetectionSignal],
    primary_entity: str,
    settings: DetectionSettings,
    *,
    facts: IncidentSeverityFacts | None = None,
) -> Severity:
    """Calculate family-aware severity from explicit canonical-event facts.

    ``primary_entity`` and ``settings`` remain for API compatibility. Fresh
    and stateful production paths pass ``facts``; callers without canonical
    events retain the legacy signal-only behavior.
    """
    del primary_entity, settings
    if not signals:
        return "informational"

    severity_value = _legacy_signal_severity(signals)
    if facts is None or facts.family not in _EVENT_AWARE_FAMILIES:
        total_events = sum(len(signal.event_ids) for signal in signals)
        distinct_targets = len(
            {target for signal in signals for target in signal.target_entities}
        )
        if total_events > 500 or distinct_targets > 50:
            severity_value = min(4, severity_value + 1)
        return _VALUE_TO_SEVERITY[severity_value]

    if facts.allowed_event_count == 0 and facts.family in _RECON_FAMILIES:
        # Fully blocked recon is visibility, not impact. Large target breadth
        # may justify investigation, but it never becomes high solely on rule
        # severity or raw volume.
        severity_value = 2 if facts.distinct_destination_count >= 25 else 1
        return _VALUE_TO_SEVERITY[severity_value]

    if facts.allowed_event_count > 0:
        severity_value = {
            "standard": 2,
            "sensitive": 3,
            "critical": 4,
        }[facts.asset_value]
        if (
            facts.targeting == "targeted"
            and facts.max_sensitive_ports_per_destination >= 2
        ):
            severity_value = min(4, severity_value + 1)
        if facts.total_event_count > 500 or facts.distinct_destination_count > 50:
            severity_value = min(4, severity_value + 1)
        return _VALUE_TO_SEVERITY[severity_value]

    # Exposure/policy/sequence incidents without an allowed event cannot claim
    # exposure. Keep them bounded at low pending investigation.
    return "low"


def calculate_incident_confidence(signals: list[DetectionSignal]) -> float:
    if not signals:
        return 0.0
    confs = sorted([signal.confidence for signal in signals], reverse=True)
    top_confs = confs[:3]
    return sum(top_confs) / len(top_confs)
