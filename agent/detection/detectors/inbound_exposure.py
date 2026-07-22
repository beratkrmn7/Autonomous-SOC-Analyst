from collections import defaultdict, deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from agent.detection.contracts import DetectionRuleMetadata
from agent.detection.correlation import sliding_window_scan
from agent.detection.detectors.base import BaseDetectionRule, DetectionContext
from agent.detection.detectors.exposure_helpers import (
    administrative_service_for_port,
    bounded_zone,
    effective_destination_ip,
    effective_destination_port,
    has_destination_translation,
    has_external_inbound_evidence,
    has_private_destination_translation,
    is_critical_management_port,
    is_explicit_dmz_zone,
    is_explicit_lan_zone,
    is_explicit_wan_zone,
    is_private_effective_destination,
    is_private_source,
    is_public_source,
    is_usable_ip,
    sensitive_service_for_port,
)
from agent.detection.detectors.scan_helpers import (
    bounded_sorted_values,
    classify_service,
    is_allowed,
    is_blocked,
    is_spi_anomaly_event,
    normalized_protocol,
    parse_ip_address,
)
from agent.detection.evidence import (
    create_evidence_from_event,
    select_representative_evidence,
)
from agent.detection.models import DetectionEvidence, DetectionSignal, generate_signal_id
from agent.detection.scoring import calculate_signal_confidence
from agent.schema import CanonicalLogEvent
from agent.triage.network_context import derive_flow_direction


MetricValue = int | float | str | bool


@dataclass(frozen=True)
class _ExposureEvent:
    event: CanonicalLogEvent
    source_ip: str
    destination_ip: str
    destination_port: int
    service: str


def _exposure_event(
    event: CanonicalLogEvent,
    service_classifier: Callable[[int | None], str | None],
) -> _ExposureEvent | None:
    source_address = parse_ip_address(event.src_ip)
    destination_value = effective_destination_ip(event)
    destination_address = parse_ip_address(destination_value)
    destination_port = effective_destination_port(event)
    service = service_classifier(destination_port)
    if (
        source_address is None
        or destination_address is None
        or not is_usable_ip(event.src_ip)
        or not is_usable_ip(destination_value)
        or destination_port is None
        or service is None
        or normalized_protocol(event) != "TCP"
    ):
        return None
    return _ExposureEvent(
        event=event,
        source_ip=str(source_address),
        destination_ip=str(destination_address),
        destination_port=destination_port,
        service=service,
    )


def _service_or_exact_port(port: int | None) -> str | None:
    # Sequence matching uses the complete deterministic service taxonomy,
    # not only the narrower inbound-exposure tiers.
    service = classify_service(port)
    if service is not None:
        return service
    if port is not None and 1 <= port <= 65_535:
        return f"tcp_{port}"
    return None


def _ordered(
    events: Sequence[_ExposureEvent],
    context: DetectionContext,
) -> list[_ExposureEvent]:
    return sorted(
        events,
        key=lambda item: (
            item.event.timestamp or context.analysis_started_at,
            item.event.event_id,
        ),
    )


def _destination_ports(events: Sequence[_ExposureEvent]) -> str:
    return ",".join(str(port) for port in sorted({item.destination_port for item in events}))


def _build_signal(
    rule: BaseDetectionRule,
    exposure_events: Sequence[_ExposureEvent],
    context: DetectionContext,
    *,
    primary_entity: str,
    correlation_key: str,
    target_entities: Sequence[str],
    metrics: dict[str, MetricValue],
    minimum_events: int,
    reason: str,
    tags: list[str],
    evidence: list[DetectionEvidence] | None = None,
) -> DetectionSignal:
    events = [item.event for item in exposure_events]
    event_ids = [event.event_id for event in events]
    first_seen = events[0].timestamp or context.analysis_started_at
    last_seen = events[-1].timestamp or context.analysis_started_at
    return DetectionSignal(
        signal_id=generate_signal_id(
            rule.rule_id,
            rule.version,
            primary_entity,
            correlation_key,
            first_seen,
            event_ids,
        ),
        rule_id=rule.rule_id,
        rule_version=rule.version,
        rule_name=rule.name,
        signal_type=rule.metadata.signal_type,
        signal_family=rule.family,
        severity=rule.metadata.default_severity,
        confidence=calculate_signal_confidence(
            len(events),
            minimum_events,
            base_confidence=(
                0.8 if rule.metadata.default_severity == "high" else 0.65
            ),
            max_confidence=(
                0.95 if rule.metadata.default_severity == "high" else 0.9
            ),
        ),
        first_seen=first_seen,
        last_seen=last_seen,
        event_ids=event_ids,
        primary_entity=primary_entity,
        target_entities=bounded_sorted_values(target_entities),
        metrics=metrics,
        evidence=(
            evidence
            if evidence is not None
            else select_representative_evidence(
                events,
                max_evidence=3,
                reason=reason,
                source_rule=rule.rule_id,
                correlation_context=metrics,
            )
        ),
        mitre_techniques=list(rule.metadata.mitre_techniques),
        tags=tags,
    )


def _sort_signals(signals: list[DetectionSignal]) -> list[DetectionSignal]:
    return sorted(
        signals,
        key=lambda signal: (
            signal.first_seen,
            signal.rule_id,
            signal.signal_id,
        ),
    )


class InboundSensitiveServiceAllowedRule(BaseDetectionRule):
    metadata = DetectionRuleMetadata(
        rule_id="inbound_sensitive_service_allowed",
        version="1.0.0",
        name="Inbound Sensitive Service Allowed",
        family="firewall_exposure",
        priority=48,
        supported_event_types=(),
        required_fields=("src_ip", "protocol", "action"),
        signal_type="inbound_sensitive_service_allowed",
        default_severity="medium",
        mitre_techniques=(),
        window_setting="INBOUND_EXPOSURE_WINDOW_SECONDS",
        minimum_events_setting="INBOUND_SENSITIVE_MIN_ALLOWED_EVENTS",
    )

    def evaluate(
        self,
        events: Sequence[CanonicalLogEvent],
        context: DetectionContext,
    ) -> list[DetectionSignal]:
        settings = context.settings
        groups: dict[tuple[str, str, str], list[_ExposureEvent]] = defaultdict(list)
        for event in events:
            item = _exposure_event(event, sensitive_service_for_port)
            if (
                item is not None
                and is_allowed(event)
                and has_external_inbound_evidence(event)
            ):
                groups[(item.source_ip, item.destination_ip, item.service)].append(item)

        signals: list[DetectionSignal] = []
        for (source_ip, destination_ip, service), grouped in groups.items():
            ordered = _ordered(grouped, context)

            def matches(
                window: deque[CanonicalLogEvent],
            ) -> tuple[bool, dict[str, Any]]:
                window_events = list(window)
                if len(window_events) < settings.INBOUND_SENSITIVE_MIN_ALLOWED_EVENTS:
                    return False, {}
                destinations = {
                    effective_destination_ip(event)
                    for event in window_events
                    if effective_destination_ip(event) is not None
                }
                if (
                    len(destinations)
                    < settings.INBOUND_SENSITIVE_MIN_DISTINCT_DESTINATIONS
                ):
                    return False, {}
                window_ids = {event.event_id for event in window_events}
                window_items = [
                    item for item in ordered if item.event.event_id in window_ids
                ]
                return True, {
                    "event_count": len(window_events),
                    "service": service,
                    "destination_ports": _destination_ports(window_items),
                    "effective_destination": destination_ip,
                    "explicit_wan_events": sum(
                        1
                        for event in window_events
                        if is_explicit_wan_zone(event.inbound_zone)
                    ),
                    "destination_translation_events": sum(
                        1 for event in window_events if has_destination_translation(event)
                    ),
                    "allowed_events": sum(
                        1 for event in window_events if is_allowed(event)
                    ),
                }

            raw_events = [item.event for item in ordered]
            for match_events, metrics in sliding_window_scan(
                raw_events,
                settings.INBOUND_EXPOSURE_WINDOW_SECONDS,
                matches,
            ):
                ids = {event.event_id for event in match_events}
                match_items = [item for item in ordered if item.event.event_id in ids]
                signals.append(
                    _build_signal(
                        self,
                        match_items,
                        context,
                        primary_entity=source_ip,
                        correlation_key=f"{destination_ip}_{service}",
                        target_entities=[destination_ip],
                        metrics=metrics,
                        minimum_events=settings.INBOUND_SENSITIVE_MIN_ALLOWED_EVENTS,
                        reason="Repeated allowed inbound access to a sensitive service",
                        tags=["network", "firewall", "exposure", service],
                    )
                )
        return _sort_signals(signals)


class CriticalManagementServiceExposedRule(BaseDetectionRule):
    metadata = DetectionRuleMetadata(
        rule_id="critical_management_service_exposed",
        version="1.0.0",
        name="Critical Management Service Exposed",
        family="firewall_exposure",
        priority=41,
        supported_event_types=(),
        required_fields=("src_ip", "protocol", "action"),
        signal_type="critical_management_service_exposed",
        default_severity="high",
        mitre_techniques=(),
        window_setting="INBOUND_EXPOSURE_WINDOW_SECONDS",
        minimum_events_setting="CRITICAL_MANAGEMENT_EXPOSURE_MIN_EVENTS",
    )

    def evaluate(
        self,
        events: Sequence[CanonicalLogEvent],
        context: DetectionContext,
    ) -> list[DetectionSignal]:
        settings = context.settings
        groups: dict[tuple[str, str, int], list[_ExposureEvent]] = defaultdict(list)
        for event in events:
            item = _exposure_event(event, sensitive_service_for_port)
            strong_inbound = bool(
                is_explicit_wan_zone(event.inbound_zone)
                or has_private_destination_translation(event)
            )
            if (
                item is not None
                and is_allowed(event)
                and is_critical_management_port(item.destination_port)
                and strong_inbound
                and not (
                    is_private_source(event)
                    and is_private_effective_destination(event)
                )
            ):
                groups[(item.source_ip, item.destination_ip, item.destination_port)].append(item)

        signals: list[DetectionSignal] = []
        for (source_ip, destination_ip, destination_port), grouped in groups.items():
            ordered = _ordered(grouped, context)

            def matches(
                window: deque[CanonicalLogEvent],
            ) -> tuple[bool, dict[str, Any]]:
                window_events = list(window)
                if len(window_events) < settings.CRITICAL_MANAGEMENT_EXPOSURE_MIN_EVENTS:
                    return False, {}
                first_event = window_events[0]
                return True, {
                    "service": grouped[0].service,
                    "destination_port": destination_port,
                    "effective_destination": destination_ip,
                    "inbound_zone": bounded_zone(first_event.inbound_zone),
                    "destination_translation": any(
                        has_destination_translation(event) for event in window_events
                    ),
                    "source_ip": source_ip,
                }

            raw_events = [item.event for item in ordered]
            for match_events, metrics in sliding_window_scan(
                raw_events,
                settings.INBOUND_EXPOSURE_WINDOW_SECONDS,
                matches,
            ):
                ids = {event.event_id for event in match_events}
                match_items = [item for item in ordered if item.event.event_id in ids]
                signals.append(
                    _build_signal(
                        self,
                        match_items,
                        context,
                        primary_entity=source_ip,
                        correlation_key=f"{destination_ip}_{destination_port}",
                        target_entities=[destination_ip],
                        metrics=metrics,
                        minimum_events=settings.CRITICAL_MANAGEMENT_EXPOSURE_MIN_EVENTS,
                        reason="Allowed inbound access to a critical management service",
                        tags=["network", "firewall", "critical_exposure", grouped[0].service],
                    )
                )
        return _sort_signals(signals)


class DnatSensitiveServiceExposureRule(BaseDetectionRule):
    metadata = DetectionRuleMetadata(
        rule_id="dnat_sensitive_service_exposure",
        version="1.0.0",
        name="DNAT Sensitive Service Exposure",
        family="firewall_exposure",
        priority=44,
        supported_event_types=(),
        required_fields=("src_ip", "protocol", "action"),
        signal_type="dnat_sensitive_service_exposure",
        default_severity="high",
        mitre_techniques=(),
        window_setting="INBOUND_EXPOSURE_WINDOW_SECONDS",
        minimum_events_setting=None,
    )

    def evaluate(
        self,
        events: Sequence[CanonicalLogEvent],
        context: DetectionContext,
    ) -> list[DetectionSignal]:
        groups: dict[tuple[str, int], list[_ExposureEvent]] = defaultdict(list)
        for event in events:
            item = _exposure_event(event, sensitive_service_for_port)
            if (
                item is not None
                and is_allowed(event)
                and has_private_destination_translation(event)
                and (
                    is_public_source(event)
                    or is_explicit_wan_zone(event.inbound_zone)
                )
                and not (
                    is_private_source(event)
                    and is_private_effective_destination(event)
                )
            ):
                groups[(item.destination_ip, item.destination_port)].append(item)

        signals: list[DetectionSignal] = []
        for (destination_ip, destination_port), grouped in groups.items():
            ordered = _ordered(grouped, context)

            def matches(
                window: deque[CanonicalLogEvent],
            ) -> tuple[bool, dict[str, Any]]:
                window_events = list(window)
                first_event = window_events[0]
                original_destination = parse_ip_address(first_event.dst_ip)
                return True, {
                    "original_destination": (
                        str(original_destination)
                        if original_destination is not None
                        else "unknown"
                    ),
                    "original_destination_port": (
                        first_event.dst_port if first_event.dst_port is not None else 0
                    ),
                    "translated_destination": destination_ip,
                    "translated_destination_port": destination_port,
                    "service": grouped[0].service,
                    "event_count": len(window_events),
                    "distinct_sources": len(
                        {event.src_ip for event in window_events if event.src_ip}
                    ),
                }

            raw_events = [item.event for item in ordered]
            for match_events, metrics in sliding_window_scan(
                raw_events,
                context.settings.INBOUND_EXPOSURE_WINDOW_SECONDS,
                matches,
            ):
                ids = {event.event_id for event in match_events}
                match_items = [item for item in ordered if item.event.event_id in ids]
                signals.append(
                    _build_signal(
                        self,
                        match_items,
                        context,
                        primary_entity=destination_ip,
                        correlation_key=f"dnat_{destination_port}",
                        target_entities=[item.source_ip for item in match_items],
                        metrics=metrics,
                        minimum_events=1,
                        reason="Allowed destination translation to a sensitive service",
                        tags=["network", "firewall", "dnat", grouped[0].service],
                    )
                )
        return _sort_signals(signals)


class WanToLanSensitiveServiceAllowedRule(BaseDetectionRule):
    metadata = DetectionRuleMetadata(
        rule_id="wan_to_lan_sensitive_service_allowed",
        version="1.0.0",
        name="WAN-to-LAN Sensitive Service Allowed",
        family="firewall_policy",
        priority=45,
        supported_event_types=(),
        required_fields=("src_ip", "protocol", "action", "inbound_zone"),
        signal_type="wan_to_lan_sensitive_service_allowed",
        default_severity="high",
        mitre_techniques=(),
        window_setting="INBOUND_EXPOSURE_WINDOW_SECONDS",
        minimum_events_setting="WAN_TO_LAN_MIN_ALLOWED_EVENTS",
    )

    def evaluate(
        self,
        events: Sequence[CanonicalLogEvent],
        context: DetectionContext,
    ) -> list[DetectionSignal]:
        settings = context.settings
        groups: dict[tuple[str, str], list[_ExposureEvent]] = defaultdict(list)
        for event in events:
            item = _exposure_event(event, sensitive_service_for_port)
            if (
                item is not None
                and is_allowed(event)
                and is_explicit_wan_zone(event.inbound_zone)
                and (
                    is_explicit_lan_zone(event.outbound_zone)
                    or (
                        not event.outbound_zone
                        and derive_flow_direction(event) == "inbound"
                    )
                )
                and not (
                    is_private_source(event)
                    and is_private_effective_destination(event)
                )
            ):
                groups[(item.destination_ip, item.service)].append(item)

        return self._evaluate_groups(groups, context, settings.WAN_TO_LAN_MIN_ALLOWED_EVENTS)

    def _evaluate_groups(
        self,
        groups: dict[tuple[str, str], list[_ExposureEvent]],
        context: DetectionContext,
        minimum_events: int,
    ) -> list[DetectionSignal]:
        signals: list[DetectionSignal] = []
        for (destination_ip, service), grouped in groups.items():
            ordered = _ordered(grouped, context)

            def matches(
                window: deque[CanonicalLogEvent],
            ) -> tuple[bool, dict[str, Any]]:
                window_events = list(window)
                if len(window_events) < minimum_events:
                    return False, {}
                ids = {event.event_id for event in window_events}
                items = [item for item in ordered if item.event.event_id in ids]
                return True, {
                    "event_count": len(window_events),
                    "inbound_zone": bounded_zone(window_events[0].inbound_zone),
                    "outbound_zone": bounded_zone(window_events[0].outbound_zone),
                    "service": service,
                    "effective_destination": destination_ip,
                    "destination_ports": _destination_ports(items),
                    "distinct_sources": len({item.source_ip for item in items}),
                }

            raw_events = [item.event for item in ordered]
            for match_events, metrics in sliding_window_scan(
                raw_events,
                context.settings.INBOUND_EXPOSURE_WINDOW_SECONDS,
                matches,
            ):
                ids = {event.event_id for event in match_events}
                match_items = [item for item in ordered if item.event.event_id in ids]
                signals.append(
                    _build_signal(
                        self,
                        match_items,
                        context,
                        primary_entity=destination_ip,
                        correlation_key=f"wan_lan_{service}",
                        target_entities=[item.source_ip for item in match_items],
                        metrics=metrics,
                        minimum_events=minimum_events,
                        reason="Allowed WAN-to-LAN access to a sensitive service",
                        tags=["network", "firewall", "wan_to_lan", service],
                    )
                )
        return _sort_signals(signals)


class WanToDmzAdministrativeServiceAllowedRule(BaseDetectionRule):
    metadata = DetectionRuleMetadata(
        rule_id="wan_to_dmz_administrative_service_allowed",
        version="1.0.0",
        name="WAN-to-DMZ Administrative Service Allowed",
        family="firewall_policy",
        priority=47,
        supported_event_types=(),
        required_fields=("src_ip", "protocol", "action", "inbound_zone", "outbound_zone"),
        signal_type="wan_to_dmz_administrative_service_allowed",
        default_severity="medium",
        mitre_techniques=(),
        window_setting="INBOUND_EXPOSURE_WINDOW_SECONDS",
        minimum_events_setting="WAN_TO_DMZ_ADMIN_MIN_ALLOWED_EVENTS",
    )

    def evaluate(
        self,
        events: Sequence[CanonicalLogEvent],
        context: DetectionContext,
    ) -> list[DetectionSignal]:
        settings = context.settings
        groups: dict[tuple[str, str], list[_ExposureEvent]] = defaultdict(list)
        for event in events:
            item = _exposure_event(event, administrative_service_for_port)
            if (
                item is not None
                and is_allowed(event)
                and is_explicit_wan_zone(event.inbound_zone)
                and is_explicit_dmz_zone(event.outbound_zone)
                and not (
                    is_private_source(event)
                    and is_private_effective_destination(event)
                )
            ):
                groups[(item.destination_ip, item.service)].append(item)

        signals: list[DetectionSignal] = []
        for (destination_ip, service), grouped in groups.items():
            ordered = _ordered(grouped, context)

            def matches(
                window: deque[CanonicalLogEvent],
            ) -> tuple[bool, dict[str, Any]]:
                window_events = list(window)
                if len(window_events) < settings.WAN_TO_DMZ_ADMIN_MIN_ALLOWED_EVENTS:
                    return False, {}
                ids = {event.event_id for event in window_events}
                items = [item for item in ordered if item.event.event_id in ids]
                return True, {
                    "event_count": len(window_events),
                    "inbound_zone": bounded_zone(window_events[0].inbound_zone),
                    "outbound_zone": bounded_zone(window_events[0].outbound_zone),
                    "service": service,
                    "destination_ports": _destination_ports(items),
                    "effective_destination": destination_ip,
                    "distinct_sources": len({item.source_ip for item in items}),
                }

            raw_events = [item.event for item in ordered]
            for match_events, metrics in sliding_window_scan(
                raw_events,
                settings.INBOUND_EXPOSURE_WINDOW_SECONDS,
                matches,
            ):
                ids = {event.event_id for event in match_events}
                match_items = [item for item in ordered if item.event.event_id in ids]
                signals.append(
                    _build_signal(
                        self,
                        match_items,
                        context,
                        primary_entity=destination_ip,
                        correlation_key=f"wan_dmz_{service}",
                        target_entities=[item.source_ip for item in match_items],
                        metrics=metrics,
                        minimum_events=settings.WAN_TO_DMZ_ADMIN_MIN_ALLOWED_EVENTS,
                        reason="Allowed WAN-to-DMZ access to an administrative service",
                        tags=["network", "firewall", "wan_to_dmz", service],
                    )
                )
        return _sort_signals(signals)


class BlockedThenAllowedSameServiceRule(BaseDetectionRule):
    metadata = DetectionRuleMetadata(
        rule_id="blocked_then_allowed_same_service",
        version="1.0.0",
        name="Repeated Blocks Followed by Allowed Same Service",
        family="network_intrusion_candidate",
        priority=43,
        supported_event_types=(),
        required_fields=("src_ip", "protocol", "action"),
        signal_type="blocked_then_allowed_same_service",
        default_severity="high",
        mitre_techniques=("T1046",),
        window_setting="BLOCKED_THEN_ALLOWED_WINDOW_SECONDS",
        minimum_events_setting="BLOCKED_THEN_ALLOWED_MIN_BLOCKED_EVENTS",
    )

    def evaluate(
        self,
        events: Sequence[CanonicalLogEvent],
        context: DetectionContext,
    ) -> list[DetectionSignal]:
        settings = context.settings
        groups: dict[tuple[str, str, str], list[_ExposureEvent]] = defaultdict(list)
        for event in events:
            item = _exposure_event(event, _service_or_exact_port)
            if item is not None and (is_allowed(event) or is_blocked(event)):
                groups[(item.source_ip, item.destination_ip, item.service)].append(item)

        signals: list[DetectionSignal] = []
        for (source_ip, destination_ip, service), grouped in groups.items():
            ordered = _ordered(grouped, context)
            for allowed_index, allowed_item in enumerate(ordered):
                allowed_event = allowed_item.event
                if not is_allowed(allowed_event) or allowed_event.timestamp is None:
                    continue
                blocked_items = [
                    item
                    for item in ordered[:allowed_index]
                    if item.event.timestamp is not None
                    and is_blocked(item.event)
                    and not is_spi_anomaly_event(
                        item.event,
                        fallback_raw_match=(
                            settings.SPI_ANOMALY_FALLBACK_RAW_MATCH
                        ),
                    )
                    and (
                        item.destination_port == allowed_item.destination_port
                        or item.service == allowed_item.service
                    )
                    and 0
                    <= (
                        allowed_event.timestamp - item.event.timestamp
                    ).total_seconds()
                    <= settings.BLOCKED_THEN_ALLOWED_WINDOW_SECONDS
                ]
                if len(blocked_items) < settings.BLOCKED_THEN_ALLOWED_MIN_BLOCKED_EVENTS:
                    continue
                match_items = [*blocked_items, allowed_item]
                first_seen = blocked_items[0].event.timestamp or context.analysis_started_at
                metrics: dict[str, MetricValue] = {
                    "blocked_event_count": len(blocked_items),
                    "allowed_event_id": allowed_event.event_id,
                    "effective_destination": destination_ip,
                    "destination_port": allowed_item.destination_port,
                    "service": service,
                    "time_to_allowed_seconds": max(
                        0.0,
                        (allowed_event.timestamp - first_seen).total_seconds(),
                    ),
                }
                evidence = select_representative_evidence(
                    [item.event for item in blocked_items],
                    max_evidence=2,
                    reason="Representative blocked attempts before an allowed service connection",
                    source_rule=self.rule_id,
                    correlation_context=metrics,
                )
                evidence.append(
                    create_evidence_from_event(
                        allowed_event,
                        reason="Allowed connection after repeated blocks to the same service",
                        source_rule=self.rule_id,
                        correlation_context=metrics,
                    )
                )
                signals.append(
                    _build_signal(
                        self,
                        match_items,
                        context,
                        primary_entity=source_ip,
                        correlation_key=f"{destination_ip}_{service}_{allowed_item.destination_port}",
                        target_entities=[destination_ip],
                        metrics=metrics,
                        minimum_events=settings.BLOCKED_THEN_ALLOWED_MIN_BLOCKED_EVENTS,
                        reason="Repeated blocks followed by an allowed service connection",
                        tags=["network", "firewall", "sequence", service],
                        evidence=evidence,
                    )
                )
        return _sort_signals(signals)


class MultiSourceAllowedSensitiveServiceRule(BaseDetectionRule):
    metadata = DetectionRuleMetadata(
        rule_id="multi_source_allowed_sensitive_service",
        version="1.0.0",
        name="Multi-Source Allowed Sensitive Service Access",
        family="firewall_exposure",
        priority=46,
        supported_event_types=(),
        required_fields=("src_ip", "protocol", "action"),
        signal_type="multi_source_allowed_sensitive_service",
        default_severity="high",
        mitre_techniques=(),
        window_setting="MULTI_SOURCE_SENSITIVE_WINDOW_SECONDS",
        minimum_events_setting="MULTI_SOURCE_SENSITIVE_MIN_EVENTS",
    )

    def evaluate(
        self,
        events: Sequence[CanonicalLogEvent],
        context: DetectionContext,
    ) -> list[DetectionSignal]:
        settings = context.settings
        groups: dict[tuple[str, str], list[_ExposureEvent]] = defaultdict(list)
        for event in events:
            item = _exposure_event(event, sensitive_service_for_port)
            if (
                item is not None
                and is_allowed(event)
                and is_public_source(event)
                and is_private_effective_destination(event)
            ):
                groups[(item.destination_ip, item.service)].append(item)

        signals: list[DetectionSignal] = []
        for (destination_ip, service), grouped in groups.items():
            ordered = _ordered(grouped, context)

            def matches(
                window: deque[CanonicalLogEvent],
            ) -> tuple[bool, dict[str, Any]]:
                window_events = list(window)
                if len(window_events) < settings.MULTI_SOURCE_SENSITIVE_MIN_EVENTS:
                    return False, {}
                sources = {event.src_ip for event in window_events if event.src_ip}
                if (
                    len(sources)
                    < settings.MULTI_SOURCE_SENSITIVE_MIN_DISTINCT_SOURCES
                ):
                    return False, {}
                ids = {event.event_id for event in window_events}
                items = [item for item in ordered if item.event.event_id in ids]
                return True, {
                    "event_count": len(window_events),
                    "distinct_sources": len(sources),
                    "service": service,
                    "destination_ports": _destination_ports(items),
                    "effective_destination": destination_ip,
                    "explicit_wan_events": sum(
                        1
                        for event in window_events
                        if is_explicit_wan_zone(event.inbound_zone)
                    ),
                    "destination_translation_events": sum(
                        1 for event in window_events if has_destination_translation(event)
                    ),
                }

            raw_events = [item.event for item in ordered]
            for match_events, metrics in sliding_window_scan(
                raw_events,
                settings.MULTI_SOURCE_SENSITIVE_WINDOW_SECONDS,
                matches,
            ):
                ids = {event.event_id for event in match_events}
                match_items = [item for item in ordered if item.event.event_id in ids]
                signals.append(
                    _build_signal(
                        self,
                        match_items,
                        context,
                        primary_entity=destination_ip,
                        correlation_key=f"multi_source_{service}",
                        target_entities=[item.source_ip for item in match_items],
                        metrics=metrics,
                        minimum_events=settings.MULTI_SOURCE_SENSITIVE_MIN_EVENTS,
                        reason="Allowed sensitive-service access from multiple public sources",
                        tags=["network", "firewall", "multi_source", service],
                    )
                )
        return _sort_signals(signals)
