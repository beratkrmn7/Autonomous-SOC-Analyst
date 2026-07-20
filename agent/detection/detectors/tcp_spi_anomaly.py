from collections import defaultdict, deque
from collections.abc import Sequence
from typing import Any, ClassVar, cast

from agent.detection.config import DetectionSettings
from agent.detection.contracts import DetectionRuleMetadata
from agent.detection.correlation import sliding_window_scan
from agent.detection.detectors.base import BaseDetectionRule, DetectionContext
from agent.detection.detectors.scan_helpers import (
    bounded_sorted_values,
    classify_service,
    event_tcp_flag_tokens,
    has_exact_tcp_flags,
    has_tcp_flags,
    is_allowed,
    is_blocked,
    is_explicit_tcp_null,
    is_spi_anomaly_event,
    is_spi_block_event,
    normalized_protocol,
    parse_ip_address,
)
from agent.detection.evidence import (
    create_evidence_from_event,
    select_representative_evidence,
)
from agent.detection.models import DetectionSignal, generate_signal_id
from agent.detection.scoring import calculate_signal_confidence
from agent.schema import CanonicalLogEvent


class _TcpFlagPatternRule(BaseDetectionRule):
    window_setting_name: ClassVar[str] = "TCP_FLAG_SCAN_WINDOW_SECONDS"
    minimum_events_setting_name: ClassVar[str] = "TCP_FLAG_SCAN_MIN_EVENTS"
    minimum_targets_setting_name: ClassVar[str] = (
        "TCP_FLAG_SCAN_MIN_DISTINCT_TARGETS"
    )
    minimum_ports_setting_name: ClassVar[str] = "TCP_FLAG_SCAN_MIN_DISTINCT_PORTS"
    minimum_block_ratio_setting_name: ClassVar[str] = (
        "TCP_FLAG_SCAN_MIN_BLOCK_RATIO"
    )
    tcp_flag_pattern: ClassVar[str]

    def matches_flags(self, event: CanonicalLogEvent) -> bool:
        raise NotImplementedError

    def additional_metrics(
        self,
        events: Sequence[CanonicalLogEvent],
        settings: DetectionSettings,
    ) -> dict[str, int | float | str | bool]:
        return {}

    def evaluate(
        self,
        events: Sequence[CanonicalLogEvent],
        context: DetectionContext,
    ) -> list[DetectionSignal]:
        settings = context.settings
        window_seconds = cast(int, getattr(settings, self.window_setting_name))
        minimum_events = cast(
            int, getattr(settings, self.minimum_events_setting_name)
        )
        minimum_targets = cast(
            int, getattr(settings, self.minimum_targets_setting_name)
        )
        minimum_ports = cast(
            int, getattr(settings, self.minimum_ports_setting_name)
        )
        minimum_block_ratio = cast(
            float, getattr(settings, self.minimum_block_ratio_setting_name)
        )

        groups: dict[str, list[CanonicalLogEvent]] = defaultdict(list)
        for event in events:
            source_address = parse_ip_address(event.src_ip)
            destination_address = parse_ip_address(event.dst_ip)
            if (
                source_address is None
                or destination_address is None
                or normalized_protocol(event) != "TCP"
                or not self.matches_flags(event)
            ):
                continue
            groups[str(source_address)].append(event)

        signals: list[DetectionSignal] = []
        for source_ip, grouped_events in groups.items():
            if len(grouped_events) < minimum_events:
                continue
            ordered_events = sorted(
                grouped_events,
                key=lambda event: (
                    event.timestamp or context.analysis_started_at,
                    event.event_id,
                ),
            )

            def matches(
                window: deque[CanonicalLogEvent],
            ) -> tuple[bool, dict[str, Any]]:
                window_events = list(window)
                if len(window_events) < minimum_events:
                    return False, {}
                targets = {
                    str(address)
                    for event in window_events
                    if (address := parse_ip_address(event.dst_ip)) is not None
                }
                ports = {
                    event.dst_port
                    for event in window_events
                    if event.dst_port is not None
                }
                if not (
                    len(targets) >= minimum_targets
                    or len(ports) >= minimum_ports
                ):
                    return False, {}
                block_ratio = sum(
                    1 for event in window_events if is_blocked(event)
                ) / len(window_events)
                if block_ratio < minimum_block_ratio:
                    return False, {}
                metrics: dict[str, int | float | str | bool] = {
                    "event_count": len(window_events),
                    "distinct_targets": len(targets),
                    "distinct_ports": len(ports),
                    "block_ratio": block_ratio,
                    "tcp_flag_pattern": self.tcp_flag_pattern,
                }
                metrics.update(self.additional_metrics(window_events, settings))
                return True, metrics

            for match_events, metrics in sliding_window_scan(
                ordered_events,
                window_seconds,
                matches,
            ):
                event_ids = [event.event_id for event in match_events]
                first_seen = (
                    match_events[0].timestamp or context.analysis_started_at
                )
                last_seen = match_events[-1].timestamp or context.analysis_started_at
                signal_id = generate_signal_id(
                    self.rule_id,
                    self.version,
                    source_ip,
                    self.tcp_flag_pattern,
                    first_seen,
                    event_ids,
                )
                signals.append(
                    DetectionSignal(
                        signal_id=signal_id,
                        rule_id=self.rule_id,
                        rule_version=self.version,
                        rule_name=self.name,
                        signal_type=self.metadata.signal_type,
                        signal_family=self.family,
                        severity=self.metadata.default_severity,
                        confidence=calculate_signal_confidence(
                            len(match_events),
                            minimum_events,
                            base_confidence=(
                                0.75
                                if self.metadata.default_severity == "high"
                                else 0.65
                            ),
                            max_confidence=(
                                0.95
                                if self.metadata.default_severity == "high"
                                else 0.9
                            ),
                        ),
                        first_seen=first_seen,
                        last_seen=last_seen,
                        event_ids=event_ids,
                        primary_entity=source_ip,
                        target_entities=bounded_sorted_values(
                            str(address)
                            for event in match_events
                            if (address := parse_ip_address(event.dst_ip)) is not None
                        ),
                        metrics=metrics,
                        evidence=select_representative_evidence(
                            match_events,
                            max_evidence=3,
                            reason=f"Repeated TCP flag pattern {self.tcp_flag_pattern}",
                            source_rule=self.rule_id,
                            correlation_context=metrics,
                        ),
                        mitre_techniques=list(self.metadata.mitre_techniques),
                        tags=["network", "tcp", "anomaly"],
                    )
                )
        return sorted(
            signals,
            key=lambda signal: (
                signal.first_seen,
                signal.rule_id,
                signal.signal_id,
            ),
        )


class TcpNullScanRule(_TcpFlagPatternRule):
    tcp_flag_pattern = "NONE"
    metadata = DetectionRuleMetadata(
        rule_id="tcp_null_scan",
        version="1.0.0",
        name="TCP NULL Scan",
        family="network_scanning",
        priority=83,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "protocol"),
        signal_type="tcp_null_scan",
        default_severity="medium",
        mitre_techniques=("T1046",),
        window_setting="TCP_FLAG_SCAN_WINDOW_SECONDS",
        minimum_events_setting="TCP_FLAG_SCAN_MIN_EVENTS",
    )

    def matches_flags(self, event: CanonicalLogEvent) -> bool:
        return is_explicit_tcp_null(event)


class TcpXmasScanRule(_TcpFlagPatternRule):
    tcp_flag_pattern = "FIN,PSH,URG"
    metadata = DetectionRuleMetadata(
        rule_id="tcp_xmas_scan",
        version="1.0.0",
        name="TCP XMAS Scan",
        family="network_scanning",
        priority=84,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "protocol"),
        signal_type="tcp_xmas_scan",
        default_severity="medium",
        mitre_techniques=("T1046",),
        window_setting="TCP_FLAG_SCAN_WINDOW_SECONDS",
        minimum_events_setting="TCP_FLAG_SCAN_MIN_EVENTS",
    )

    def matches_flags(self, event: CanonicalLogEvent) -> bool:
        return has_exact_tcp_flags(event, frozenset({"FIN", "PSH", "URG"}))


class TcpFinScanRule(_TcpFlagPatternRule):
    tcp_flag_pattern = "FIN"
    metadata = DetectionRuleMetadata(
        rule_id="tcp_fin_scan",
        version="1.0.0",
        name="TCP FIN Scan",
        family="network_scanning",
        priority=85,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "protocol"),
        signal_type="tcp_fin_scan",
        default_severity="medium",
        mitre_techniques=("T1046",),
        window_setting="TCP_FLAG_SCAN_WINDOW_SECONDS",
        minimum_events_setting="TCP_FLAG_SCAN_MIN_EVENTS",
    )

    def matches_flags(self, event: CanonicalLogEvent) -> bool:
        return has_exact_tcp_flags(event, frozenset({"FIN"}))


class TcpAckScanRule(_TcpFlagPatternRule):
    minimum_events_setting_name = "TCP_ACK_SCAN_MIN_EVENTS"
    minimum_block_ratio_setting_name = "TCP_ACK_SCAN_MIN_BLOCK_RATIO"
    tcp_flag_pattern = "ACK"
    metadata = DetectionRuleMetadata(
        rule_id="tcp_ack_scan",
        version="1.0.0",
        name="TCP ACK Scan",
        family="network_scanning",
        priority=86,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "protocol"),
        signal_type="tcp_ack_scan",
        default_severity="medium",
        mitre_techniques=("T1046",),
        window_setting="TCP_FLAG_SCAN_WINDOW_SECONDS",
        minimum_events_setting="TCP_ACK_SCAN_MIN_EVENTS",
    )

    def matches_flags(self, event: CanonicalLogEvent) -> bool:
        return has_exact_tcp_flags(event, frozenset({"ACK"}))


class TcpSynFinAnomalyRule(_TcpFlagPatternRule):
    minimum_events_setting_name = "TCP_INVALID_COMBINATION_MIN_EVENTS"
    minimum_block_ratio_setting_name = (
        "TCP_INVALID_COMBINATION_MIN_BLOCK_RATIO"
    )
    tcp_flag_pattern = "FIN,SYN"
    metadata = DetectionRuleMetadata(
        rule_id="tcp_syn_fin_anomaly",
        version="1.0.0",
        name="TCP SYN+FIN Anomaly",
        family="network_anomaly",
        priority=81,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "protocol"),
        signal_type="tcp_syn_fin_anomaly",
        default_severity="high",
        mitre_techniques=("T1046",),
        window_setting="TCP_FLAG_SCAN_WINDOW_SECONDS",
        minimum_events_setting="TCP_INVALID_COMBINATION_MIN_EVENTS",
    )

    def matches_flags(self, event: CanonicalLogEvent) -> bool:
        return has_tcp_flags(event, frozenset({"SYN", "FIN"}))

    def additional_metrics(
        self,
        events: Sequence[CanonicalLogEvent],
        settings: DetectionSettings,
    ) -> dict[str, int | float | str | bool]:
        return {
            "spi_event_count": sum(
                1
                for event in events
                if is_spi_anomaly_event(
                    event,
                    fallback_raw_match=settings.SPI_ANOMALY_FALLBACK_RAW_MATCH,
                )
            )
        }


class TcpSynRstAnomalyRule(_TcpFlagPatternRule):
    minimum_events_setting_name = "TCP_INVALID_COMBINATION_MIN_EVENTS"
    minimum_block_ratio_setting_name = (
        "TCP_INVALID_COMBINATION_MIN_BLOCK_RATIO"
    )
    tcp_flag_pattern = "SYN,RST"
    metadata = DetectionRuleMetadata(
        rule_id="tcp_syn_rst_anomaly",
        version="1.0.0",
        name="TCP SYN+RST Anomaly",
        family="network_anomaly",
        priority=82,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "protocol"),
        signal_type="tcp_syn_rst_anomaly",
        default_severity="medium",
        mitre_techniques=("T1046",),
        window_setting="TCP_FLAG_SCAN_WINDOW_SECONDS",
        minimum_events_setting="TCP_INVALID_COMBINATION_MIN_EVENTS",
    )

    def matches_flags(self, event: CanonicalLogEvent) -> bool:
        return has_tcp_flags(event, frozenset({"SYN", "RST"}))

    def additional_metrics(
        self,
        events: Sequence[CanonicalLogEvent],
        settings: DetectionSettings,
    ) -> dict[str, int | float | str | bool]:
        spi_event_count = sum(
            1
            for event in events
            if is_spi_anomaly_event(
                event,
                fallback_raw_match=settings.SPI_ANOMALY_FALLBACK_RAW_MATCH,
            )
        )
        return {
            "spi_event_count": spi_event_count,
            "spi_ratio": spi_event_count / len(events),
        }


class RepeatedTcpResetAnomalyRule(_TcpFlagPatternRule):
    window_setting_name = "TCP_RESET_ANOMALY_WINDOW_SECONDS"
    minimum_events_setting_name = "TCP_RESET_ANOMALY_MIN_EVENTS"
    minimum_targets_setting_name = "TCP_RESET_ANOMALY_MIN_DISTINCT_TARGETS"
    minimum_ports_setting_name = "TCP_RESET_ANOMALY_MIN_DISTINCT_PORTS"
    minimum_block_ratio_setting_name = "TCP_RESET_ANOMALY_MIN_BLOCK_RATIO"
    tcp_flag_pattern = "RST_WITHOUT_SYN"
    metadata = DetectionRuleMetadata(
        rule_id="repeated_tcp_reset_anomaly",
        version="1.0.0",
        name="Repeated TCP Reset Anomaly",
        family="network_anomaly",
        priority=87,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "protocol"),
        signal_type="repeated_tcp_reset_anomaly",
        default_severity="medium",
        mitre_techniques=("T1046",),
        window_setting="TCP_RESET_ANOMALY_WINDOW_SECONDS",
        minimum_events_setting="TCP_RESET_ANOMALY_MIN_EVENTS",
    )

    def matches_flags(self, event: CanonicalLogEvent) -> bool:
        tokens = event_tcp_flag_tokens(event)
        return "RST" in tokens and "SYN" not in tokens

    def additional_metrics(
        self,
        events: Sequence[CanonicalLogEvent],
        settings: DetectionSettings,
    ) -> dict[str, int | float | str | bool]:
        reset_only_events = 0
        ack_reset_events = 0
        other_reset_events = 0
        for event in events:
            tokens = event_tcp_flag_tokens(event)
            if tokens == frozenset({"RST"}):
                reset_only_events += 1
            elif "ACK" in tokens:
                ack_reset_events += 1
            else:
                other_reset_events += 1
        return {
            "reset_only_events": reset_only_events,
            "ack_reset_events": ack_reset_events,
            "other_reset_events": other_reset_events,
        }


class SpiFollowedByAllowedConnectionRule(BaseDetectionRule):
    metadata = DetectionRuleMetadata(
        rule_id="spi_followed_by_allowed_connection",
        version="1.0.0",
        name="SPI Followed by Allowed Connection",
        family="network_intrusion_candidate",
        priority=42,
        supported_event_types=(),
        required_fields=("src_ip", "dst_ip", "dst_port", "protocol", "action"),
        signal_type="spi_followed_by_allowed_connection",
        default_severity="high",
        mitre_techniques=("T1046",),
        window_setting="SPI_THEN_ALLOWED_WINDOW_SECONDS",
        minimum_events_setting="SPI_THEN_ALLOWED_MIN_SPI_EVENTS",
    )

    def evaluate(
        self,
        events: Sequence[CanonicalLogEvent],
        context: DetectionContext,
    ) -> list[DetectionSignal]:
        settings = context.settings
        groups: dict[str, list[CanonicalLogEvent]] = defaultdict(list)
        for event in events:
            source_address = parse_ip_address(event.src_ip)
            destination_address = parse_ip_address(event.dst_ip)
            if (
                source_address is None
                or destination_address is None
                or event.dst_port is None
                or normalized_protocol(event) != "TCP"
            ):
                continue
            groups[str(source_address)].append(event)

        signals: list[DetectionSignal] = []
        for source_ip, grouped_events in groups.items():
            ordered_events = sorted(
                grouped_events,
                key=lambda event: (
                    event.timestamp or context.analysis_started_at,
                    event.event_id,
                ),
            )
            for allowed_index, allowed_event in enumerate(ordered_events):
                if not is_allowed(allowed_event) or allowed_event.timestamp is None:
                    continue
                spi_events = [
                    event
                    for event in ordered_events[:allowed_index]
                    if event.timestamp is not None
                    and is_spi_block_event(
                        event,
                        fallback_raw_match=(
                            settings.SPI_ANOMALY_FALLBACK_RAW_MATCH
                        ),
                    )
                    and 0
                    <= (allowed_event.timestamp - event.timestamp).total_seconds()
                    <= settings.SPI_THEN_ALLOWED_WINDOW_SECONDS
                ]
                if len(spi_events) < settings.SPI_THEN_ALLOWED_MIN_SPI_EVENTS:
                    continue
                allowed_service = classify_service(allowed_event.dst_port)
                has_related_spi_event = any(
                    event.dst_ip == allowed_event.dst_ip
                    and (
                        event.dst_port == allowed_event.dst_port
                        or (
                            allowed_service is not None
                            and classify_service(event.dst_port) == allowed_service
                        )
                    )
                    for event in spi_events
                )
                if not has_related_spi_event:
                    continue

                first_seen = spi_events[0].timestamp or context.analysis_started_at
                last_seen = allowed_event.timestamp
                event_ids = [event.event_id for event in spi_events]
                event_ids.append(allowed_event.event_id)
                distinct_spi_targets = {
                    event.dst_ip for event in spi_events if event.dst_ip is not None
                }
                metrics: dict[str, int | float | str | bool] = {
                    "spi_event_count": len(spi_events),
                    "distinct_spi_targets": len(distinct_spi_targets),
                    "allowed_event_id": allowed_event.event_id,
                    "allowed_destination": allowed_event.dst_ip or "unknown",
                    "allowed_destination_port": cast(int, allowed_event.dst_port),
                    "time_to_allowed_seconds": max(
                        0.0, (last_seen - first_seen).total_seconds()
                    ),
                }
                evidence = select_representative_evidence(
                    spi_events,
                    max_evidence=2,
                    reason="Representative explicit SPI blocks before an allowed connection",
                    source_rule=self.rule_id,
                    correlation_context=metrics,
                )
                evidence.append(
                    create_evidence_from_event(
                        allowed_event,
                        reason="Allowed connection after related explicit SPI blocks",
                        source_rule=self.rule_id,
                        correlation_context=metrics,
                    )
                )
                signal_id = generate_signal_id(
                    self.rule_id,
                    self.version,
                    source_ip,
                    f"allowed_{allowed_event.dst_ip}_{allowed_event.dst_port}",
                    first_seen,
                    event_ids,
                )
                signals.append(
                    DetectionSignal(
                        signal_id=signal_id,
                        rule_id=self.rule_id,
                        rule_version=self.version,
                        rule_name=self.name,
                        signal_type=self.metadata.signal_type,
                        signal_family=self.family,
                        severity=self.metadata.default_severity,
                        confidence=calculate_signal_confidence(
                            len(spi_events),
                            settings.SPI_THEN_ALLOWED_MIN_SPI_EVENTS,
                            base_confidence=0.8,
                            max_confidence=0.95,
                        ),
                        first_seen=first_seen,
                        last_seen=last_seen,
                        event_ids=event_ids,
                        primary_entity=source_ip,
                        target_entities=bounded_sorted_values(
                            [
                                *(
                                    event.dst_ip
                                    for event in spi_events
                                    if event.dst_ip is not None
                                ),
                                allowed_event.dst_ip or "unknown",
                            ]
                        ),
                        metrics=metrics,
                        evidence=evidence,
                        mitre_techniques=list(self.metadata.mitre_techniques),
                        tags=["network", "spi", "sequence", "allowed_after_spi"],
                    )
                )
        return sorted(
            signals,
            key=lambda signal: (
                signal.first_seen,
                signal.rule_id,
                signal.signal_id,
            ),
        )
