# mypy: ignore-errors
from agent.persistence.orm_models import (
    CanonicalEvent, DetectionSignal, Incident,
    IncidentEvent, IncidentSignal
)
from agent.ingestion.models import CanonicalLogEvent
from agent.detection.models import DetectionSignal as DomainDetectionSignal
from agent.detection.models import IncidentBundle

# Reserved internal key: DetectionSignal has no dedicated primary_entity
# column (no migration), so the real source/attacker entity is smuggled
# through the existing metrics JSON column and stripped back out on
# hydration so it never leaks into the public metrics.
_PRIMARY_ENTITY_METRICS_KEY = "_primary_entity"
_UNKNOWN_PRIMARY_ENTITY = "unknown"

# Public key already written by agent.detection.incident_correlation into
# IncidentBundle.metrics; read back here (not stripped - it is meant to be
# visible) to reconstruct absorbed_signal_ids without a migration.
_PRIMARY_SIGNAL_ID_METRICS_KEY = "primary_signal_id"

_MAX_INTERFACE_CHARS = 128
_MAX_ZONE_CHARS = 128
_MAX_ACTION_REASON_CHARS = 256
_MAX_NAT_TYPE_CHARS = 64
_MAX_IP_CHARS = 64
_MAX_TCP_FLAGS_CHARS = 64
_MAX_FQDN_CHARS = 253
_MAX_FQDNS = 20
_MAX_METADATA_TEXT_CHARS = 128
_MAX_TCP_FLAG_TOKENS = 16
_PERSISTED_METADATA_BOOL_FIELDS = (
    "spi_anomaly",
    "tcp_flags_present",
    "tcp_flags_explicit_none",
)
_PERSISTED_METADATA_TEXT_FIELDS = (
    "original_device_action",
    "original_tcp_flags",
    "pf_event_type",
    "source_timezone_offset",
)


def _bounded_optional_text(value, max_chars):
    if value is None:
        return None
    normalized = " ".join(str(value).split())
    return normalized[:max_chars] or None


def _bounded_fqdns(values):
    if not isinstance(values, (list, tuple)):
        return []
    bounded = []
    seen = set()
    for value in values:
        normalized = _bounded_optional_text(value, _MAX_FQDN_CHARS)
        if normalized is None or normalized in seen:
            continue
        seen.add(normalized)
        bounded.append(normalized)
        if len(bounded) >= _MAX_FQDNS:
            break
    return bounded


def _bounded_parser_metadata(metadata):
    """Persist only the bounded PF facts required after hydration.

    Canonical parser metadata is intentionally not a general persistence
    extension point. Unknown keys and nested values are discarded.
    """
    if not isinstance(metadata, dict):
        return None

    bounded = {}
    for key in _PERSISTED_METADATA_BOOL_FIELDS:
        value = metadata.get(key)
        if isinstance(value, bool):
            bounded[key] = value
    for key in _PERSISTED_METADATA_TEXT_FIELDS:
        value = _bounded_optional_text(metadata.get(key), _MAX_METADATA_TEXT_CHARS)
        if value is not None:
            bounded[key] = value

    tokens = metadata.get("tcp_flag_tokens")
    if isinstance(tokens, (list, tuple)):
        bounded_tokens = []
        seen_tokens = set()
        for token in tokens:
            normalized = _bounded_optional_text(token, 16)
            if normalized is None or normalized in seen_tokens:
                continue
            seen_tokens.add(normalized)
            bounded_tokens.append(normalized)
            if len(bounded_tokens) >= _MAX_TCP_FLAG_TOKENS:
                break
        bounded["tcp_flag_tokens"] = bounded_tokens

    return bounded or None


class DataMapper:
    @staticmethod
    def domain_event_to_orm(event: CanonicalLogEvent) -> CanonicalEvent:
        return CanonicalEvent(
            event_id=event.event_id,
            source_name=event.source_name,
            parser_name=event.parser_name,
            timestamp=event.timestamp,
            observed_at=event.observed_at,
            source_line=event.source_line,
            raw_record_hash=event.raw_record_hash,
            safe_message_excerpt=event.safe_message_excerpt[:2000] if event.safe_message_excerpt else None,
            parser_version=event.parser_version,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            src_port=event.src_port,
            dst_port=event.dst_port,
            protocol=event.protocol,
            action=event.action,
            action_reason=_bounded_optional_text(
                event.action_reason, _MAX_ACTION_REASON_CHARS
            ),
            tcp_flags=_bounded_optional_text(event.tcp_flags, _MAX_TCP_FLAGS_CHARS),
            inbound_interface=_bounded_optional_text(
                event.inbound_interface, _MAX_INTERFACE_CHARS
            ),
            outbound_interface=_bounded_optional_text(
                event.outbound_interface, _MAX_INTERFACE_CHARS
            ),
            inbound_zone=_bounded_optional_text(event.inbound_zone, _MAX_ZONE_CHARS),
            outbound_zone=_bounded_optional_text(event.outbound_zone, _MAX_ZONE_CHARS),
            source_fqdns=_bounded_fqdns(event.source_fqdns),
            destination_fqdns=_bounded_fqdns(event.destination_fqdns),
            bytes=event.bytes,
            packets=event.packets,
            duration_ms=event.duration_ms,
            nat_type=_bounded_optional_text(event.nat_type, _MAX_NAT_TYPE_CHARS),
            translated_src_ip=_bounded_optional_text(
                event.translated_src_ip, _MAX_IP_CHARS
            ),
            translated_dst_ip=_bounded_optional_text(
                event.translated_dst_ip, _MAX_IP_CHARS
            ),
            translated_src_port=event.translated_src_port,
            translated_dst_port=event.translated_dst_port,
            parser_metadata=_bounded_parser_metadata(event.parser_metadata),
            user=event.source_username
        )

    @staticmethod
    def orm_to_domain_event(orm_event: CanonicalEvent) -> CanonicalLogEvent:
        return CanonicalLogEvent( # type: ignore
            event_id=orm_event.event_id,
            source_name=orm_event.source_name,
            parser_name=orm_event.parser_name,
            timestamp=orm_event.timestamp,
            observed_at=orm_event.observed_at,
            source_line=orm_event.source_line,
            raw_record_hash=orm_event.raw_record_hash,
            safe_message_excerpt=orm_event.safe_message_excerpt or "",
            parser_version=orm_event.parser_version,
            src_ip=orm_event.src_ip,
            dst_ip=orm_event.dst_ip,
            src_port=orm_event.src_port,
            dst_port=orm_event.dst_port,
            protocol=orm_event.protocol,
            action=orm_event.action,
            action_reason=orm_event.action_reason,
            tcp_flags=orm_event.tcp_flags,
            inbound_interface=orm_event.inbound_interface,
            outbound_interface=orm_event.outbound_interface,
            inbound_zone=orm_event.inbound_zone,
            outbound_zone=orm_event.outbound_zone,
            source_fqdns=list(orm_event.source_fqdns or []),
            destination_fqdns=list(orm_event.destination_fqdns or []),
            bytes=orm_event.bytes,
            packets=orm_event.packets,
            duration_ms=orm_event.duration_ms,
            nat_type=orm_event.nat_type,
            translated_src_ip=orm_event.translated_src_ip,
            translated_dst_ip=orm_event.translated_dst_ip,
            translated_src_port=orm_event.translated_src_port,
            translated_dst_port=orm_event.translated_dst_port,
            parser_metadata=(
                dict(orm_event.parser_metadata)
                if isinstance(orm_event.parser_metadata, dict)
                else None
            ),
            source_username=orm_event.user,
            parse_status='success'
        )

    @staticmethod
    def domain_signal_to_orm(signal: DomainDetectionSignal) -> DetectionSignal:
        metrics_with_primary_entity = {
            **signal.metrics,
            _PRIMARY_ENTITY_METRICS_KEY: signal.primary_entity,
        }
        return DetectionSignal(
            signal_id=signal.signal_id,
            rule_id=signal.rule_id,
            rule_name=signal.rule_name,
            rule_version=getattr(signal, 'rule_version', None),
            signal_family=getattr(signal, 'signal_family', None),
            signal_type=signal.signal_type,
            severity=signal.severity,
            confidence=signal.confidence,
            first_seen=getattr(signal, 'first_seen', None),
            last_seen=getattr(signal, 'last_seen', None),
            suppressed=getattr(signal, 'suppressed', False),
            suppression_reason=getattr(signal, 'suppression_reason', None),
            metrics=metrics_with_primary_entity,
            mitre_techniques=signal.mitre_techniques,
            target_entities=signal.target_entities,
            event_ids=signal.event_ids
        )

    @staticmethod
    def orm_to_domain_signal(orm_signal: DetectionSignal) -> DomainDetectionSignal:
        # Copy so popping the reserved key never mutates the ORM-tracked dict.
        public_metrics = dict(orm_signal.metrics or {})
        primary_entity = public_metrics.pop(_PRIMARY_ENTITY_METRICS_KEY, None)
        if not isinstance(primary_entity, str) or not primary_entity:
            # Old rows persisted before this key existed. Never fall back to
            # a target entity here - that would reverse source/attacker and
            # target/victim.
            primary_entity = _UNKNOWN_PRIMARY_ENTITY

        return DomainDetectionSignal( # type: ignore
            signal_id=orm_signal.signal_id,
            rule_id=orm_signal.rule_id,
            rule_name=orm_signal.rule_name,
            rule_version=orm_signal.rule_version,
            signal_type=orm_signal.signal_type,
            signal_family=orm_signal.signal_family or orm_signal.signal_type,
            severity=orm_signal.severity,
            confidence=orm_signal.confidence,
            first_seen=orm_signal.first_seen,
            last_seen=orm_signal.last_seen,
            suppressed=orm_signal.suppressed,
            suppression_reason=orm_signal.suppression_reason,
            event_ids=orm_signal.event_ids,
            primary_entity=primary_entity,
            target_entities=orm_signal.target_entities,
            metrics=public_metrics,
            # Not persisted on the signal row (no dedicated columns without a
            # migration); reconstructed empty, the same "not persisted
            # separately" convention already used by
            # orm_to_domain_incident's evidence=[].
            evidence=[],
            mitre_techniques=orm_signal.mitre_techniques,
            tags=[],
        )

    @staticmethod
    def domain_incident_to_orm(bundle: IncidentBundle) -> Incident:
        inc = Incident(
            incident_id=bundle.incident_id,
            title=bundle.title,
            incident_type=bundle.incident_type,
            incident_family=bundle.incident_family,
            merge_key=bundle.merge_key,
            severity=bundle.severity,
            confidence=bundle.confidence,
            first_seen=bundle.first_seen,
            last_seen=bundle.last_seen,
            primary_entity=bundle.primary_entity,
            target_entities=bundle.target_entities,
            mitre_techniques=bundle.mitre_techniques,
            metrics=bundle.metrics,
            status="new"
        )
        for eid in bundle.event_ids:
            inc.events.append(IncidentEvent(event_id=eid, is_context=False))
        for cid in bundle.context_event_ids:
            inc.events.append(IncidentEvent(event_id=cid, is_context=True))
        for sid in bundle.signal_ids:
            inc.signals.append(IncidentSignal(signal_id=sid))
        return inc

    @staticmethod
    def orm_to_domain_incident(orm_inc: Incident) -> IncidentBundle:
        signal_ids = [s.signal_id for s in orm_inc.signals]
        metrics = dict(orm_inc.metrics or {})
        # Phase 6E.2: no dedicated absorbed_signal_ids column (no
        # migration). The anchor/primary signal is persisted as a scalar
        # under this key in the existing metrics JSON column;
        # absorbed_signal_ids is every other correlated signal.
        primary_signal_id = metrics.get(_PRIMARY_SIGNAL_ID_METRICS_KEY)
        if isinstance(primary_signal_id, str) and primary_signal_id in signal_ids:
            absorbed_signal_ids = [
                sid for sid in signal_ids if sid != primary_signal_id
            ]
        else:
            absorbed_signal_ids = []

        return IncidentBundle( # type: ignore
            incident_id=orm_inc.incident_id,
            incident_type=orm_inc.incident_type,
            incident_family=orm_inc.incident_family,
            title=orm_inc.title,
            severity=orm_inc.severity,
            confidence=orm_inc.confidence,
            first_seen=orm_inc.first_seen,
            last_seen=orm_inc.last_seen,
            primary_entity=orm_inc.primary_entity,
            target_entities=orm_inc.target_entities,
            signal_ids=signal_ids,
            event_ids=[e.event_id for e in orm_inc.events if not e.is_context],
            context_event_ids=[e.event_id for e in orm_inc.events if e.is_context],
            evidence=[], # Evidence is separate
            metrics=metrics,
            mitre_techniques=orm_inc.mitre_techniques,
            merge_key=orm_inc.merge_key or "",
            absorbed_signal_ids=absorbed_signal_ids,
        )
