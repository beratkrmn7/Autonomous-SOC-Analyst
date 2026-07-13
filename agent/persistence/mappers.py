# mypy: ignore-errors
from agent.persistence.orm_models import (
    CanonicalEvent, DetectionSignal, Incident, 
    IncidentEvent, IncidentSignal
)
from agent.ingestion.models import CanonicalLogEvent
from agent.detection.models import DetectionSignal as DomainDetectionSignal
from agent.detection.models import IncidentBundle

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
            source_username=orm_event.user,
            parse_status='success'
        )

    @staticmethod
    def domain_signal_to_orm(signal: DomainDetectionSignal) -> DetectionSignal:
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
            metrics=signal.metrics,
            mitre_techniques=signal.mitre_techniques,
            target_entities=signal.target_entities,
            event_ids=signal.event_ids
        )

    @staticmethod
    def orm_to_domain_signal(orm_signal: DetectionSignal) -> DomainDetectionSignal:
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
            target_entities=orm_signal.target_entities,
            metrics=orm_signal.metrics,
            mitre_techniques=orm_signal.mitre_techniques
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
            signal_ids=[s.signal_id for s in orm_inc.signals],
            event_ids=[e.event_id for e in orm_inc.events if not e.is_context],
            context_event_ids=[e.event_id for e in orm_inc.events if e.is_context],
            evidence=[], # Evidence is separate
            metrics=orm_inc.metrics,
            mitre_techniques=orm_inc.mitre_techniques,
            merge_key=""
        )
