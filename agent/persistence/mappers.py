from agent.persistence.orm_models import (
    CanonicalEvent, DetectionSignal, Incident, 
    IncidentEvent, IncidentSignal
)
from agent.ingestion.models import CanonicalLogEvent
from agent.detection.models import DetectionSignal as DomainDetectionSignal
from agent.detection.models import IncidentBundle
from typing import List, Dict, Any

class DataMapper:
    @staticmethod
    def domain_event_to_orm(event: CanonicalLogEvent, job_id: str = None) -> CanonicalEvent:
        return CanonicalEvent(
            event_id=event.event_id,
            job_id=job_id,
            source_name=event.source_name,
            parser_name=event.parser_name,
            timestamp=event.timestamp,
            raw_message=event.raw_message,
            original_log=event.original_log,
            normalized_fields=event.normalized_fields,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            src_port=event.src_port,
            dst_port=event.dst_port,
            protocol=event.protocol,
            action=event.action,
            user=event.user
        )

    @staticmethod
    def orm_to_domain_event(orm_event: CanonicalEvent) -> CanonicalLogEvent:
        return CanonicalLogEvent(
            event_id=orm_event.event_id,
            source_name=orm_event.source_name,
            parser_name=orm_event.parser_name,
            timestamp=orm_event.timestamp,
            raw_message=orm_event.raw_message,
            original_log=orm_event.original_log,
            normalized_fields=orm_event.normalized_fields,
            src_ip=orm_event.src_ip,
            dst_ip=orm_event.dst_ip,
            src_port=orm_event.src_port,
            dst_port=orm_event.dst_port,
            protocol=orm_event.protocol,
            action=orm_event.action,
            user=orm_event.user
        )

    @staticmethod
    def domain_signal_to_orm(signal: DomainDetectionSignal) -> DetectionSignal:
        return DetectionSignal(
            signal_id=signal.signal_id,
            rule_id=signal.rule_id,
            rule_name=signal.rule_name,
            signal_type=signal.signal_type,
            severity=signal.severity,
            confidence=signal.confidence,
            metrics=signal.metrics,
            mitre_techniques=signal.mitre_techniques,
            target_entities=signal.target_entities,
            event_ids=signal.event_ids
        )

    @staticmethod
    def orm_to_domain_signal(orm_signal: DetectionSignal) -> DomainDetectionSignal:
        return DomainDetectionSignal(
            signal_id=orm_signal.signal_id,
            rule_id=orm_signal.rule_id,
            rule_name=orm_signal.rule_name,
            signal_type=orm_signal.signal_type,
            signal_family=orm_signal.signal_type, # Provide fallback
            severity=orm_signal.severity,
            confidence=orm_signal.confidence,
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
            severity=bundle.severity,
            confidence=bundle.confidence,
            first_seen=bundle.first_seen,
            last_seen=bundle.last_seen,
            primary_entity=bundle.primary_entity,
            target_entities=bundle.target_entities,
            mitre_techniques=bundle.mitre_techniques,
            metrics=bundle.metrics
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
        return IncidentBundle(
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
