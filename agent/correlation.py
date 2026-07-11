from typing import List
from agent.schema import CanonicalLogEvent
from agent.models import IncidentBundle as OldIncidentBundle
from agent.detection.engine import DetectionEngine
from agent.detection.models import DetectionResult

class CorrelationEngine:
    """
    Deprecated facade for the Phase 3 DetectionEngine.
    Used to bridge old code that expects the old IncidentBundle structure.
    """
    def __init__(self):
        self.engine = DetectionEngine()

    def build_incidents(self, candidate_events: List[CanonicalLogEvent], context_events: List[CanonicalLogEvent]) -> List[OldIncidentBundle]:
        # Run new detection engine
        result: DetectionResult = self.engine.analyze(candidate_events, context_events)
        
        # Build event map
        event_map = {e.event_id: e for e in candidate_events if e.event_id}
        context_map = {e.event_id: e for e in context_events if e.event_id}
        
        old_bundles = []
        for inc in result.incidents:
            resolved_events = [event_map[eid] for eid in inc.event_ids if eid in event_map]
            resolved_context = [context_map[eid] for eid in inc.context_event_ids if eid in context_map]
            
            # Convert new IncidentBundle to old IncidentBundle
            old_bundle = OldIncidentBundle(
                incident_id=inc.incident_id,
                incident_type_hint=inc.incident_type,
                first_seen=inc.first_seen,
                last_seen=inc.last_seen,
                source_ips=[inc.primary_entity] if inc.primary_entity else [],
                destination_ips=inc.target_entities,
                destination_ports=[], # Extracted from metrics if needed
                event_ids=inc.event_ids,
                events=resolved_events,
                context_events=resolved_context,
                correlation_reason=f"Correlated {len(inc.signal_ids)} signals: {', '.join(inc.signal_ids)}",
                correlation_metrics=inc.metrics,
                severity_hint=inc.severity,
                confidence_hint=inc.confidence
            )
            old_bundles.append(old_bundle)
            
        return old_bundles
