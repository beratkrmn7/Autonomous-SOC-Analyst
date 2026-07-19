import time
from datetime import datetime
from typing import List, Optional, Any, Set
import logging
from collections import defaultdict

from agent.schema import CanonicalLogEvent
from agent.detection.models import (
    DetectionSignal, IncidentBundle, DetectionResult, DetectionMetrics,
    generate_incident_id
)
from agent.detection.config import DetectionSettings, settings as default_settings
from agent.detection.registry import RuleRegistry, default_registry
from agent.detection.detectors.base import DetectionContext
from agent.detection.suppression import SuppressionPolicy
from agent.detection.scoring import calculate_incident_severity, calculate_incident_confidence

logger = logging.getLogger(__name__)

class DetectionEngine:
    def __init__(
        self,
        registry: RuleRegistry = default_registry,
        settings: DetectionSettings = default_settings,
        suppression_policy: Optional[SuppressionPolicy] = None
    ):
        if registry is default_registry and not registry.get_all_rules():
            from agent.detection.detectors import register_default_rules
            register_default_rules()
            
        self.registry = registry
        self.settings = settings
        self.suppression_policy = suppression_policy or SuppressionPolicy()

    def analyze(
        self,
        candidate_events: List[CanonicalLogEvent],
        context_events: Optional[List[CanonicalLogEvent]] = None
    ) -> DetectionResult:
        start_time = time.time()
        context_events = context_events or []
        
        metrics = DetectionMetrics()
        metrics.total_events = len(candidate_events)
        
        warnings = []
        
        # 1. Deduplicate by event_id and raw_record_hash
        seen_keys: Set[str] = set()
        deduped_events = []
        for e in candidate_events:
            if not e.event_id:
                warnings.append("Skipped event without ID")
                metrics.skipped_events += 1
                continue
            key = f"{e.event_id}|{e.raw_record_hash or ''}"
            if key in seen_keys:
                metrics.skipped_events += 1
                continue
            seen_keys.add(key)
            deduped_events.append(e)

        # 2. Eligibility Check
        eligible_events = []
        for e in deduped_events:
            if not e.timestamp:
                warnings.append(f"Event {e.event_id} skipped: missing timestamp")
                metrics.skipped_events += 1
                continue
            if e.timestamp.tzinfo is None:
                warnings.append(f"Event {e.event_id} skipped: timezone-naive timestamp")
                metrics.skipped_events += 1
                continue
            if e.parse_status in ["failed", "unsupported_schema", "semantically_invalid"]:
                warnings.append(f"Event {e.event_id} skipped: invalid parse_status '{e.parse_status}'")
                metrics.skipped_events += 1
                continue
            eligible_events.append(e)
            
        metrics.eligible_events = len(eligible_events)
        
        if not eligible_events:
            metrics.duration_ms = (time.time() - start_time) * 1000
            return DetectionResult(signals=[], incidents=[], suppressed_signals=[], uncorrelated_event_ids=[], warnings=warnings, metrics=metrics)
            
        # Create detection context
        # We know eligible_events[0].timestamp is not None
        DetectionContext(
            settings=self.settings,
            analysis_started_at=eligible_events[0].timestamp or datetime.now()
        )
        if not eligible_events:
            return DetectionResult(
                signals=[], incidents=[], suppressed_signals=[],
                uncorrelated_event_ids=[], metrics=metrics, warnings=["No eligible events found"]
            )
            
        # Deterministicaly sort events by timestamp then event_id
        eligible_events.sort(key=lambda x: (x.timestamp, x.event_id))
            
        context = DetectionContext(
            settings=self.settings,
            analysis_started_at=eligible_events[0].timestamp or datetime.now()
        )

        all_signals: List[DetectionSignal] = []
        
        # 2. Rule Execution
        for rule in self.registry.get_all_rules():
            try:
                signals = rule.evaluate(eligible_events, context)
                all_signals.extend(signals)
            except Exception as ex:
                logger.error(f"Rule {rule.rule_id} failed: {ex}")
                
        metrics.signal_count = len(all_signals)

        # 3. Suppression
        active_signals = []
        suppressed_signals = []
        for sig in all_signals:
            suppression_reason = self.suppression_policy.is_suppressed(sig)
            if suppression_reason:
                sig.suppressed = True
                sig.suppression_reason = suppression_reason
                suppressed_signals.append(sig)
                metrics.suppressed_signal_count += 1
            else:
                active_signals.append(sig)

        # 4. Signal Deduplication (Exact duplicates & Precedence)
        deduped_signals = self._deduplicate_signals(active_signals)
        metrics.duplicate_signal_count = len(active_signals) - len(deduped_signals)

        # 5. Incident Correlation and Merging
        incidents = self._correlate_incidents(deduped_signals, context_events or [])
        metrics.incident_count = len(incidents)
        
        # Determine uncorrelated events
        correlated_event_ids = set()
        for inc in incidents:
            correlated_event_ids.update(inc.event_ids)
            
        uncorrelated = [e.event_id for e in eligible_events if e.event_id not in correlated_event_ids]
        
        metrics.duration_ms = (time.time() - start_time) * 1000

        return DetectionResult(
            signals=deduped_signals,
            incidents=incidents,
            suppressed_signals=suppressed_signals,
            uncorrelated_event_ids=uncorrelated,
            metrics=metrics,
            warnings=[]
        )

    def _deduplicate_signals(self, signals: List[DetectionSignal]) -> List[DetectionSignal]:
        # Map source to signals
        source_signals = defaultdict(list)
        for s in signals:
            source_signals[s.primary_entity].append(s)
            
        final_signals = []
        
        for src, sigs in source_signals.items():
            # 1. Merge overlapping signals from the SAME rule (e.g. continuous sliding window matches)
            merged_by_rule = []
            sigs_by_rule = defaultdict(list)
            for s in sigs:
                sigs_by_rule[s.rule_id].append(s)
                
            for rule_id, rule_sigs in sigs_by_rule.items():
                # Sort by time
                rule_sigs.sort(key=lambda x: x.first_seen)
                
                merged_list: List[DetectionSignal] = []
                for current_sig in rule_sigs:
                    if not merged_list:
                        merged_list.append(current_sig)
                        continue
                        
                    prev_sig = merged_list[-1]
                    # Check overlap using event_ids
                    current_events = set(current_sig.event_ids)
                    prev_events = set(prev_sig.event_ids)
                    
                    intersection = current_events.intersection(prev_events)
                    union = current_events.union(prev_events)
                    
                    if intersection and (current_sig.first_seen - prev_sig.last_seen).total_seconds() <= self.settings.INCIDENT_MERGE_WINDOW_SECONDS:
                        # Merge current_sig into prev_sig
                        prev_sig.event_ids = sorted(list(union))
                        prev_sig.last_seen = max(prev_sig.last_seen, current_sig.last_seen)
                        # Merge target entities
                        prev_sig.target_entities = sorted(list(set(prev_sig.target_entities + current_sig.target_entities)))
                        # Merge evidence (deduping)
                        seen_ev = {e.event_id for e in prev_sig.evidence}
                        for ev in current_sig.evidence:
                            if ev.event_id not in seen_ev:
                                prev_sig.evidence.append(ev)
                                seen_ev.add(ev.event_id)
                        # Re-calculate signal_id to reflect union
                        from agent.detection.models import generate_signal_id
                        # Use first target entity as correlation_key for ID generation to keep it simple
                        corr_key = f"target_{prev_sig.target_entities[0]}" if prev_sig.target_entities else "multiple"
                        prev_sig.signal_id = generate_signal_id(
                            prev_sig.rule_id, prev_sig.rule_version, prev_sig.primary_entity, 
                            corr_key, prev_sig.first_seen, prev_sig.event_ids
                        )
                    else:
                        merged_list.append(current_sig)
                
                merged_by_rule.extend(merged_list)
                
            # 2. Precedence: Specific Service Probe > Generic Horizontal Scan
            probes = [s for s in merged_by_rule if "probe" in s.rule_id.lower()]
            scans = [s for s in merged_by_rule if "horizontal" in s.rule_id.lower()]
            others = [s for s in merged_by_rule if s not in probes and s not in scans]
            
            kept_scans = []
            for scan in scans:
                absorbed = False
                scan_events = set(scan.event_ids)
                for probe in probes:
                    probe_events = set(probe.event_ids)
                    if scan_events.intersection(probe_events) and abs((scan.first_seen - probe.first_seen).total_seconds()) < self.settings.INCIDENT_MERGE_WINDOW_SECONDS:
                        absorbed = True
                        break
                if not absorbed:
                    kept_scans.append(scan)
                    
            final_signals.extend(probes + kept_scans + others)
            
        return final_signals

    def _correlate_incidents(self, signals: List[DetectionSignal], context_events: List[CanonicalLogEvent]) -> List[IncidentBundle]:
        if not signals:
            return []
            
        # Group by primary entity and time window
        groups = defaultdict(list)
        for s in signals:
            # We use first_seen quantized to INCIDENT_MERGE_WINDOW_SECONDS for bucket grouping
            bucket = int(s.first_seen.timestamp()) // self.settings.INCIDENT_MERGE_WINDOW_SECONDS
            key = (s.primary_entity, s.signal_family, bucket)
            groups[key].append(s)
            
        incidents = []
        for key, sigs in groups.items():
            entity, family, bucket = key
            
            all_event_ids = set()
            all_target_entities = set()
            all_evidence: List[Any] = []
            all_mitre: Set[str] = set()
            all_signal_ids = []
            
            first_seen = sigs[0].first_seen
            last_seen = sigs[0].last_seen
            
            for s in sigs:
                all_event_ids.update(s.event_ids)
                all_target_entities.update(s.target_entities)
                all_signal_ids.append(s.signal_id)
                all_mitre.update(s.mitre_techniques)
                # Keep up to 10 evidence items per merged incident to avoid bloat
                if len(all_evidence) < 10:
                    for ev in s.evidence:
                        if len(all_evidence) < 10 and ev.event_id not in [e.event_id for e in all_evidence]:
                            all_evidence.append(ev)
                if s.first_seen < first_seen:
                    first_seen = s.first_seen
                if s.last_seen > last_seen:
                    last_seen = s.last_seen
                
            sorted_event_ids = sorted(list(all_event_ids))
            
            # Find context events (up to MAX_CONTEXT_EVENTS_PER_INCIDENT)
            context_ids: List[str] = []
            seen_context_ids: Set[str] = set()
            if context_events:
                # Basic context matching: same source IP, close in time, and not
                # already incident evidence. The explicit set also protects
                # against duplicate context input without expanding the bound.
                start_window = first_seen.timestamp() - self.settings.INCIDENT_MERGE_WINDOW_SECONDS
                end_window = last_seen.timestamp() + self.settings.INCIDENT_MERGE_WINDOW_SECONDS
                
                for ce in context_events:
                    if len(context_ids) >= self.settings.MAX_CONTEXT_EVENTS_PER_INCIDENT:
                        break
                    if ce.event_id in all_event_ids or ce.event_id in seen_context_ids:
                        continue
                    if ce.src_ip == entity and ce.timestamp:
                        ts = ce.timestamp.timestamp()
                        if start_window <= ts <= end_window:
                            context_ids.append(ce.event_id)
                            seen_context_ids.add(ce.event_id)
            
            incident_type = sigs[0].signal_type if len(set(s.signal_type for s in sigs)) == 1 else f"multiple_{family}"
            merge_key = f"{family}_{bucket}"
            
            # Severity and confidence
            severity = calculate_incident_severity(sigs, entity, self.settings)
            confidence = calculate_incident_confidence(sigs)
            
            inc_id = generate_incident_id(family, incident_type, entity, merge_key, first_seen)
            
            inc = IncidentBundle(
                incident_id=inc_id,
                incident_type=incident_type,
                incident_family=family,
                title=f"Detected {incident_type} from {entity}",
                severity=severity,
                confidence=confidence,
                first_seen=first_seen,
                last_seen=last_seen,
                primary_entity=entity,
                target_entities=sorted(list(all_target_entities)),
                signal_ids=sorted(list(set(all_signal_ids))),
                event_ids=sorted_event_ids,
                context_event_ids=context_ids,
                evidence=all_evidence,
                metrics={"total_events": len(all_event_ids), "distinct_targets": len(all_target_entities)},
                mitre_techniques=sorted(list(all_mitre)),
                merge_key=merge_key
            )
            incidents.append(inc)
            
        return sorted(incidents, key=lambda x: x.first_seen)
