import time
from datetime import datetime
from typing import List, Optional, Set
import logging
from collections import defaultdict
from types import MappingProxyType

from agent.schema import CanonicalLogEvent
from agent.detection.models import (
    DetectionSignal, DetectionResult, DetectionMetrics,
)
from agent.detection.config import DetectionSettings, settings as default_settings
from agent.detection.registry import RuleRegistry, default_registry
from agent.detection.detectors.base import DetectionContext
from agent.detection.contracts import (
    RuleContractError,
    select_rule_events,
    validate_signal_contract,
)
from agent.detection.incident_correlation import build_correlated_incidents
from agent.detection.suppression import SuppressionPolicy

logger = logging.getLogger(__name__)


def _bounded_identifier(value: str, max_length: int = 80) -> str:
    safe_value = "".join(
        character if character.isalnum() or character in "-_.:" else "_"
        for character in value
    )
    return safe_value[:max_length] or "unknown"

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
            rule_events = select_rule_events(eligible_events, rule.metadata)
            if not rule_events:
                continue
            try:
                signals = rule.evaluate(rule_events, context)
                input_event_ids = {event.event_id for event in rule_events}
                for signal in signals:
                    try:
                        validate_signal_contract(signal, rule, input_event_ids)
                    except RuleContractError as ex:
                        warning = (
                            f"Rule {rule.rule_id} produced invalid signal "
                            f"{_bounded_identifier(signal.signal_id)}: {ex}"
                        )
                        warnings.append(warning)
                        logger.warning(warning)
                        continue
                    all_signals.append(signal)
            except Exception as ex:
                warning = f"Rule {rule.rule_id} failed: {type(ex).__name__}"
                warnings.append(warning)
                logger.warning(warning)
                
        metrics.signal_count = len(all_signals)

        # 3. Suppression
        active_signals = []
        suppressed_signals = []
        suppression_event_lookup = MappingProxyType(
            {event.event_id: event for event in eligible_events}
        )
        for sig in all_signals:
            suppression_reason = self.suppression_policy.is_suppressed(
                sig, suppression_event_lookup
            )
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

        # 5. Incident Correlation and Merging (Phase 6E.2 - Correlation V2)
        incidents, merge_count = build_correlated_incidents(
            deduped_signals, context_events or [], eligible_events, self.settings
        )
        metrics.incident_count = len(incidents)
        metrics.merge_count = merge_count
        
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
            warnings=warnings
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

            # Cross-rule precedence (for example a specific service probe
            # over a generic horizontal scan) is no longer resolved by
            # deleting a signal here. Every same-rule-deduplicated signal
            # stays in DetectionResult.signals; incident_correlation decides
            # which cross-rule signals belong to the same incident and which
            # one defines its identity.
            final_signals.extend(merged_by_rule)

        return final_signals
