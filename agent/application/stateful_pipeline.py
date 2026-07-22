"""Phase 6E.4: final canonical incident hydration for production routing.

After the stateful resolver has persisted the final canonical incidents,
routing and triage must operate on the complete persisted canonical state -
all attached signals (historical and current), all incident and bounded
context events, and bounded reconstructed evidence - not on the partial
incoming batch-local IncidentBundle. This module provides one focused,
read-only hydration function that produces exactly that.

It performs no writes, no provider calls, no unbounded table scans (every
lookup is by primary key over the incident's own bounded association rows),
and never surfaces raw records or parser_metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, Sequence

from agent.application.stateful_correlation_service import (
    _EVIDENCE_RECONSTRUCTION_LIMIT,
    StatefulIncidentCorrelationService,
)
from agent.detection.models import DetectionSignal, IncidentBundle
from agent.persistence.mappers import DataMapper
from agent.persistence.orm_models import Incident
from agent.persistence.unit_of_work import UnitOfWork
from agent.schema import CanonicalLogEvent


@dataclass(frozen=True)
class HydratedCanonicalIncident:
    """The complete persisted canonical incident plus current-job provenance.

    - `bundle` is the final canonical IncidentBundle (canonical incident_id,
      primary signal, absorbed signals, union of targets/MITRE, first/last
      seen, severity/confidence, stateful metrics), carrying bounded
      reconstructed evidence.
    - `event_map` / `signal_map` cover every incident and context event and
      every attached signal (historical and current), so routing sees the
      complete promoted identity.
    - `current_job_signal_ids` / `current_job_event_ids` keep this job's
      provenance separately identifiable from historical associations.
    """

    bundle: IncidentBundle
    event_map: Dict[str, CanonicalLogEvent]
    signal_map: Dict[str, DetectionSignal]
    resolve_status: str
    correlation_key: Optional[str]
    generation: Optional[int]
    material_changes: tuple[str, ...]
    current_job_signal_ids: tuple[str, ...] = field(default_factory=tuple)
    current_job_event_ids: tuple[str, ...] = field(default_factory=tuple)


def hydrate_canonical_incident(
    uow: UnitOfWork,
    incident_row: Incident,
    *,
    resolve_status: str,
    correlation_key: Optional[str] = None,
    generation: Optional[int] = None,
    material_changes: Sequence[str] = (),
    current_job_signal_ids: Sequence[str] = (),
    current_job_event_ids: Sequence[str] = (),
    evidence_limit: int = _EVIDENCE_RECONSTRUCTION_LIMIT,
) -> HydratedCanonicalIncident:
    """Hydrate the complete persisted canonical incident for routing/triage.

    Deterministic and duplicate-free: association rows carry a unique
    (incident_id, event_id)/(incident_id, signal_id) constraint, event and
    context IDs are kept disjoint by the merge layer, and evidence is bounded
    and reconstructed from safe structured fields only.
    """
    bundle = DataMapper.orm_to_domain_incident(incident_row)

    # Bounded evidence rebuilt from persisted canonical events (the incident
    # row has no evidence column). Reuses the resolver's safe reconstruction:
    # structured fields and the sanitized excerpt only - never raw records.
    evidence = StatefulIncidentCorrelationService._reconstruct_canonical_evidence(
        uow, incident_row, limit=evidence_limit
    )
    bundle = bundle.model_copy(update={"evidence": evidence})

    event_map: Dict[str, CanonicalLogEvent] = {}
    for assoc in incident_row.events:
        event_id = str(assoc.event_id)
        if event_id in event_map:
            continue
        orm_event = uow.canonical_events.get(event_id)
        if orm_event is not None:
            event_map[event_id] = DataMapper.orm_to_domain_event(orm_event)

    signal_map: Dict[str, DetectionSignal] = {}
    for assoc in incident_row.signals:
        signal_id = str(assoc.signal_id)
        if signal_id in signal_map:
            continue
        orm_signal = uow.detection_signals.get(signal_id)
        if orm_signal is not None:
            signal_map[signal_id] = DataMapper.orm_to_domain_signal(orm_signal)

    return HydratedCanonicalIncident(
        bundle=bundle,
        event_map=event_map,
        signal_map=signal_map,
        resolve_status=resolve_status,
        correlation_key=correlation_key,
        generation=generation,
        material_changes=tuple(material_changes),
        current_job_signal_ids=tuple(sorted(set(current_job_signal_ids))),
        current_job_event_ids=tuple(sorted(set(current_job_event_ids))),
    )
