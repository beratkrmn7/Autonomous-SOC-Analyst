from typing import Optional, List, Dict, Any, cast
from agent.persistence.unit_of_work import UnitOfWork
from agent.application.models import AnalysisResult
from agent.ingestion.pipeline import IngestionPipeline
from agent.ingestion.models import CanonicalLogEvent
from agent.filtering import EventFilter
from agent.detection.engine import DetectionEngine
from agent.models import IncidentState
from agent.graph import app
import traceback
from sqlalchemy.sql import func

class AnalysisService:
    def __init__(self, uow: Optional[Any] = None):
        self.uow = uow
        self.ingest = IngestionPipeline()
        self.filter_engine = EventFilter()
        self.detection_engine = DetectionEngine()

    def _persist_analysis(self, result: AnalysisResult, run_triage: bool):
        from agent.persistence.mappers import DataMapper
        from agent.persistence.lifecycle import IncidentLifecycle
        from agent.persistence.orm_models import IngestionJob, TriageRun, EvidenceItem, Report
        import uuid
        
        with cast(UnitOfWork, self.uow) as uow: # type: ignore
            # 1. Ingestion Job
            # Check if job_id is already assigned (from idempotency flow)
            job_id = result.job_id
            
            if result.ingestion_result and not job_id:
                job_id = str(uuid.uuid4())
                job = IngestionJob(
                    id=job_id,
                    idempotency_key=getattr(result, 'idempotency_key', None),
                    file_sha256=getattr(result, 'file_sha256', None),
                    pipeline_version=getattr(result, 'pipeline_version', None),
                    analysis_mode=getattr(result, 'analysis_mode', None),
                    source_name=result.ingestion_result.source_name,
                    input_format=result.ingestion_result.input_format.value,
                    total_records=result.ingestion_result.metrics.total_records,
                    parsed_records=result.ingestion_result.metrics.parsed_records,
                    failed_records=result.ingestion_result.metrics.failed_records,
                    unsupported_records=result.ingestion_result.metrics.unsupported_records,
                    duration_ms=result.ingestion_result.metrics.duration_ms,
                    parser_counts=result.ingestion_result.metrics.parser_counts,
                    error_counts=result.ingestion_result.metrics.error_counts,
                    status="completed",
                    completed_at=func.now()
                )
                uow.ingestion_jobs.add(job)
            elif job_id:
                # Update existing job
                job = uow.session.query(IngestionJob).get(job_id)
                if job and result.ingestion_result:
                    job.status = "completed"
                    job.completed_at = func.now()
                    job.total_records = result.ingestion_result.metrics.total_records
                    job.parsed_records = result.ingestion_result.metrics.parsed_records
                    job.failed_records = result.ingestion_result.metrics.failed_records
                    job.unsupported_records = result.ingestion_result.metrics.unsupported_records
                    job.duration_ms = result.ingestion_result.metrics.duration_ms
                    job.parser_counts = result.ingestion_result.metrics.parser_counts
                    job.error_counts = result.ingestion_result.metrics.error_counts
            
            # 2. Canonical Events
            for event in result.event_map.values():
                orm_event = DataMapper.domain_event_to_orm(event)
                existing_event = uow.canonical_events.get(orm_event.event_id)
                if not existing_event:
                    uow.canonical_events.add(orm_event)
                    job.events.append(orm_event)
                else:
                    if existing_event not in job.events:
                        job.events.append(existing_event)
                
            # 3. Detection Signals
            for signal in result.detection_result.signals:
                orm_signal = DataMapper.domain_signal_to_orm(signal)
                existing_signal = uow.detection_signals.get(orm_signal.signal_id)
                if not existing_signal:
                    uow.detection_signals.add(orm_signal)
                    job.signals.append(orm_signal)
                else:
                    if existing_signal not in job.signals:
                        job.signals.append(existing_signal)
                
            # 4. Incidents
            for inc in result.detection_result.incidents:
                orm_inc = DataMapper.domain_incident_to_orm(inc)
                
                # Check idempotency/existing
                existing = uow.incidents.get(orm_inc.incident_id)
                if not existing:
                    uow.incidents.add(orm_inc)
                    job.incidents.append(orm_inc)
                    IncidentLifecycle.transition(orm_inc, "new", actor="detection_engine")
                else:
                    if existing not in job.incidents:
                        job.incidents.append(existing)
            
            uow.session.flush() # Flush to get incident IDs ready for triage references
            
            # 5, 6, 7. Triage Run, Evidence, Report
            if run_triage:
                for inc_state in result.incidents:
                    incident_id = inc_state.get("incident_id")
                    if not incident_id:
                        continue
                        
                    orm_inc = uow.incidents.get(incident_id)
                    if orm_inc:
                        verdict = inc_state.get("triage_verdict")
                        new_status = "triaged" if verdict else "investigating"
                        IncidentLifecycle.transition(orm_inc, new_status, actor="triage_agent", details={"verdict": verdict})
                        
                        run = TriageRun(
                            triage_run_id=str(uuid.uuid4()),
                            job_id=job.id,
                            incident_id=incident_id,
                            verdict=verdict,
                            severity=inc_state.get("severity"),
                            confidence_score=inc_state.get("confidence_score"),
                            incident_type=inc_state.get("incident_type"),
                            iteration_count=inc_state.get("iteration_count", 0),
                            status="completed" if verdict else "failed"
                        )
                        uow.triage_runs.add(run)
                        uow.session.flush()
                        
                        # Process Evidence from safe_triage_input which has full candidate records
                        triage_input = inc_state.get("safe_triage_input", {})
                        candidates = triage_input.get("candidate_evidence", [])
                        
                        valid_map = {e["evidence_id"]: e for e in inc_state.get("validated_evidence", [])}
                        reject_map = {e["evidence_id"]: e for e in inc_state.get("rejected_evidence", [])}
                        
                        for cand in candidates:
                            ev_id = cand.get("evidence_id")
                            status = "candidate"
                            rej_reason = None
                            
                            if ev_id in valid_map:
                                status = "validated"
                            elif ev_id in reject_map:
                                status = "rejected"
                                rej_reason = reject_map[ev_id].get("rejection_reason")
                                
                            evidence = EvidenceItem(
                                evidence_id=ev_id or str(uuid.uuid4()),
                                job_id=job.id,
                                incident_id=incident_id,
                                triage_run_id=run.id,
                                event_id=cand.get("event_id"),
                                quote=cand.get("quote"),
                                reason=cand.get("reason"),
                                source=cand.get("source"),
                                validation_status=status,
                                rejection_reason=rej_reason
                            )
                            uow.evidence.add(evidence)
                            
                        if inc_state.get("final_report"):
                            report = Report(
                                report_id=str(uuid.uuid4()),
                                job_id=job.id,
                                incident_id=incident_id,
                                triage_run_id=run.id,
                                content=inc_state.get("final_report"),
                                entities=inc_state.get("entities", {}),
                                recommended_actions=inc_state.get("recommended_actions", []),
                                mitre_techniques=inc_state.get("mitre_techniques", [])
                            )
                            uow.reports.add(report)
                            
            # 8. Commit (happens on context exit)

    def analyze_file(self, file_path: str, *, run_triage: bool = True, source_name: Optional[str] = None, file_sha256: Optional[str] = None, idempotency_key: Optional[str] = None, pipeline_version: Optional[str] = None, analysis_mode: Optional[str] = None) -> AnalysisResult:
        # 1. Check Idempotency if key is provided
        from agent.persistence.orm_models import IngestionJob
        import uuid
        from sqlalchemy.exc import IntegrityError
        from agent.application.errors import DuplicateAnalysisError
        from sqlalchemy.sql import func
        from agent.persistence.mappers import DataMapper
        
        job_id = None
        
        if self.uow and idempotency_key:
            with cast(UnitOfWork, self.uow) as uow: # type: ignore
                job = uow.session.query(IngestionJob).filter_by(idempotency_key=idempotency_key).first()
                if job:
                    if job.status == "processing":
                        raise DuplicateAnalysisError(status="processing")
                    elif job.status == "failed":
                        # Retry
                        job.status = "processing"
                        job.reused_count += 1
                        job.last_requested_at = func.now()
                        uow.session.commit()
                        job_id = job.id
                    elif job.status == "completed":
                        # Hydrate results from DB
                        job.reused_count += 1
                        job.last_requested_at = func.now()
                        uow.session.commit()
                        
                        # Build AnalysisResult from DB
                        result = AnalysisResult(
                            source_name=job.source_name,
                            job_id=job.id,
                            reused=True,
                            idempotency_status="reused_completed_result",
                            event_map={},
                            signal_map={},
                            incidents=[]
                        )
                        # We fully reconstruct everything from the DB
                        from agent.detection.models import DetectionResult
                        from agent.detection.models import DetectionMetrics
                        
                        # Reconstruct Events
                        for ev in job.events:
                            domain_ev = DataMapper.orm_to_domain_event(ev)
                            result.event_map[domain_ev.event_id] = domain_ev
                            
                        # Reconstruct Signals
                        result.detection_result = DetectionResult(
                            signals=[], 
                            incidents=[], 
                            suppressed_signals=[], 
                            uncorrelated_event_ids=[], 
                            warnings=[], 
                            metrics=DetectionMetrics(
                                signal_count=len(job.signals), 
                                duration_ms=0.0
                            )
                        )
                        for sig in job.signals:
                            domain_sig = DataMapper.orm_to_domain_signal(sig)
                            result.detection_result.signals.append(domain_sig)
                            result.signal_map[domain_sig.signal_id] = domain_sig
                            
                        # Reconstruct Incidents
                        for inc in job.incidents:
                            domain_inc = DataMapper.orm_to_domain_incident(inc)
                            result.detection_result.incidents.append(domain_inc)
                            
                            # Use the same exact builder logic to hydrate state
                            state = self._build_initial_state(domain_inc, result.event_map, result.signal_map)
                            
                            triage_runs = [tr for tr in job.triage_runs if tr.incident_id == inc.incident_id]
                            if triage_runs:
                                last_run = sorted(triage_runs, key=lambda r: r.started_at, reverse=True)[0]
                                state["triage_verdict"] = last_run.verdict
                                state["incident_type"] = last_run.incident_type
                                state["severity"] = last_run.severity
                                state["confidence_score"] = last_run.confidence_score
                                state["iteration_count"] = last_run.iteration_count
                                
                                reports = [rp for rp in job.reports if rp.triage_run_id == last_run.id]
                                if reports:
                                    state["final_report"] = reports[0].content
                                    
                                # Hydrate Evidence
                                run_evidence = [ev for ev in job.evidence_items if ev.triage_run_id == last_run.id]
                                if run_evidence:
                                    state["validated_evidence"] = [{
                                        "event_id": ev.event_id,
                                        "quote": ev.quote,
                                        "reason": ev.reason,
                                        "source": ev.source
                                    } for ev in run_evidence]
                                    
                            result.incidents.append(state)
                            
                        return result
                else:
                    # Create placeholder processing job
                    job_id = str(uuid.uuid4())
                    job = IngestionJob(
                        id=job_id,
                        idempotency_key=idempotency_key,
                        file_sha256=file_sha256,
                        pipeline_version=pipeline_version,
                        analysis_mode=analysis_mode,
                        status="processing",
                        source_name=source_name or "api"
                    )
                    uow.ingestion_jobs.add(job)
                    try:
                        uow.session.commit()
                    except IntegrityError:
                        uow.session.rollback()
                        # Race condition lost, another thread inserted it
                        raise DuplicateAnalysisError(status="processing")

        # 2. Ingestion
        ingest_result = self.ingest.ingest_file(file_path)
        
        # 3. Process Events
        res = self._process_events(
            events=ingest_result.events,
            run_triage=run_triage,
            ingestion_result=ingest_result,
            source_name=source_name or ingest_result.source_name,
            job_id=job_id,
            file_sha256=file_sha256,
            idempotency_key=idempotency_key,
            pipeline_version=pipeline_version,
            analysis_mode=analysis_mode
        )
        return res

    def analyze_events(self, events: List[CanonicalLogEvent], *, run_triage: bool = True) -> AnalysisResult:
        return self._process_events(
            events=events,
            run_triage=run_triage,
            ingestion_result=None,
            source_name="api",
            job_id=None
        )

    def _process_events(self, events: List[CanonicalLogEvent], run_triage: bool, ingestion_result: Any, source_name: str, job_id: Optional[str] = None, file_sha256: Optional[str] = None, idempotency_key: Optional[str] = None, pipeline_version: Optional[str] = None, analysis_mode: Optional[str] = None) -> AnalysisResult:
        # 2. Filtering
        filter_result = self.filter_engine.filter_events(events)
        
        # 3. Detection
        det_result = self.detection_engine.analyze(filter_result.candidates, filter_result.context)
        
        event_map = {e.event_id: e for e in events if e.event_id}
        signal_map = {s.signal_id: s for s in det_result.signals}
        
        result = AnalysisResult(
            source_name=source_name,
            ingestion_result=ingestion_result,
            detection_result=det_result,
            event_map=event_map,
            signal_map=signal_map,
            incidents=[],
            job_id=job_id,
            file_sha256=file_sha256,
            idempotency_key=idempotency_key,
            pipeline_version=pipeline_version,
            analysis_mode=analysis_mode
        )
        
        # 4. Persistence setup (Optional Phase 5 integration point)
        # If we have a Unit Of Work, we can persist the canonical events, signals, and incidents here.
        # This will be done after triage, to ensure a single transaction.
        
        # 5. Graph Invocation (Triage)
        for inc in det_result.incidents:
            initial_state = self._build_initial_state(inc, event_map, signal_map)
            
            if run_triage:
                try:
                    final_state = app.invoke(initial_state)
                    result.incidents.append(final_state)
                except Exception as e:
                    print(f"Error during triage: {e}")
                    traceback.print_exc()
                    result.incidents.append(initial_state)
            else:
                result.incidents.append(initial_state)
                
        # 6. Persistence
        if self.uow:
            try:
                self._persist_analysis(result, run_triage)
            except Exception as e:
                # If we fail during persistence, mark the job as failed
                if getattr(result, "job_id", None):
                    with cast(UnitOfWork, self.uow) as uow: # type: ignore
                        from agent.persistence.orm_models import IngestionJob
                        job = uow.session.query(IngestionJob).get(result.job_id)
                        if job:
                            job.status = "failed"
                            # Determine machine-readable error code
                            if "IntegrityError" in str(type(e)):
                                job.error_code = "PERSISTENCE_INTEGRITY_ERROR"
                            else:
                                job.error_code = "INTERNAL_ANALYSIS_ERROR"
                            uow.session.commit()
                raise
                
        return result

    def _build_initial_state(self, incident: Any, event_map: Dict[str, CanonicalLogEvent], signal_map: Dict[str, Any]) -> IncidentState:
        # Reconstruct the logic that was duplicated in main.py and server.py
        if isinstance(incident, dict):
            incident_id = incident.get("incident_id")
            event_ids = incident.get("event_ids", [])
            signal_ids = incident.get("signal_ids", [])
            evidence_list = incident.get("evidence", [])
        else:
            incident_id = getattr(incident, 'incident_id', None)
            event_ids = getattr(incident, 'event_ids', [])
            signal_ids = getattr(incident, 'signal_ids', [])
            evidence_list = getattr(incident, 'evidence', [])
        
        canonical_events = []
        for eid in event_ids:
            if eid in event_map:
                canonical_events.append(event_map[eid].model_dump(mode="json"))
                
        detected_signals = []
        for sid in signal_ids:
            if sid in signal_map:
                sig = signal_map[sid]
                detected_signals.append({
                    "detector_name": getattr(sig, 'rule_name', 'Unknown'),
                    "status": "alert",
                    "message": f"{getattr(sig, 'rule_name', 'Unknown')} detected. Severity: {getattr(sig, 'severity', 'low')}",
                    "matched_event_ids": getattr(sig, 'event_ids', [])
                })
                
        candidate_evidence = []
        for ev in evidence_list:
            candidate_evidence.append({
                "event_id": getattr(ev, 'event_id', ev.get('event_id') if isinstance(ev, dict) else None),
                "quote": getattr(ev, 'quote', ev.get('quote') if isinstance(ev, dict) else ""),
                "reason": getattr(ev, 'reason', ev.get('reason') if isinstance(ev, dict) else ""),
                "source": getattr(ev, 'source', ev.get('source') if isinstance(ev, dict) else ""),
                "original_fields": getattr(ev, 'original_fields', ev.get('original_fields') if isinstance(ev, dict) else {}),
                "correlation_context": getattr(ev, 'correlation_context', ev.get('correlation_context') if isinstance(ev, dict) else {})
            })
            
        # Extract Phase 3 IncidentBundle fields to ensure lossless transport
        incident_bundle = None
        if hasattr(incident, 'model_dump'):
            incident_bundle = incident.model_dump(mode="json")
            
        return {
            "incident": incident_bundle, # Pass true incident bundle!
            "incident_id": incident_id,
            "canonical_events": canonical_events,
            "messages": [],
            "iteration_count": 0,
            "mitre_techniques": [],
            "candidate_evidence": candidate_evidence,
            "detected_signals": detected_signals,
            "search_history": [],
            "tool_results": [],
            "errors": [],
            "detection_engine_executed": True
        }
