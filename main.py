import json
import os
import argparse
from typing import Optional
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from agent.graph import app
from agent.ingestion.pipeline import IngestionPipeline
from agent.filtering import EventFilter
from agent.models import IncidentState

console = Console()

def run_graph_from_state(initial_state: IncidentState):
    try:
        final_state = app.invoke(initial_state)
        
        console.print(f"\n[bold cyan]--- FINAL STATE ({initial_state.get('incident_id', 'unknown')}) ---[/bold cyan]")
        console.print(f"[bold]Verdict:[/bold] {final_state.get('triage_verdict')}")
        console.print(f"[bold]Incident Type:[/bold] {final_state.get('incident_type')}")
        console.print(f"[bold]Severity:[/bold] {final_state.get('severity')}")
        console.print(f"[bold]Iterations:[/bold] {final_state.get('iteration_count')}")
        
        if final_state.get('final_report'):
            console.print("\n")
            console.print(Panel(Markdown(final_state['final_report']), title="[bold green]GENERATED REPORT[/bold green]", border_style="green"))
        else:
            console.print("\n[yellow](No report generated)[/yellow]")
            
        return final_state
    except Exception as e:
        console.print(f"\n[bold red][ERROR] An error occurred while processing {initial_state.get('incident_id', 'unknown')}: {e}[/bold red]")
        import traceback
        traceback.print_exc()
        return None

def run_graph_from_incident(incident, event_map: dict, signal_map: Optional[dict] = None) -> IncidentState:
    signal_map = signal_map or {}
    
    incident_id = incident.incident_id if hasattr(incident, 'incident_id') else incident.get("incident_id")
    event_ids = incident.event_ids if hasattr(incident, 'event_ids') else incident.get("event_ids", [])
    signal_ids = incident.signal_ids if hasattr(incident, 'signal_ids') else incident.get("signal_ids", [])
    evidence_list = incident.evidence if hasattr(incident, 'evidence') else incident.get("evidence", [])
    
    canonical_events = []
    for eid in event_ids:
        if eid in event_map:
            canonical_events.append(event_map[eid])
            
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
        
    return {
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

def analyze_file(file_path: str):
    console.print(f"[bold blue]Starting File Analysis: {file_path}[/bold blue]")
    
    from agent.detection.engine import DetectionEngine
    
    ingest = IngestionPipeline()
    filter_engine = EventFilter()
    detection_engine = DetectionEngine()
    
    # 1. Ingestion
    ingest_result = ingest.ingest_file(file_path)
    console.print(f"Ingested {ingest_result.metrics.total_records} lines. Parsed: {ingest_result.metrics.parsed_records}. Failed: {ingest_result.metrics.failed_records}. Unsupported: {ingest_result.metrics.unsupported_records}.")
    
    # 2. Filtering
    filter_result = filter_engine.filter_events(ingest_result.events)
    console.print(f"Filtering complete. Noise: {filter_result.metrics['noise']}. Context: {filter_result.metrics['context']}. Candidates: {filter_result.metrics['candidates']}.")
    
    # 3. Detection & Correlation (Phase 3 Engine)
    det_result = detection_engine.analyze(filter_result.candidates, filter_result.context)
    console.print(f"Detection engine generated {det_result.metrics.incident_count} incidents from {det_result.metrics.signal_count} signals.")
    
    event_map = {e.event_id: e.model_dump(mode="json") for e in ingest_result.events if e.event_id}
    signal_map = {s.signal_id: s for s in det_result.signals}
    
    # 4. Graph Invocation
    for inc in det_result.incidents:
        initial_state = run_graph_from_incident(inc, event_map, signal_map)
        run_graph_from_state(initial_state)
        print("\n" + "="*50 + "\n")

def run_mock_test():
    run_all = os.environ.get("RUN_ALL", "false").lower() == "true"
    
    try:
        with open("data/samples/mock_incidents.json", "r") as f:
            MOCK_DATA = json.load(f)
    except FileNotFoundError:
        console.print("[bold red]data/samples/mock_incidents.json not found.[/bold red]")
        return
        
    for item in MOCK_DATA:
        if "raw_logs" in item:
            incident_id = item.get("incident_id", "MOCK-INCIDENT")
            desc = item.get("description", "Mock Incident")
            raw_logs = item["raw_logs"]
        else:
            incident_id = item.get("incident_id", "MOCK-INCIDENT")
            desc = "Single Log Mock Incident"
            raw_logs = [item]

        console.rule(f"[bold blue]Processing {incident_id}: {desc}[/bold blue]")
        
        for i, log in enumerate(raw_logs):
            if "event_id" not in log:
                log["event_id"] = f"{incident_id}-E{i+1:03d}"
                
        # Convert mock logs to canonical format and state
        from agent.ingestion.pipeline import IngestionPipeline
        c_events = IngestionPipeline().ingest_records(raw_logs, source_name="mock_incidents").events
        event_map = {e.event_id: e.model_dump(mode="json") for e in c_events}
        
        class FakeIncident:
            def __init__(self, incident_id, events):
                self.incident_id = incident_id
                self.event_ids = [e.event_id for e in events]
                self.signal_ids = []
                self.evidence = [
                    {
                        "event_id": e.event_id,
                        "quote": e.raw_message or "",
                        "original_fields": e.original_log
                    } for e in events
                ]
                
        inc = FakeIncident(incident_id, c_events)
        initial_state = run_graph_from_incident(inc, event_map, {})
        run_graph_from_state(initial_state)
            
        if not run_all:
            print("\n[INFO] Breaking early after 1 incident. Set RUN_ALL=true in .env to run all.")
            break
        else:
            import time
            time.sleep(4)

def ingest_file_only(file_path: str):
    console.print(f"[bold blue]Starting File Ingestion: {file_path}[/bold blue]")
    
    ingest = IngestionPipeline()
    result = ingest.ingest_file(file_path)
    
    console.print("\n[bold cyan]--- INGESTION SUMMARY ---[/bold cyan]")
    console.print(f"Source: {result.source_name}")
    console.print(f"Format: {result.input_format.value}")
    console.print(f"Duration: {result.metrics.duration_ms} ms")
    console.print(f"Total records: {result.metrics.total_records}")
    console.print(f"Parsed: {result.metrics.parsed_records}")
    console.print(f"Failed: {result.metrics.failed_records}")
    console.print(f"Unsupported: {result.metrics.unsupported_records}")
    console.print(f"Invalid: {result.metrics.semantically_invalid_records}")
    
    if result.metrics.parser_counts:
        console.print("\n[bold]Parsers used:[/bold]")
        for k, v in result.metrics.parser_counts.items():
            console.print(f"  - {k}: {v}")
            
    if result.metrics.error_counts:
        console.print("\n[bold]Errors:[/bold]")
        for k, v in result.metrics.error_counts.items():
            console.print(f"  - {k}: {v}")
            
    if result.warnings:
        console.print("\n[bold yellow]Warnings:[/bold yellow]")
        for w in result.warnings:
            console.print(f"  - {w}")

def detect_file_only(file_path: str):
    console.print(f"[bold blue]Starting File Detection: {file_path}[/bold blue]")
    
    ingest = IngestionPipeline()
    filter_engine = EventFilter()
    result = ingest.ingest_file(file_path)
    filter_result = filter_engine.filter_events(result.events)
    
    from agent.detection.engine import DetectionEngine
    engine = DetectionEngine()
    
    console.print("[bold blue]Running Detection Engine...[/bold blue]")
    det_result = engine.analyze(filter_result.candidates, filter_result.context)
    
    console.print("\n[bold cyan]--- DETECTION SUMMARY ---[/bold cyan]")
    console.print(f"Total Canonical Events: {det_result.metrics.total_events}")
    console.print(f"Eligible Events: {det_result.metrics.eligible_events}")
    console.print(f"Skipped Events: {det_result.metrics.skipped_events}")
    console.print(f"Signal Count: {det_result.metrics.signal_count}")
    console.print(f"Suppressed Signal Count: {det_result.metrics.suppressed_signal_count}")
    console.print(f"Incident Count: {det_result.metrics.incident_count}")
    console.print(f"Duplicate Signal Count: {det_result.metrics.duplicate_signal_count}")
    console.print(f"Duration: {det_result.metrics.duration_ms:.2f} ms")
    
    if det_result.incidents:
        console.print("\n[bold]Generated Incidents (Sample of max 3):[/bold]")
        for inc in det_result.incidents[:3]:
            console.print(f"  - {inc.incident_id} ({inc.incident_type}): {inc.title}")
            console.print(f"    Severity: {inc.severity}, Confidence: {inc.confidence:.2f}")
            console.print(f"    Events: {len(inc.event_ids)}, Signals: {len(inc.signal_ids)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOC Triage Assistant CLI")
    parser.add_argument("--file", type=str, help="Path to JSONL log file to analyze end-to-end")
    parser.add_argument("--ingest-file", type=str, help="Path to file to only run ingestion and print summary")
    parser.add_argument("--detect-file", type=str, help="Path to file to only run deterministic detection and print summary")
    args = parser.parse_args()
    
    if args.detect_file:
        detect_file_only(args.detect_file)
    elif args.ingest_file:
        ingest_file_only(args.ingest_file)
    elif args.file:
        analyze_file(args.file)
    else:
        run_mock_test()
