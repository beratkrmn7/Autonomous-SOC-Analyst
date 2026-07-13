import json
import os
import argparse
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from agent.ingestion.pipeline import IngestionPipeline

console = Console()

# Duplicated logic removed. We now use AnalysisService.

def analyze_file(file_path: str):
    console.print(f"[bold blue]Starting File Analysis: {file_path}[/bold blue]")
    from agent.application.analysis_service import AnalysisService
    
    svc = AnalysisService()
    result = svc.analyze_file(file_path, run_triage=True, source_name="cli")
    
    for inc_state in result.incidents:
        console.print(f"\n[bold cyan]--- FINAL STATE ({inc_state.get('incident_id', 'unknown')}) ---[/bold cyan]")
        console.print(f"[bold]Verdict:[/bold] {inc_state.get('triage_verdict')}")
        console.print(f"[bold]Incident Type:[/bold] {inc_state.get('incident_type')}")
        console.print(f"[bold]Severity:[/bold] {inc_state.get('severity')}")
        console.print(f"[bold]Iterations:[/bold] {inc_state.get('iteration_count')}")
        
        if inc_state.get('final_report'):
            console.print("\n")
            console.print(Panel(Markdown(inc_state['final_report']), title="[bold green]GENERATED REPORT[/bold green]", border_style="green"))
        else:
            console.print("\n[yellow](No report generated)[/yellow]")
            
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
        from agent.application.analysis_service import AnalysisService
        from agent.ingestion.pipeline import IngestionPipeline
        from rich.panel import Panel
        from rich.markdown import Markdown
        
        c_events = IngestionPipeline().ingest_records(raw_logs, source_name="mock_incidents").events
        
        svc = AnalysisService()
        result = svc.analyze_events(c_events, run_triage=True)
        
        for inc_state in result.incidents:
            console.print(f"\n[bold cyan]--- FINAL STATE ({inc_state.get('incident_id', 'unknown')}) ---[/bold cyan]")
            console.print(f"[bold]Verdict:[/bold] {inc_state.get('triage_verdict')}")
            console.print(f"[bold]Incident Type:[/bold] {inc_state.get('incident_type')}")
            console.print(f"[bold]Severity:[/bold] {inc_state.get('severity')}")
            console.print(f"[bold]Iterations:[/bold] {inc_state.get('iteration_count')}")
            
            if inc_state.get('final_report'):
                console.print("\n")
                console.print(Panel(Markdown(inc_state['final_report']), title="[bold green]GENERATED REPORT[/bold green]", border_style="green"))
            else:
                console.print("\n[yellow](No report generated)[/yellow]")
            
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
    
    from agent.application.analysis_service import AnalysisService
    svc = AnalysisService()
    
    console.print("[bold blue]Running Detection Engine...[/bold blue]")
    result = svc.analyze_file(file_path, run_triage=False, source_name="cli_detect")
    det_result = result.detection_result
    
    console.print("\n[bold cyan]--- DETECTION SUMMARY ---[/bold cyan]")
    if det_result:
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
