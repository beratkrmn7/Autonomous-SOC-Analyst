import json
import os
import argparse
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from agent.ingestion.pipeline import IngestionPipeline
from agent.models import IncidentState

console = Console()

# Duplicated logic removed. We now use AnalysisService.

# Static full-mode scaffolding strings. Deterministic values - IDs, verdicts,
# severities, incident types, counts and ATT&CK identifiers - are never
# translated.
FULL_MODE_LABELS = {
    "en": {
        "routing_summary": "--- TRIAGE ROUTING SUMMARY ---",
        "batch_eligible": "Batch-enrichment eligible",
        "deterministic_reports": "Deterministic reports",
        "added_to_digest": "Added to digest",
        "stored_only": "Stored only",
        "provider_calls": "Provider calls",
        "digest": "Digest",
        "incidents": "incidents",
        "sources": "sources",
        "blocked_events": "blocked events",
        "distinct_targets": "distinct targets",
        "common_ports": "Common ports",
        "sources_label": "Sources",
        "final_state": "FINAL STATE",
        "route": "Route",
        "verdict": "Verdict",
        "incident_type": "Incident Type",
        "severity": "Severity",
        "iterations": "Iterations",
        "detection_confidence": "Detection confidence score",
        "evidence_strength": "Evidence strength",
        "why_it_matters": "Why it matters",
        "generated_report": "GENERATED REPORT",
        "digest_routed": "(Routed to digest; see routing summary)",
        "store_only": "(Stored only; no report generated)",
        "no_report": "(No report generated)",
        "analysis_summary": "--- ANALYSIS SUMMARY ---",
    },
    "tr": {
        "routing_summary": "--- TRİYAJ YÖNLENDİRME ÖZETİ ---",
        "batch_eligible": "Toplu zenginleştirmeye uygun",
        "deterministic_reports": "Deterministik raporlar",
        "added_to_digest": "Özete eklendi",
        "stored_only": "Yalnızca saklandı",
        "provider_calls": "Sağlayıcı çağrıları",
        "digest": "Özet",
        "incidents": "olay",
        "sources": "kaynak",
        "blocked_events": "engellenen olay",
        "distinct_targets": "farklı hedef",
        "common_ports": "Yaygın portlar",
        "sources_label": "Kaynaklar",
        "final_state": "NİHAİ DURUM",
        "route": "Yönlendirme",
        "verdict": "Karar",
        "incident_type": "Olay Türü",
        "severity": "Önem Derecesi",
        "iterations": "Yineleme",
        "detection_confidence": "Tespit güven puanı",
        "evidence_strength": "Kanıt gücü",
        "why_it_matters": "Neden önemli",
        "generated_report": "OLUŞTURULAN RAPOR",
        "digest_routed": "(Özete yönlendirildi; yönlendirme özetine bakın)",
        "store_only": "(Yalnızca saklandı; rapor oluşturulmadı)",
        "no_report": "(Rapor oluşturulmadı)",
        "analysis_summary": "--- ANALİZ ÖZETİ ---",
    },
}


def _print_routing_summary(result, lang: str = "en") -> None:
    metrics = result.routing_metrics
    if not metrics:
        return
    labels = FULL_MODE_LABELS.get(lang, FULL_MODE_LABELS["en"])
    console.print(f"\n[bold cyan]{labels['routing_summary']}[/bold cyan]")
    console.print(
        f"{labels['batch_eligible']}: {metrics.get('individual_triage_count', 0)}"
    )
    console.print(
        f"{labels['deterministic_reports']}: "
        f"{metrics.get('deterministic_report_count', 0)}"
    )
    console.print(
        f"{labels['added_to_digest']}: {metrics.get('digest_incident_count', 0)}"
    )
    console.print(f"{labels['stored_only']}: {metrics.get('store_only_count', 0)}")
    console.print(
        f"{labels['provider_calls']}: {metrics.get('provider_invocation_count', 0)}"
    )

    for digest in result.triage_digests:
        console.print(
            f"\n[bold]{labels['digest']} ({digest.get('incident_type')}):[/bold] "
            f"{digest.get('incident_count', 0)} {labels['incidents']}, "
            f"{digest.get('source_count', 0)} {labels['sources']}, "
            f"{digest.get('total_blocked_events', 0)} {labels['blocked_events']}, "
            f"{digest.get('distinct_target_count', 0)} {labels['distinct_targets']}"
        )
        console.print(f"  {labels['common_ports']}: {digest.get('common_ports', [])}")
        console.print(f"  {labels['sources_label']}: {digest.get('sources', [])}")
        console.print(f"  {digest.get('statement', '')}")


def _matching_enrichment(result, incident_id: str, lang: str):
    """The persisted enrichment text covering one incident, if any.

    An incident may be represented in the brief by itself or by a group, so
    the lookup goes through the selection's member incident IDs rather than
    assuming a one-to-one mapping.
    """
    selection = getattr(result, "brief_selection", None)
    enrichment = getattr(result, "brief_enrichment", None)
    if selection is None or enrichment is None:
        return None
    for item in selection.all_items:
        if incident_id in item.member_incident_ids:
            entry = enrichment.for_item(item.item_id)
            if entry is None:
                return None
            return (
                entry.explanation_tr if lang == "tr" else entry.explanation_en,
                list(
                    entry.recommended_actions_tr
                    if lang == "tr"
                    else entry.recommended_actions_en
                ),
            )
    return None


def _print_incident_state(
    inc_state: IncidentState, result=None, *, lang: str = "en"
) -> None:
    labels = FULL_MODE_LABELS.get(lang, FULL_MODE_LABELS["en"])
    incident_id = inc_state.get('incident_id', 'unknown')
    console.print(
        f"\n[bold cyan]--- {labels['final_state']} ({incident_id}) ---[/bold cyan]"
    )
    route = inc_state.get('triage_route', 'individual_triage')
    # Route, verdict, type and severity are deterministic values, printed as-is.
    console.print(f"[bold]{labels['route']}:[/bold] {route}")
    console.print(f"[bold]{labels['verdict']}:[/bold] {inc_state.get('triage_verdict')}")
    console.print(
        f"[bold]{labels['incident_type']}:[/bold] {inc_state.get('incident_type')}"
    )
    console.print(f"[bold]{labels['severity']}:[/bold] {inc_state.get('severity')}")
    console.print(
        f"[bold]{labels['iterations']}:[/bold] {inc_state.get('iteration_count')}"
    )
    detection_confidence = inc_state.get('detection_confidence')
    if detection_confidence is not None:
        console.print(
            f"[bold]{labels['detection_confidence']}:[/bold] {detection_confidence:.2f}"
        )
    if inc_state.get('evidence_strength'):
        console.print(
            f"[bold]{labels['evidence_strength']}:[/bold] "
            f"{inc_state['evidence_strength']}"
        )

    enriched = _matching_enrichment(
        result, str(inc_state.get('incident_id', '')), lang
    ) if result is not None else None
    if enriched:
        explanation, actions = enriched
        if explanation:
            console.print(f"\n[bold]{labels['why_it_matters']}:[/bold] {explanation}")
        for action in actions:
            console.print(f"  - {action}")

    if inc_state.get('final_report'):
        console.print("\n")
        console.print(
            Panel(
                Markdown(inc_state['final_report']),
                title=f"[bold green]{labels['generated_report']}[/bold green]",
                border_style="green",
            )
        )
    elif route == "digest":
        console.print(f"\n[yellow]{labels['digest_routed']}[/yellow]")
    elif route == "store_only":
        console.print(f"\n[yellow]{labels['store_only']}[/yellow]")
    else:
        console.print(f"\n[yellow]{labels['no_report']}[/yellow]")

    print("\n" + "="*50 + "\n")


def _run_persistent_analysis(file_path: str, *, run_triage: bool, analysis_mode: str, source_name: str, isolated: bool = False):
    """Run detect/analyze through the persistent AnalysisService so jobs,
    events, signals, incidents (and, in analyze mode, triage/report outputs)
    are persisted and optional stateful cross-job correlation applies. Computes
    the file SHA-256, analysis mode, pipeline version, and the existing
    idempotency-key format. Runs no migrations."""
    from agent.application.service_factory import (
        build_persistent_analysis_service,
        compute_file_sha256,
        compute_idempotency_key,
    )
    from agent.config import get_settings

    settings = get_settings()
    pipeline_version = settings.pipeline_version
    file_sha256 = compute_file_sha256(file_path)
    correlation_mode = "isolated" if isolated else "configured"
    idempotency_key = compute_idempotency_key(
        file_sha256,
        pipeline_version,
        analysis_mode,
        correlation_mode,
    )
    svc = build_persistent_analysis_service(settings)
    return svc.analyze_file(
        file_path,
        run_triage=run_triage,
        source_name=source_name,
        file_sha256=file_sha256,
        idempotency_key=idempotency_key,
        pipeline_version=pipeline_version,
        analysis_mode=analysis_mode,
        stateful_correlation_enabled=False if isolated else None,
    )


def analyze_file(
    file_path: str,
    *,
    isolated: bool = False,
    report_mode: str = "brief",
    lang: str = "en",
):
    console.print(f"[bold blue]Starting File Analysis: {file_path}[/bold blue]")

    result = _run_persistent_analysis(
        file_path,
        run_triage=True,
        analysis_mode="analyze",
        source_name="cli",
        isolated=isolated,
    )

    if report_mode == "full":
        # Full mode reuses the same persisted analysis as brief mode: the same
        # job, the same deterministic facts, and the same enrichment text.
        _print_analysis_summary(result, lang)
        for inc_state in result.incidents:
            _print_incident_state(inc_state, result, lang=lang)
        _print_routing_summary(result, lang)
        return result

    from pathlib import Path

    from agent.detection.rollup import build_rollup
    from agent.triage.brief import render_soc_brief

    detection_result = result.detection_result
    if detection_result is None:
        _print_analysis_summary(result)
        return result
    run_event_ids = (
        [event.event_id for event in result.ingestion_result.events]
        if result.ingestion_result and result.ingestion_result.events
        else list(result.event_map)
    )
    rollup = build_rollup(
        detection_result.incidents,
        result.event_map,
        suppressed_signals=detection_result.suppressed_signals,
        run_event_ids=run_event_ids,
    )
    render_soc_brief(
        console,
        rollup=rollup,
        event_lookup=result.event_map,
        source_name=Path(file_path).name,
        job_id=result.job_id,
        provider_call_count=int(
            (result.routing_metrics or {}).get("provider_invocation_count", 0)
        ),
        selection=result.brief_selection,
        enrichment=result.brief_enrichment,
        lang="tr" if lang == "tr" else "en",
    )
    return result

def _print_analysis_summary(result, lang: str = "en") -> None:
    labels = FULL_MODE_LABELS.get(lang, FULL_MODE_LABELS["en"])
    console.print(f"\n[bold cyan]{labels['analysis_summary']}[/bold cyan]")
    ingestion = getattr(result, "ingestion_result", None)
    if ingestion is not None:
        console.print(f"Parsed/valid events: {ingestion.metrics.parsed_records}")
    det_result = result.detection_result
    if det_result is not None:
        console.print(f"Detected signals: {det_result.metrics.signal_count}")
        console.print(
            f"Suppressed signals: {det_result.metrics.suppressed_signal_count}"
        )
        console.print(
            f"Duplicate signals removed: {det_result.metrics.duplicate_signal_count}"
        )
        # With stateful correlation enabled this is the final canonical count.
        console.print(f"Final incidents: {det_result.metrics.incident_count}")
    report_count = sum(
        1 for incident_state in result.incidents if incident_state.get("final_report")
    )
    console.print(f"Reports: {report_count}")

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

        c_events = IngestionPipeline().ingest_records(raw_logs, source_name="mock_incidents").events
        
        from agent.config import get_settings

        svc = AnalysisService(llm_enabled=get_settings().llm_enabled)
        result = svc.analyze_events(c_events, run_triage=True)

        for inc_state in result.incidents:
            _print_incident_state(inc_state)

        _print_routing_summary(result)

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

def detect_file_only(file_path: str, *, isolated: bool = False):
    console.print(f"[bold blue]Starting File Detection: {file_path}[/bold blue]")

    console.print("[bold blue]Running Detection Engine...[/bold blue]")
    result = _run_persistent_analysis(
        file_path,
        run_triage=False,
        analysis_mode="detect",
        source_name="cli_detect",
        isolated=isolated,
    )
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
    parser.add_argument(
        "--report",
        choices=("full", "brief"),
        default="brief",
        help="Analyze output format (default: brief)",
    )
    parser.add_argument(
        "--lang",
        choices=("en", "tr"),
        default="en",
        help=(
            "Brief language (default: en). Presentation only: both languages "
            "come from the same persisted enrichment, so switching never "
            "triggers another provider call."
        ),
    )
    parser.add_argument(
        "--isolated",
        action="store_true",
        help="Disable cross-job correlation for this analysis",
    )
    args = parser.parse_args()
    
    if args.detect_file:
        detect_file_only(args.detect_file, isolated=args.isolated)
    elif args.ingest_file:
        ingest_file_only(args.ingest_file)
    elif args.file:
        analyze_file(
            args.file,
            isolated=args.isolated,
            report_mode=args.report,
            lang=args.lang,
        )
    else:
        run_mock_test()
