import time
import argparse
from datetime import datetime, timedelta, timezone
import psutil
import os
import sys

from agent.schema import CanonicalLogEvent
from agent.detection.engine import DetectionEngine

def generate_events(num_records: int) -> list[CanonicalLogEvent]:
    events = []
    base_time = datetime.now(timezone.utc)
    
    # 90% normal, 10% anomalies
    for i in range(num_records):
        is_scan = i % 10 == 0
        src = f"1.2.3.{i%20}" if is_scan else f"10.1.1.{i%50}"
        dst = f"10.0.0.{i%200}" if is_scan else f"10.0.0.{i%10}"
        port = 80 + (i % 5) if not is_scan else (3389 if i % 3 == 0 else 22)
        action = "block" if is_scan else "allow"
        
        events.append(CanonicalLogEvent(
            event_id=f"bench-e{i}",
            timestamp=base_time + timedelta(seconds=i),
            src_ip=src,
            dst_ip=dst,
            dst_port=port,
            action=action,
            parser_name="test",
            parse_status="success"
        ))
    return events

def run_benchmark(num_records: int):
    print(f"Generating {num_records} canonical events...")
    events = generate_events(num_records)
    
    engine = DetectionEngine()
    
    print("Starting Detection Engine benchmark...")
    
    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss
    
    start = time.time()
    res = engine.analyze(events)
    end = time.time()
    
    mem_after = process.memory_info().rss
    peak_mem_mb = (mem_after - mem_before) / (1024 * 1024)
    duration = end - start
    eps = num_records / max(0.001, duration)
    
    print("\n--- Benchmark Results ---")
    print(f"Python Version: {sys.version.split(' ')[0]}")
    print(f"Platform: {sys.platform}")
    print(f"Total Events: {res.metrics.total_events}")
    print(f"Eligible Events: {res.metrics.eligible_events}")
    print(f"Signals Generated: {res.metrics.signal_count}")
    print(f"Incidents Correlated: {res.metrics.incident_count}")
    print(f"Duplicate/Merged Signals: {res.metrics.duplicate_signal_count}")
    print(f"Duration: {duration:.4f} seconds")
    print(f"Events Per Second (EPS): {eps:.0f}")
    print(f"Approx Memory Growth: {peak_mem_mb:.2f} MB")
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--records", type=int, default=100000)
    args = parser.parse_args()
    run_benchmark(args.records)
