import time
import sys
import argparse
from pathlib import Path
from agent.ingestion.pipeline import IngestionPipeline

def generate_large_fixture(path: str, size_mb: int, template_path: str):
    """Generate a large fixture for benchmarking by duplicating a template file."""
    print(f"Generating {size_mb}MB fixture at {path} using {template_path}...")
    
    with open(template_path, 'r', encoding='utf-8') as f:
        template_content = f.read()
        
    target_bytes = size_mb * 1024 * 1024
    current_bytes = 0
    
    with open(path, 'w', encoding='utf-8') as f:
        while current_bytes < target_bytes:
            f.write(template_content)
            if not template_content.endswith('\\n'):
                f.write('\\n')
                current_bytes += 1
            current_bytes += len(template_content.encode('utf-8'))
            
    print("Done.")

def run_benchmark(path: str):
    pipeline = IngestionPipeline()
    print(f"Benchmarking ingestion for {path}...")
    
    start_time = time.time()
    result = pipeline.ingest_file(path)
    end_time = time.time()
    
    duration = end_time - start_time
    file_size_mb = Path(path).stat().st_size / (1024 * 1024)
    eps = result.metrics.total_records / duration if duration > 0 else 0
    throughput_mbps = file_size_mb / duration if duration > 0 else 0
    
    print("\\n--- BENCHMARK RESULTS ---")
    print(f"Duration: {duration:.2f} seconds")
    print(f"File Size: {file_size_mb:.2f} MB")
    print(f"Total Records: {result.metrics.total_records}")
    print(f"Parsed Records: {result.metrics.parsed_records}")
    print(f"Events Per Second (EPS): {eps:.2f}")
    print(f"Throughput: {throughput_mbps:.2f} MB/s")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=str, help="Path to file to benchmark")
    parser.add_argument("--generate-mb", type=int, help="Generate a large fixture of this size in MB")
    parser.add_argument("--template", type=str, help="Template file to duplicate", default="tests/fixtures/mock/mock_events.jsonl")
    args = parser.parse_args()
    
    target_file = args.file or "tests/fixtures/large_benchmark.jsonl"
    
    if args.generate_mb:
        generate_large_fixture(target_file, args.generate_mb, args.template)
        
    if Path(target_file).exists():
        run_benchmark(target_file)
    else:
        print(f"File {target_file} not found. Use --generate-mb to create it.")
