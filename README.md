# Agentic SOC Triage Assistant - Phase 1 (Foundation)

The system operates strictly as a **Triage Assistant**. It does not perform autonomous remediation (e.g., blocking IPs) or replace SIEM correlation rules. Its purpose is to contextualize alerts and accelerate analyst decision-making.

### Phase 2: Professional Log Ingestion Platform
The ingestion layer has been upgraded to a modular, robust, and extensible platform capable of handling diverse log formats reliably:
- **Safe Streaming Readers**: Memory-efficient processing of `JSONL`, `JSON Arrays`, `Syslog`, and `CEF` logs with strict size limits.
- **Parser Plugin System**: A confidence-based parser registry with deterministic schema fingerprinting. Support for custom vendors is as easy as adding a class.
- **Fail-safe Operations**: Unparseable and unsupported schemas are isolated. A single malformed line will not crash the pipeline.
- **Canonical Schema**: All records are mapped to an upgraded `CanonicalLogEvent` standardizing IP, ports, network zones, timestamps, and parsing metadata.
- **Full Traceability**: Every event gets a deterministic `EVT-*` ID, and all parse warnings/errors are captured without leaking sensitive raw logs.

## Features (Phase 1)
- **Robust Ingestion Pipeline**: Deterministically parses logs into a `CanonicalLogEvent` using schema fingerprinting and pre-defined parsers.
- **Strict Evidence Validation**: Evidence gathered by the LLM is deterministically validated against the original logs (`original_fields` and `raw_message`).
- **Graceful Fallback**: Enforces a `needs_review` verdict automatically if the agent hallucinates or if the LLM is unavailable.
- **Decoupled Architecture**: End-to-end data contracts using typed `CanonicalLogEvent` objects instead of raw dictionaries.

## System Overview

This project is not a simple LLM chatbot. Raw logs are first normalized and analyzed by deterministic Python detection rules. These rules generate detected signals and candidate evidence before the LLM is invoked. The Triage Agent then reviews these signals, optionally calls the `search_logs` tool for additional context, and submits a structured triage decision. Every evidence item is validated against the original raw logs before the final report is generated.

The final output is a concise SOC triage report focused on four questions:

1. What happened?
2. Why is it suspicious or benign?
3. What evidence supports the verdict?
4. What should the analyst do next?

## Architecture

1. **Ingestion Layer (`agent/ingestion/`)**: Modular platform supporting JSON, Syslog, CEF. Detects formats, streams data securely, generates fingerprints, and assigns deterministic IDs.
2. **Parser Registry (`agent/parsers/`)**: Confidence-based plugin system containing parsers for `pf_firewall`, `syslog`, `cef`, `generic_json`, and `mock`.
3. **Filtering Engine (`agent/filtering.py`)**: Filters out known noisy events (e.g., internal scans) and flags candidates.
4. **Correlation Engine (`agent/correlation.py`)**: Groups related events into Incident Bundles based on source IP and temporal proximity.
5. **Triage Agent (`agent/graph.py`)**: LangGraph workflow containing Pre-Analysis, Triage, and Reporting nodes. Uses Groq/Llama-3 for decision making.

## Key Features

- **LangGraph-based agentic workflow:** The system is built as a controlled state machine instead of a free-form chatbot.
- **Deterministic pre-analysis:** Python detection rules identify suspicious or benign patterns before the LLM is invoked.
- **Candidate evidence generation:** Detection rules generate structured evidence with `event_id`, `quote`, `reason`, and `source`.
- **Constrained Triage Agent:** The LLM can only use limited tools such as `search_logs` and `submit_triage_result`.
- **Evidence validation:** Every submitted evidence item is checked against the original raw logs.
- **needs_review fallback:** Invalid, missing, or weak evidence prevents unsafe automatic decisions.
- **MITRE ATT&CK mapping:** Relevant incident types are mapped to ATT&CK techniques.
- **Concise SOC reporting:** Reports are short, evidence-based, and focused on analyst decision-making.
- **FastAPI support:** The workflow can be used through REST endpoints.
- **Pytest coverage:** Deterministic detection and validation logic are covered by tests.

### 1. Robust Pipeline Core (Phase 1)
- Deterministic Event ID Generation (SHA-256)
- File Upload Security (Chunking, Temp File Cleanup)
- Ingestion Limits Enforcement
- Comprehensive Unit Testing & Benchmarking

### 2. Advanced Parsers & Integration (Phase 2) - **COMPLETED**
- Flexible JSON Reader with Array and Single Object support
- Strict vs Lenient UTF-8 Encoding Handlers
- Dynamic Format Detection (JSONL, Syslog, CEF, Text Logs)
- Universal `CanonicalLogEvent` Mapping
- Extensible Parser Registry (`agent/parsers/registry.py`)
- Standardized API Error Handling (HTTP 413, 415, 422)

## Why This Is Not Just an LLM Chatbot

A simple chatbot would send raw logs directly to an LLM and return a free-form answer. This project uses a controlled agentic workflow:

1. Logs are normalized with event IDs.
2. Deterministic detection rules generate signals and candidate evidence.
3. The Triage Agent reviews structured evidence and may call tools for more context.
4. The triage result must follow a strict Pydantic schema.
5. Evidence is validated against the original raw logs.
6. The final report is generated only from validated evidence and deterministic recommendations.

This makes the system a controlled Agentic SOC Triage PoC rather than a plain LLM chatbot.

## Report Generation

The report generation layer is intentionally concise and evidence-first. The goal is not to produce long generic security writeups, but to create a short SOC triage report that can be understood quickly.

Each report answers four questions:

1. **Verdict:** Is the incident a false positive, suspicious activity, confirmed incident, or does it need human review?
2. **Why it matters:** Why is the log suspicious, malicious, benign, or inconclusive?
3. **Key evidence:** Which validated event IDs and log quotes support the decision?
4. **Recommended actions:** What should the analyst do next?

The report is designed to be short and readable. It avoids unsupported claims such as data exfiltration, account compromise, or database compromise unless the logs provide direct evidence.

### Example Report Format
<img width="1917" height="1055" alt="image" src="https://github.com/user-attachments/assets/77ae86e2-2832-4d7f-8879-81635dbc1375" />

## Tech Stack

- Python 3.10+
- LangGraph
- LangChain / LangChain Groq
- Groq API with Llama 3.3 70B
- Pydantic
- FastAPI
- Uvicorn
- Pytest
- Rich for terminal output

## Project Structure

```text
SOC-Project/
├── agent/
│   ├── graph.py          # LangGraph workflow definition
│   ├── nodes.py          # Workflow nodes: extraction, detection, triage, validation, reporting
│   ├── tools.py          # LLM-accessible tools and deterministic detection functions
│   └── models.py         # Pydantic schemas and LangGraph state definitions
├── data/
│   └── mock_logs.json    # Mock SOC incident dataset
├── tests/
│   ├── test_detection_tools.py
│   ├── test_evidence_validation.py
│   ├── test_reporter_output.py
│   └── test_graph_smoke.py
├── main.py               # Terminal-based test runner
├── server.py             # FastAPI server
├── requirements.txt
└── README.md
```

## Getting Started

### Prerequisites
- Python 3.11+
- [Groq API Key](https://console.groq.com/) (Optional, but required for full LLM capability)

### Installation
1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Configure environment variables:
   Copy `.env.example` to `.env` and configure your settings.
   ```bash
   cp .env.example .env
   ```

### Running Locally

**CLI Mode:**
Run mock data through the pipeline:
```bash
python main.py
```

Process a specific log file:
```bash
python main.py --file data/samples/sanitized_firewall_sample.jsonl
```

To quickly test the ingestion platform without running LLM triage:
```bash
python main.py --ingest-file tests/fixtures/mixed/mixed_formats.log
```

### Ingestion Benchmarking
To benchmark the ingestion pipeline with large log files:
```bash
python scripts/benchmark_ingestion.py --generate-mb 25
```
This generates a mock log file and evaluates events-per-second (EPS) performance.

**API Mode:**
Run the REST API:
```bash
python -m uvicorn server:app --reload
```
Endpoints:
- `GET /health` : Liveness probe
- `GET /ready` : Readiness probe (checks LLM availability)
- `POST /analyze` : Mock endpoint for analysis

## Testing & CI
This project uses `pytest`, `mypy`, and `ruff` for code quality and testing. The test suite does not require external network requests and executes gracefully when `LLM_ENABLED=false`.

```bash
# Run tests
pytest

# Run linter
ruff check .

# Run type checking
mypy agent/
```

## Security
- Do not commit `.env` or any real API keys to version control.
- Dummy keys and mock endpoints should be used in test environments.
