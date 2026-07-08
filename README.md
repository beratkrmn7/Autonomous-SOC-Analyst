# Agentic SOC Triage Assistant 

An **Autonomous Security Operations Center (SOC) Triage System** powered by LangGraph, LLMs, and Python. This project is designed to automate the initial investigation and triage of security alerts and raw logs, reducing the false positive workload on human SOC analysts.

##  Key Features

*   **Multi-Agent State Machine (LangGraph):** The system relies on a strictly defined directed graph rather than an unconstrained LLM. It manages iterative reasoning (ReAct) efficiently.
*   **Deterministic Entity Extraction:** Pre-processes logs with Regex to extract IPs, domains, hashes, and endpoints *before* sending data to the LLM, saving tokens and improving accuracy.
*   **Automated Deterministic Pre-Analysis:** Analyzes incoming event types and deterministically runs Python detection tools to generate highly accurate "candidate evidence" before the LLM is even invoked.
*   **Robust Evidence Validation:** Validates all LLM-provided evidence against the original raw logs to reduce hallucinated evidence through strict `event_id` and substring quote validation.
*   **Action Recommendations & MITRE ATT&CK:** Maps specific incident types (e.g., `sql_injection`, `dns_tunneling`, `benign_web_traffic`) to actionable mitigation strategies and MITRE techniques.
*   **Infinite Loop Protection:** Enforces a strict iteration limit to prevent the agent from getting stuck in an endless tool-calling loop.
*   **FastAPI Integration:** Fully accessible via a REST API (`/analyze`, `/incident/{id}/report`).

##  Tech Stack

*   **Python 3.10+**
*   **LangGraph & LangChain:** For agent orchestration and tool binding.
*   **Groq API (Llama 3.3 70B):** High-speed, cost-effective LLM inference.
*   **FastAPI & Uvicorn:** For API endpoints and server deployment.
*   **Pydantic:** Strict schema validation for agent outputs.
*   **Pytest:** For deterministic logic testing.

##  Getting Started

### 1. Prerequisites
Ensure you have Python installed. Install the required dependencies:
```bash
pip install -r requirements.txt
```

### 2. Environment Variables
Create a `.env` file in the root directory and add your Groq API key:
```env
GROQ_API_KEY=your_groq_api_key_here
```

### 3. Running in Test Mode (Terminal)
To run the automated triage process on the provided `mock_logs.json` and watch the agent's thought process in the terminal:
```bash
# Run the first incident only
python main.py

# Run all mock incidents
RUN_ALL=true python main.py
```

### 4. Running as an API (Server)
To start the FastAPI server:
```bash
python server.py
```
You can access the Swagger UI documentation at: `http://localhost:8000/docs`

##  Project Structure

*   `graph.py`: LangGraph workflow definition.
*   `main.py`: Terminal-based test runner using `mock_logs.json`.
*   `server.py`: FastAPI server for exposing the system via REST endpoints.
*   `nodes.py`: Workflow nodes such as entity extraction, automated detection, triage, validation, action recommendation and reporter.
*   `tools.py`: LLM-accessible tools and deterministic detection functions.
*   `models.py`: Pydantic models and LangGraph state schemas.
*   `mock_logs.json`: Mock SOC incident dataset.
*   `tests/`: Test suite for detection logic and graph execution.

##  System Definition

This project is not a full production SOC platform. It is a **LangGraph-based, deterministic detection-layered, and constrained LLM triage agent PoC** demonstrating evidence-based autonomous investigation.

##  License
MIT License
