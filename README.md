# Agentic SOC Triage Assistant 

An **Autonomous Security Operations Center (SOC) Triage System** powered by LangGraph, LLMs, and Python. This project is designed to automate the initial investigation and triage of security alerts and raw logs, significantly reducing the workload on human SOC analysts while eliminating false positives.

##  Key Features

*   **Multi-Agent State Machine (LangGraph):** The system relies on a strictly defined directed graph rather than an unconstrained LLM. It manages iterative reasoning (ReAct) efficiently.
*   **Deterministic Entity Extraction:** Pre-processes logs with Regex to extract IPs, domains, hashes, and endpoints *before* sending data to the LLM, saving tokens and improving accuracy.
*   **Dynamic Strategy Routing:** Analyzes incoming event types (e.g., `SSH_AUTH`, `DNS_QUERY`) and generates a strict, step-by-step investigation strategy injected directly into the LLM's system prompt.
*   **Robust Evidence Validation:** Validates all LLM-provided evidence against the original raw logs to completely prevent hallucinated quotes or mismatched event IDs.
*   **Action Recommendations:** Maps specific incident types (e.g., `sql_injection`, `dns_tunneling`, `benign_web_traffic`) to actionable, context-aware mitigation strategies.
*   **Infinite Loop Protection:** Enforces a strict iteration limit to prevent the agent from getting stuck in an endless tool-calling loop.
*   **FastAPI Integration:** Fully accessible via a REST API (`/analyze`, `/incident/{id}/report`).

##  Tech Stack

*   **Python 3.10+**
*   **LangGraph & LangChain:** For agent orchestration and tool binding.
*   **Groq API (Llama 3.3 70B):** High-speed, cost-effective LLM inference.
*   **FastAPI & Uvicorn:** For API endpoints and server deployment.
*   **Pydantic:** Strict schema validation for agent outputs.

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

*   `main.py`: The entry point for the terminal-based testing and the LangGraph workflow definition.
*   `server.py`: FastAPI server for exposing the system via REST endpoints.
*   `nodes.py`: Contains all the individual workflow nodes (Entity Extraction, Router, Triage Agent, Validation, Reporter).
*   `tools.py`: Deterministic Python tools for the LLM to search logs and detect specific threat patterns (SQLi, Brute Force, Port Scan, etc.).
*   `models.py`: Pydantic schemas and typed dictionaries for state management.
*   `mock_logs.json`: A dataset containing 12 distinct security scenarios (both real threats and false positives).

##  License
MIT License
