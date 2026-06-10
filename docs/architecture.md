# AfriShield Cyber Defence Architecture

AfriShield Cyber Defence is built as a Streamlit dashboard over a FastAPI analysis service. The backend combines deterministic cybersecurity logic with optional LLM enrichment so the product remains usable during demos even when a model endpoint is slow or unavailable.

## High-Level Flow

```text
User or analyst
      |
      v
Streamlit dashboard
      |
      |  HTTP requests
      v
FastAPI backend
      |
      |-- PreprocessingAgent
      |-- IOCAgent
      |-- ClassificationAgent
      |-- EnrichmentAgent
      |-- RiskAgent
      |-- MitreAgent
      |-- ReportAgent
      |
      |-- Local deterministic engines
      |-- Optional LLM client
      |
      v
Analysis response, Markdown report, PDF export, feedback record
```

## Frontend

The dashboard lives in `frontend/streamlit_app.py`.

- Shows the AfriShield Cyber Defence logo and brand.
- Provides a common-user form for suspicious messages, URLs, and uploaded evidence.
- Includes quick example cases for Kenyan and African threat scenarios.
- Displays a simple risk explanation first, then hides technical detail under advanced sections.
- Supports Markdown download, PDF export, report copy, and analyst feedback.
- Uses responsive CSS so the sidebar, result cards, tabs, tables, and forms work on smaller screens.

## Backend

The FastAPI entry point is `backend/app/main.py`.

| Endpoint | Purpose |
|---|---|
| `GET /health` | Service health check |
| `POST /api/analyze` | Main threat analysis workflow |
| `GET /api/runtime` | Runtime/model/backend metadata for the dashboard |
| `GET /api/samples` | Demo sample cases |
| `POST /api/feedback` | Persist analyst feedback |
| `POST /api/report/pdf` | Convert Markdown report to PDF |
| `POST /api/document/extract` | Extract text from TXT, MD, EML, LOG, or PDF uploads |

## Analysis Pipeline

The orchestrator is `backend/app/analyzer.py`; agent-style units are defined in `backend/app/agents.py`.

1. **Preprocessing** normalizes text and prepares request context.
2. **IOC extraction** finds URLs, domains, emails, IP addresses, and hashes.
3. **Threat classification** applies local rules and optionally enriches with the configured LLM.
4. **Threat feed enrichment** checks extracted indicators against `samples/threat_feed.json` and local heuristics.
5. **Risk scoring** assigns a 0-100 score and severity label.
6. **MITRE mapping** adds tactics, techniques, and formal ATT&CK IDs.
7. **Report generation** creates a SOC-style Markdown report. LLM-generated reports are available but disabled by default for faster local demos.

## Model Runtime

Local development uses:

```text
Provider: local_transformers
Model: Qwen/Qwen3-0.6B
Backend: Transformers local
Framework: PyTorch CUDA when CUDA is available
Compute: auto-detected GPU or CPU fallback
```

AMD deployment uses:

```text
Provider: openai_compatible
Backend: vLLM
Framework: ROCm + PyTorch
Compute: AMD Instinct MI300X
Cloud: AMD Developer Cloud
```

The runtime panel is metadata-driven. If the app is moved to AMD, update `backend/.env` so the dashboard displays the correct provider, backend, framework, model, and compute target.

## Storage

- Demo and benign examples live in `samples/*.json`.
- Local enrichment data lives in `samples/threat_feed.json`.
- Analyst feedback is appended to `data/feedback.jsonl`.
- No user authentication, database, or SIEM integration is included in the MVP.

## Reliability Design

The deterministic pipeline always runs first. The LLM is used only as enrichment, so timeouts or JSON parsing failures do not break the core analyzer. This keeps the system suitable for hackathon demos and low-resource environments.
