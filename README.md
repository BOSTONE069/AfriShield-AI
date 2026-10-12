# AfriShield Cyber Defence

AfriShield Cyber Defence is a threat intelligence assistant for African institutions. It helps common users and analysts check suspicious emails, URLs, SMS messages, social messages, and uploaded evidence documents, then turns the evidence into clear risk guidance, extracted indicators, MITRE ATT&CK mapping, and exportable incident reports.

The application currently runs locally with a real open-source model, `Qwen/Qwen3-0.6B`, through Transformers and PyTorch CUDA when an NVIDIA GPU is available. It can also be pointed at an OpenAI-compatible vLLM endpoint on AMD Developer Cloud for ROCm/MI300X hackathon deployment.

## Current Features

- Responsive Streamlit dashboard branded as **AfriShield Cyber Defence** with the project logo.
- Common-user workflow with plain-language risk explanation, next steps, and quick example cases.
- Advanced analyst details for IOCs, OSINT-style enrichment, MITRE ATT&CK mapping, runtime metrics, and full reports.
- FastAPI backend with `/health`, `/api/analyze`, `/api/runtime`, `/api/samples`, `/api/feedback`, `/api/report/pdf`, and `/api/document/extract`.
- Multi-agent-style analyzer pipeline covering preprocessing, IOC extraction, classification, enrichment, risk scoring, MITRE mapping, and reporting.
- Deterministic baseline analysis for reliable demos and tests.
- Optional LLM classification enrichment using a local Transformers model or an OpenAI-compatible inference endpoint.
- Multiple report formats: executive summary, technical SOC report, user advisory, and incident ticket.
- Markdown report download, PDF report export, and browser copy-to-clipboard support for the selected report format.
- Analyst feedback capture with verdict, rating, and comments stored as JSONL.
- TXT, MD, EML, LOG, and PDF evidence upload text extraction.
- Threat feed enrichment from the local sample feed plus heuristic domain/IP/URL checks.
- MITRE ATT&CK techniques with formal IDs such as `T1566`.
- Test coverage for API routes, IOC extraction, enrichment, MITRE mapping, risk scoring, sample loading, analyzer behavior, and LLM fallback.

## Project Structure

```text
backend/app/             FastAPI service and analysis pipeline
backend/tests/           Pytest test suite
frontend/streamlit_app.py Streamlit dashboard
frontend/assets/         AfriShield logo and UI assets
samples/                 Demo cases and local threat feed
docs/                    Architecture, pitch, demo, judging, and threat-model notes
```

## Setup

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install backend and frontend dependencies:

```bash
pip install -r backend/requirements.txt
pip install -r frontend/requirements.txt
```

Production dependencies are pinned and do not include test tools or the large
local-model stack. For development, install the combined quality/test profile:

```bash
pip install -r requirements-dev.txt
```

For optional local Transformers inference, also install:

```bash
pip install -r backend/requirements-llm.txt
```

Use the PyTorch package index when a CUDA/ROCm-specific wheel is required.

For local GPU inference, install a PyTorch build that matches your driver/CUDA stack. The tested local setup uses PyTorch `2.6.0+cu124` with CUDA `12.4`.

Check CUDA from Python:

```bash
python3 -c "import torch; print(torch.__version__); print(torch.version.cuda); print(torch.cuda.is_available()); print(torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'no cuda')"
```

## Start The App

Start the backend from the repository root:

```bash
uvicorn backend.app.main:app --reload --no-server-header
```

Start the dashboard in another terminal:

```bash
streamlit run frontend/streamlit_app.py
```

The dashboard expects the backend at `http://localhost:8000` unless `AFRISHIELD_API_BASE` is set.

## Model Configuration

The local development configuration uses a real model:

```env
LLM_PROVIDER=local_transformers
USE_LLM=true
LLM_MODEL=Qwen/Qwen3-0.6B
LOCAL_MODEL_PATH=/home/th3c0nf3d3r4t3/.cache/huggingface/hub/models--Qwen--Qwen3-0.6B/snapshots/c1899de289a04d12100db370d81485cdf75e47ca
LOCAL_MAX_NEW_TOKENS=220
USE_LLM_REPORTS=false
RUNTIME_GPU=auto
RUNTIME_CLOUD=Local Workstation
RUNTIME_BACKEND=Transformers local
RUNTIME_FRAMEWORK=PyTorch CUDA
```

`USE_LLM_REPORTS=false` is recommended for local demos on smaller GPUs because it avoids a second generation call for the report. Classification can still use the LLM while the report is generated from the deterministic template.

For AMD Developer Cloud or another ROCm/vLLM deployment, update `backend/.env`:

```env
LLM_PROVIDER=openai_compatible
USE_LLM=true
LLM_API_BASE=http://your-amd-vllm-endpoint:8000/v1
LLM_API_KEY=not-required-or-your-key
LLM_MODEL=Qwen/Qwen2.5-7B-Instruct
RUNTIME_GPU=AMD Instinct MI300X
RUNTIME_CLOUD=AMD Developer Cloud
RUNTIME_BACKEND=vLLM
RUNTIME_FRAMEWORK=ROCm + PyTorch
```

Set `USE_LLM=false` for deterministic rules-only operation.

## API Example

Protected endpoints require an API key. Submit analysis to the bounded background queue and poll the returned job URL:

```bash
curl -X POST http://localhost:8000/api/analysis/jobs \
  -H "X-API-Key: your-analyst-key" \
  -H "Content-Type: application/json" \
  -d '{"input_type":"sms","context":"Kenya","content":"Dear taxpayer, your KRA refund is ready. Verify your account at https://kra-refund-verify.com/login","remote_processing_consent":false}'
```

The response contains a `job_id`. Poll `GET /api/analysis/jobs/{job_id}` with the same key. Synchronous `/api/analyze` is disabled in the production Compose configuration.

Remote LLM processing is opt-in for every request. When `LLM_PROVIDER=openai_compatible`, evidence is not transmitted unless `remote_processing_consent` is explicitly `true`.

## Tests

```bash
python3 -m pytest
ruff check .
ruff format --check .
mypy
pip-audit -r backend/requirements.txt
pip-audit -r frontend/requirements.txt
```

Pytest enforces at least 75% branch-aware backend coverage. The suite also
covers malformed inputs, upload and extraction limits, malformed PDFs, prompt
injection downgrade attempts, and concurrent deterministic analysis.

Run a smoke load test against a running backend:

```bash
python3 scripts/load_test.py --requests 50 --concurrency 10
```

## Evaluation Benchmark

The repository includes a versioned 600-case multilingual safety benchmark.
It reports confusion matrices, precision, recall, false-negative rate, and
results by language, threat type, and scenario:

```bash
python3 evaluation/evaluate.py \
  --max-false-negative-rate 0.17 \
  --min-accuracy 0.35
```

See [Evaluation Benchmark](evaluation/README.md) for the dataset card,
limitations, anonymization rules, and the process for adding analyst-reviewed
field samples.

Analyst feedback now records corrected labels, severity, error reasons, IOCs, actions, reviewer identity, score factors, and component versions in encrypted SQLite. Administrators can retrieve content-free aggregate metrics from `GET /api/admin/feedback/metrics`, and reviewed cases can be evaluated with `python evaluation/evaluate_feedback.py`. Prediction-affecting component changes must pass the held-out regression before the component fingerprint is refreshed.

## Containers

Create deployment secrets before starting the services:

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Put the first value in both the secret portion of `AFRISHIELD_API_KEYS` and `AFRISHIELD_API_KEY`. API credentials use `reviewer-name=secret:role`, so feedback is attributed to the authenticated reviewer without accepting a user-supplied identity. Put the second generated value in `AFRISHIELD_DATA_ENCRYPTION_KEY`. Then start both services:

If upgrading an existing checkout with `data/feedback.jsonl`, migrate it after filling in `.env` and before deployment:

```bash
python scripts/migrate_feedback.py
```

The migration validates every row, imports it into encrypted SQLite, writes an encrypted `.fernet` recovery archive, and removes the plaintext only after both operations succeed. `/ready` reports `not_ready` while legacy plaintext feedback remains.

```bash
docker compose up --build
```

If either default host port is already in use, override it without editing the
Compose file:

```bash
AFRISHIELD_FRONTEND_PORT=8502 docker compose up --build
```

The API is exposed at `http://localhost:8000`, the dashboard at
`http://localhost:8501`, and both images include health checks. `/health` is a
liveness probe; `/ready` reports readiness and the active analysis mode.

Deployment controls include API-key roles (`viewer`, `analyst`, `admin`), per-key rate limiting, request IDs, body-free audit logs, encrypted SQLite feedback, automatic retention, strict upload MIME/signature checks, subprocess parser limits, and a bounded background inference queue. Terminate TLS at a trusted reverse proxy or load balancer; API keys and submitted evidence must never cross an unencrypted network.

Uvicorn is launched with `--no-server-header`, and application responses strip common technology-banner headers. If a reverse proxy is added, configure it to discard upstream `Server` headers as well—for Nginx, use `proxy_hide_header Server`; complete removal of Nginx's own banner requires a build/module that supports clearing its generated `Server` header.

The CI workflow runs formatting, linting, type checking, tests with the
coverage floor, dependency audits, and both container builds. Dependabot checks
Python and GitHub Actions dependencies weekly.

## Documentation

- [Architecture](docs/architecture.md)
- [Demo Script](docs/demo_script.md)
- [Pitch](docs/pitch.md)
- [Judging Notes](docs/judging_notes.md)
- [Threat Model](docs/threat_model.md)
- [Project Approach](afrishield_ai_project_approach.md)
