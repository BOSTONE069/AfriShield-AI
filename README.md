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
- Markdown report download, PDF report export, and browser copy-to-clipboard support.
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

For local GPU inference, install a PyTorch build that matches your driver/CUDA stack. The tested local setup uses PyTorch `2.6.0+cu124` with CUDA `12.4`.

Check CUDA from Python:

```bash
python3 -c "import torch; print(torch.__version__); print(torch.version.cuda); print(torch.cuda.is_available()); print(torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'no cuda')"
```

## Start The App

Start the backend from the repository root:

```bash
uvicorn backend.app.main:app --reload
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

```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"input_type":"sms","context":"Kenya","content":"Dear taxpayer, your KRA refund is ready. Verify your account at https://kra-refund-verify.com/login"}'
```

## Tests

```bash
python3 -m pytest backend/tests
```

The current test suite covers analyzer basics, API endpoints, document extraction, PDF export, analyst feedback, IOC extraction, local threat feed enrichment, MITRE mappings, sample cases, risk scoring, and LLM fallback behavior.

## Documentation

- [Architecture](docs/architecture.md)
- [Demo Script](docs/demo_script.md)
- [Pitch](docs/pitch.md)
- [Judging Notes](docs/judging_notes.md)
- [Threat Model](docs/threat_model.md)
- [Project Approach](afrishield_ai_project_approach.md)
