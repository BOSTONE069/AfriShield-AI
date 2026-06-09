# AfriShield AI

AMD MI300X-powered autonomous threat intelligence agent for African cyber defense.

AfriShield AI analyzes suspicious emails, URLs, SMS messages, and social messages. It extracts indicators of compromise, classifies likely threats, assigns a risk score, maps activity to MITRE ATT&CK, and produces a SOC-ready Markdown report.

## Features

- FastAPI backend with `/health`, `/api/analyze`, `/api/runtime`, and `/api/samples`
- Deterministic IOC extraction for URLs, domains, emails, IPs, and hashes
- Localized classifier for KRA, M-Pesa, SACCO, university, donor, and banking scam patterns
- Risk scoring and severity interpretation
- MITRE ATT&CK mapping
- Streamlit analyst dashboard
- Runtime panel for model, backend, latency, and tokens/sec
- Real local model support through Transformers using `Qwen/Qwen3-0.6B`
- Optional OpenAI-compatible vLLM endpoint for AMD Developer Cloud inference

## Architecture

See [docs/architecture.md](docs/architecture.md).

## Setup

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install backend dependencies:

```bash
pip install -r backend/requirements.txt
```

Run the backend from the repository root:

```bash
uvicorn backend.app.main:app --reload
```

Install frontend dependencies in the same environment:

```bash
pip install -r frontend/requirements.txt
```

Run the dashboard:

```bash
streamlit run frontend/streamlit_app.py
```

## Model Configuration

This workspace is configured to use a real local model by default:

```env
LLM_PROVIDER=local_transformers
USE_LLM=true
LLM_MODEL=Qwen/Qwen3-0.6B
LOCAL_MODEL_PATH=/home/th3c0nf3d3r4t3/.cache/huggingface/hub/models--Qwen--Qwen3-0.6B/snapshots/c1899de289a04d12100db370d81485cdf75e47ca
```

The local model runs through Transformers and PyTorch. If CUDA is available, the backend automatically moves the local model to your NVIDIA GPU; otherwise it falls back to CPU.

For AMD Developer Cloud vLLM, update [backend/.env](backend/.env):

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

Set `USE_LLM=false` if you want deterministic rules-only analysis.

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

## Demo Samples

Sample scenarios live in [samples](samples), including fake KRA refund, fake M-Pesa suspension, fake university portal, NGO grant impersonation, SACCO account alert, and benign department message examples.
