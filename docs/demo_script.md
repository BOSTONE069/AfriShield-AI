# Demo Script

Use this flow to demonstrate AfriShield Cyber Defence to judges, lecturers, or non-technical users.

## 1. Start Services

Terminal 1:

```bash
uvicorn backend.app.main:app --reload
```

Terminal 2:

```bash
streamlit run frontend/streamlit_app.py
```

Open the Streamlit URL shown in the terminal.

## 2. Show The Dashboard

Point out:

- AfriShield Cyber Defence branding and logo.
- Plain-language intake form: "Check a suspicious message".
- Quick example cases in the sidebar.
- System status/runtime panel showing provider, model, backend, framework, compute device, and tokens/sec.

## 3. Run A High-Risk Example

Select a sample such as the fake KRA refund, M-Pesa suspension, NGO donor grant, or university portal case.

Click the analysis button and show:

- Risk label and score.
- Simple explanation of what the message means.
- Recommended next steps for a common user.
- Extracted links and indicators.
- Threat feed enrichment results.
- MITRE ATT&CK mapping with technique IDs.

## 4. Show Analyst Features

Open the advanced details area and show:

- IOC table.
- Reputation/enrichment findings.
- MITRE tactics and techniques.
- Runtime latency and model metadata.
- Full SOC-style Markdown report.

Then demonstrate:

- Copy report button.
- Markdown download.
- PDF export.
- Analyst feedback with verdict, rating, and notes.

## 5. Show Document Upload

Upload a TXT, MD, EML, LOG, or PDF file containing suspicious evidence.

Explain that the backend extracts text through `/api/document/extract`, sends the extracted content into the same analyzer pipeline, and returns the same risk/report workflow.

## 6. Show A Benign Example

Run the benign department message sample.

Explain that AfriShield is not designed to mark every message as malicious. The deterministic baseline, local heuristics, and optional LLM enrichment work together to separate suspicious content from normal communication.

## 7. AMD Hackathon Talking Point

Explain the current runtime clearly:

- Local development uses `Qwen/Qwen3-0.6B` through Transformers and PyTorch CUDA.
- AMD deployment is configured by changing `backend/.env` to an OpenAI-compatible vLLM endpoint.
- On AMD Developer Cloud, the runtime panel should show `AMD Instinct MI300X`, `vLLM`, and `ROCm + PyTorch`.
