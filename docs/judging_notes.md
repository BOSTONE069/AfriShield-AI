# Judging Notes

These notes summarize how AfriShield Cyber Defence maps to common hackathon judging areas.

## Application Of Technology

- Uses a FastAPI backend and Streamlit frontend for a working end-to-end product.
- Runs a deterministic threat intelligence pipeline so results are explainable and reliable.
- Supports optional open-source LLM enrichment through local Transformers or an OpenAI-compatible vLLM endpoint.
- Documents the AMD Developer Cloud path using ROCm, PyTorch, vLLM, and AMD Instinct MI300X runtime metadata.
- Exposes `/api/runtime` so judges can verify model, provider, backend, framework, compute device, latency, and tokens/sec.

## Product Completeness

Implemented features include:

- Suspicious message, URL, and evidence intake.
- TXT, MD, EML, LOG, and PDF upload extraction.
- IOC extraction for URLs, domains, emails, IPs, and hashes.
- Local threat feed enrichment.
- Risk scoring and severity labels.
- MITRE ATT&CK tactic/technique mapping with formal IDs.
- Markdown, PDF, and copy-to-clipboard report workflows.
- Analyst feedback capture.
- Responsive dashboard with common-user and advanced analyst views.
- Test suite covering core backend behavior and API paths.

## Business Value

AfriShield Cyber Defence targets institutions that need fast cyber triage without a mature SOC:

- Universities checking fake student portal links.
- SACCOs and banks reviewing payment and account phishing.
- NGOs handling donor and grant impersonation.
- SMEs without full-time security analysts.
- Public agencies responding to citizen-targeted scams.
- Cybersecurity students learning practical threat intelligence workflow.

## Originality

The product is localized for African cyber defense scenarios rather than being a generic phishing checker. Demo cases include KRA, M-Pesa, SACCO, university portal, NGO donor, and benign institutional communications.

## Demo Proof Points

During the demo, show:

- A high-risk scam analysis with extracted indicators.
- A benign example to prove the app does not flag everything as malicious.
- MITRE technique IDs.
- Threat feed enrichment.
- PDF export and copy report.
- Analyst feedback submission.
- Runtime panel showing the active model and compute target.

## Remaining Hackathon Evidence

If the final submission requires proof of AMD infrastructure, capture:

- Screenshot of the runtime panel on AMD Developer Cloud.
- Terminal or dashboard proof that vLLM is serving the selected model.
- Inference run showing `RUNTIME_GPU=AMD Instinct MI300X`, `RUNTIME_BACKEND=vLLM`, and `RUNTIME_FRAMEWORK=ROCm + PyTorch`.
