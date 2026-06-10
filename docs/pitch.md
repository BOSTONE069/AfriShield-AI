# AfriShield Cyber Defence Pitch

AfriShield Cyber Defence turns suspicious messages, links, emails, and uploaded evidence into explainable cyber threat intelligence for African institutions.

## Problem

Universities, SACCOs, SMEs, NGOs, public agencies, and community organizations often receive phishing, fake grant, fake payment, fake portal, and impersonation messages before they have mature SOC capacity. Many users need a tool that can explain risk in plain language, while analysts need structured indicators, MITRE mapping, and incident-ready reporting.

## Solution

AfriShield Cyber Defence provides a lightweight AI-assisted triage console:

- A common user can paste a suspicious message and receive a clear risk label, explanation, and next steps.
- An analyst can inspect extracted IOCs, enrichment, ATT&CK mapping, and a SOC-style report.
- The organization can export reports as Markdown or PDF and capture analyst feedback for future improvement.

## Technology

The system uses:

- Streamlit for the responsive dashboard.
- FastAPI for the backend API.
- A multi-agent-style analyzer pipeline for preprocessing, IOC extraction, classification, enrichment, risk scoring, MITRE mapping, and reporting.
- A deterministic cybersecurity baseline for reliable behavior.
- Optional open-source LLM enrichment using local Transformers or an OpenAI-compatible vLLM endpoint.
- PyTorch CUDA locally and a documented ROCm/vLLM path for AMD Developer Cloud.

## Hackathon Fit

The project fits the AMD Developer Hackathon because it is an AI application with a clear path to AMD acceleration:

- It can run open-source instruct models on AMD Instinct MI300X through ROCm-compatible vLLM.
- It exposes runtime metadata so judges can verify the active model, backend, framework, cloud, and compute target.
- It demonstrates practical business and public-sector value, not only a model demo.

## Differentiation

AfriShield Cyber Defence is localized for African cyber defense workflows. It includes KRA, M-Pesa, SACCO, university, donor, banking, and NGO examples, while still producing standard security outputs such as IOCs, MITRE ATT&CK IDs, risk scores, and incident reports.

## Demo Message

> AfriShield Cyber Defence helps African organizations turn suspicious digital content into clear cyber defense action. It gives common users safe next steps and gives analysts structured threat intelligence, using deterministic security logic plus optional GPU-accelerated open-source AI.
