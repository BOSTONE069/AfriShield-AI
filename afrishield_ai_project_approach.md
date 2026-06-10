# AfriShield Cyber Defence

## AMD MI300X-Powered Autonomous Threat Intelligence Agent for African Cyber Defence

---

## Current Implementation Status - June 2026

The project has moved beyond the original MVP plan and is now implemented as **AfriShield Cyber Defence**, a branded Streamlit and FastAPI threat intelligence platform.

### Implemented Application Updates

| Area | Current Status |
|---|---|
| Branding | Dashboard renamed to AfriShield Cyber Defence with a generated logo in `frontend/assets/afrishield-cyber-defence-logo.png`. |
| Dashboard UX | Responsive Streamlit dashboard with common-user wording, quick examples, plain-language risk explanation, next steps, and advanced analyst details. |
| Backend API | FastAPI exposes `/health`, `/api/analyze`, `/api/runtime`, `/api/samples`, `/api/feedback`, `/api/report/pdf`, and `/api/document/extract`. |
| IOC extraction | URLs, domains, email addresses, IP addresses, and hashes are extracted from pasted or uploaded evidence. |
| Threat classification | Deterministic localized classifier runs first; optional LLM enrichment is available. |
| Real model | Local development uses `Qwen/Qwen3-0.6B` through Transformers. CUDA is used automatically when PyTorch detects the NVIDIA GPU. |
| AMD deployment path | The app can be pointed to an OpenAI-compatible vLLM endpoint on AMD Developer Cloud by changing `backend/.env`. |
| Runtime panel | Dashboard shows provider, model, backend, framework, compute device, latency, and tokens/sec. |
| Threat feed enrichment | Extracted indicators are checked against `samples/threat_feed.json` and local reputation heuristics. |
| MITRE mapping | Mappings now include formal ATT&CK technique IDs such as `T1566`. |
| Reports | Markdown reports are generated, downloadable, copyable, and exportable to PDF. |
| Analyst feedback | Correct/incorrect/needs-review feedback, confidence rating, and comments are captured through the dashboard and saved as JSONL. |
| Document upload | TXT, MD, EML, LOG, and PDF evidence upload is supported through the backend extraction endpoint. |
| Multi-agent mode | Implemented as an orchestrated multi-agent-style pipeline with preprocessing, IOC, classification, enrichment, risk, MITRE, and report agents. |
| Tests | Tests now cover analyzer behavior, IOC extraction, risk scoring, MITRE mapping, enrichment, API endpoints, samples, PDF export, document extraction, feedback, and LLM fallback. |

### Current Local Runtime

```env
LLM_PROVIDER=local_transformers
USE_LLM=true
LLM_MODEL=Qwen/Qwen3-0.6B
LOCAL_MAX_NEW_TOKENS=220
USE_LLM_REPORTS=false
RUNTIME_GPU=auto
RUNTIME_CLOUD=Local Workstation
RUNTIME_BACKEND=Transformers local
RUNTIME_FRAMEWORK=PyTorch CUDA
```

`USE_LLM_REPORTS=false` keeps local analysis responsive on smaller GPUs by using the model for classification enrichment while generating the report from deterministic template code.

### AMD Developer Cloud Runtime

For hackathon judging on AMD infrastructure, update `backend/.env`:

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

### Remaining Submission Tasks

- Run and screen-record the final demo on AMD Developer Cloud if hackathon rules require AMD runtime proof.
- Capture screenshots of the runtime panel showing AMD MI300X, vLLM, and ROCm + PyTorch.
- Review feedback storage before production use because the MVP stores analyst feedback locally in `data/feedback.jsonl`.
- Add authentication, history storage, and external live OSINT integrations only if the project moves beyond MVP/hackathon scope.

## 1. Project Summary

**AfriShield Cyber Defence** is an AI-powered cyber threat intelligence assistant designed to help African institutions quickly analyze suspicious emails, URLs, messages, and security-related text. The system classifies potential threats, extracts indicators of compromise, assigns a risk score, maps activity to MITRE ATT&CK techniques, and generates a SOC-ready incident report.

The project is designed for the **AMD Developer Hackathon: ACT II**, where the solution must run on AMD infrastructure using AMD cloud-accessible GPUs, ROCm-compatible frameworks, and open-source AI tooling.

### Short Description

AfriShield Cyber Defence turns suspicious links, emails, and messages into explainable cyber threat intelligence reports in seconds.

### Long Description

African institutions such as universities, banks, SMEs, SACCOs, public agencies, and NGOs face increasing phishing, scam, impersonation, credential theft, and misinformation threats. Many of these organizations do not have mature Security Operations Centers or expensive commercial threat intelligence tools.

AfriShield Cyber Defence acts as a lightweight AI SOC analyst. It helps users analyze suspicious digital content, identify risks, extract technical indicators, understand the threat context, and receive recommended response actions.

---

## 2. Core Problem

Cyber threats are growing across Africa, especially:

- Fake mobile money messages
- Fake KRA/tax refund scams
- Banking phishing links
- Fake university portal links
- Fake job recruitment scams
- NGO/donor impersonation scams
- Credential harvesting attacks
- Malicious URLs
- Social engineering messages
- Misinformation and harmful coordinated messaging

Many organizations lack:

- Real-time threat analysis
- Skilled SOC analysts
- Localized African cyber threat context
- Affordable AI-assisted security tooling
- Automated incident reporting

AfriShield Cyber Defence addresses this by providing a localized, explainable, and GPU-accelerated AI cyber defense assistant.

---

## 3. Target Users

| User Group | Pain Point | AfriShield Value |
|---|---|---|
| Universities | Fake student portal and fee payment links | Detects suspicious student/staff messages |
| Banks and SACCOs | Phishing and impersonation attacks | Provides quick first-level triage |
| SMEs | No dedicated SOC team | Offers affordable cyber risk analysis |
| Government agencies | Fake notices and citizen-targeted scams | Identifies scam and impersonation patterns |
| NGOs | Donor fraud and grant scams | Analyzes suspicious communication |
| Cybersecurity students | Need practical SOC learning tools | Provides hands-on threat intelligence workflow |

---

## 4. Project Goal

The main goal is to build a working AI agent that can:

1. Accept suspicious email text, URLs, or messages.
2. Extract indicators of compromise.
3. Classify the threat type.
4. Generate a cyber risk score.
5. Map the threat to MITRE ATT&CK techniques.
6. Produce a SOC-ready incident report.
7. Run inference on AMD Developer Cloud using AMD GPU infrastructure.

---

## 5. Hackathon Positioning

### Recommended Pitch

> AfriShield Cyber Defence is an AMD MI300X-powered autonomous threat intelligence agent for African cyber defense. It analyzes suspicious emails, URLs, and messages, extracts indicators of compromise, classifies cyber risk, maps threats to MITRE ATT&CK, and generates SOC-ready incident reports. The system uses open-source AI models accelerated on AMD Developer Cloud through ROCm-compatible inference tooling.

### Tagline

> Turning suspicious links, emails, and messages into explainable SOC-ready intelligence in seconds.

### Why This Fits the Hackathon

The hackathon asks participants to build an AI agent or high-performance AI application on AMD Developer Cloud using ROCm-compatible frameworks and AMD GPUs.

AfriShield Cyber Defence fits because it:

- Solves a real-world cybersecurity problem.
- Uses open-source AI models.
- Can run inference using AMD MI300X GPUs.
- Demonstrates enterprise and public-sector value.
- Uses AI agents for automation, reasoning, and report generation.
- Has a clear demo workflow.

---

## 6. MVP Scope

The MVP should be narrow, useful, and easy to demonstrate.

### MVP Input Types

For the first version, support:

1. Suspicious email text
2. Suspicious URL
3. Suspicious SMS or social message

Avoid complex file upload in the first build unless time allows.

### MVP Output

The system should return:

```json
{
  "threat_type": "PHISHING",
  "risk_score": 88,
  "severity": "HIGH",
  "iocs": {
    "urls": ["https://kra-refund-verify.com/login"],
    "domains": ["kra-refund-verify.com"],
    "emails": [],
    "ips": [],
    "hashes": []
  },
  "mitre_mapping": [
    {
      "tactic": "Initial Access",
      "technique": "Phishing"
    },
    {
      "tactic": "Credential Access",
      "technique": "Credential Harvesting"
    }
  ],
  "summary": "The message attempts to lure the user into visiting a fake KRA refund page.",
  "recommended_actions": [
    "Do not click the link.",
    "Block the domain.",
    "Report the message to the security team.",
    "Warn users about the campaign."
  ]
}
```

---

## 7. MVP Features

### Must-Have Features

| Feature | Description |
|---|---|
| Threat Input Form | Allows user to paste email, URL, or message |
| IOC Extractor | Extracts URLs, domains, IPs, emails, and hashes |
| Threat Classifier | Classifies input as phishing, scam, malware, credential theft, benign, or suspicious |
| Risk Scoring Engine | Assigns numerical risk score from 0 to 100 |
| MITRE Mapper | Maps threat behavior to MITRE ATT&CK categories |
| Report Generator | Produces SOC-style incident report |
| AMD Runtime Panel | Shows AMD GPU, model, inference backend, latency, and tokens/sec |
| Demo Samples | Includes Kenyan/African scam examples |

### Nice-to-Have Features

| Feature | Description | Current Status |
|---|---|---|
| PDF Export | Export threat report as PDF | Implemented through `/api/report/pdf` |
| History Dashboard | Store previous analyses | Not implemented; feedback is stored locally only |
| Analyst Feedback | Allow analyst to mark output as correct/incorrect | Implemented through `/api/feedback` |
| Document Upload | Analyze uploaded PDFs or TXT files | Implemented for TXT, MD, EML, LOG, and PDF text extraction |
| Multi-Agent Mode | Separate agents for URL, email, IOC, MITRE, and report generation | Implemented as an orchestrated multi-agent-style pipeline |
| Threat Feed Enrichment | Add external open-source threat intelligence feeds | Implemented with local threat feed and heuristic enrichment; live external OSINT APIs remain future work |

---

## 8. Non-Goals for the Hackathon MVP

To keep the build clean, avoid the following in the first version:

- Full SIEM integration
- Real-time network packet inspection
- Complex malware sandboxing
- Full fine-tuning pipeline
- Large multi-tenant enterprise dashboard
- User authentication unless required
- Over-engineered microservices
- Too many input formats

The goal is a working, polished, demonstrable AI threat intelligence agent.

---

## 9. Recommended Technical Stack

| Layer | Recommended Tool |
|---|---|
| Frontend | Streamlit for fast MVP or Next.js for polished UI |
| Backend | FastAPI |
| LLM Serving | vLLM OpenAI-compatible endpoint |
| GPU Infrastructure | AMD Developer Cloud |
| GPU | AMD Instinct MI300X |
| AI Stack | ROCm + PyTorch |
| Model | Qwen2.5, Llama, Mistral, or another open-source instruct model |
| Database | SQLite for MVP, PostgreSQL for production |
| Vector Store | ChromaDB or FAISS if RAG is added |
| Reports | Markdown, copy-to-clipboard, and PDF export |
| Deployment | AMD cloud VM + GitHub repo |

### Recommended MVP Choice

For speed:

```text
Streamlit + FastAPI + vLLM + ROCm + AMD MI300X + SQLite
```

For a more polished final demo:

```text
Next.js + FastAPI + vLLM + ROCm + AMD MI300X + PostgreSQL
```

---

## 10. High-Level Architecture

```text
User
 |
 v
Frontend Dashboard
(Streamlit or Next.js)
 |
 v
FastAPI Backend
 |
 |--- IOC Extractor
 |--- Threat Classifier
 |--- Risk Scoring Engine
 |--- MITRE Mapper
 |--- Report Generator
 |--- AMD Runtime Metrics
 |
 v
LLM Inference Endpoint
(vLLM OpenAI-Compatible API)
 |
 v
AMD Developer Cloud
ROCm + AMD Instinct MI300X GPU
 |
 v
Open-Source LLM
```

---

## 11. Internal Processing Pipeline

```text
Input: Email, URL, SMS, or message text
 |
 v
1. Preprocessing
   - Normalize text
   - Remove unnecessary whitespace
   - Detect URLs and domains
   - Detect email addresses, IPs, hashes
 |
 v
2. IOC Extraction
   - URLs
   - Domains
   - IP addresses
   - Email addresses
   - File hashes
 |
 v
3. Threat Classification
   - Phishing
   - Scam
   - Credential theft
   - Malware
   - Business email compromise
   - Misinformation
   - Benign
 |
 v
4. Risk Scoring
   - Suspicious domain
   - Urgency language
   - Credential request
   - Financial lure
   - Impersonation
   - Unknown link
 |
 v
5. MITRE Mapping
   - Initial Access
   - Phishing
   - Credential Access
   - Command and Control
 |
 v
6. Report Generation
   - Executive summary
   - Technical analysis
   - IOCs
   - Severity
   - Recommended actions
 |
 v
Output: SOC-ready threat intelligence report
```

---

## 12. Recommended Project Folder Structure

```text
afrishield-ai/
│
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── schemas.py
│   │   ├── analyzer.py
│   │   ├── ioc_extractor.py
│   │   ├── risk_scoring.py
│   │   ├── mitre_mapper.py
│   │   ├── agents.py
│   │   ├── document_parser.py
│   │   ├── enrichment.py
│   │   ├── feedback.py
│   │   ├── report_generator.py
│   │   ├── pdf_export.py
│   │   ├── llm_client.py
│   │   └── runtime_metrics.py
│   │
│   ├── tests/
│   │   ├── test_api.py
│   │   ├── test_enrichment.py
│   │   ├── test_ioc_extractor.py
│   │   ├── test_llm_fallback.py
│   │   ├── test_mitre_mapper.py
│   │   ├── test_risk_scoring.py
│   │   └── test_analyzer.py
│   │
│   ├── requirements.txt
│   ├── .env.example
│   └── README.md
│
├── frontend/
│   ├── streamlit_app.py
│   ├── components/
│   └── assets/
│       └── afrishield-cyber-defence-logo.png
│
├── samples/
│   ├── kenya_phishing_examples.json
│   ├── benign_examples.json
│   ├── mpesa_scam_examples.json
│   ├── kra_scam_examples.json
│   └── university_portal_scam_examples.json
│
├── docs/
│   ├── architecture.md
│   ├── pitch.md
│   ├── demo_script.md
│   ├── judging_notes.md
│   └── threat_model.md
│
├── notebooks/
│   └── prompt_testing.ipynb
│
├── README.md
├── docker-compose.yml
├── .gitignore
└── LICENSE
```

---

## 13. Backend API Design

### 13.1 Health Check

```http
GET /health
```

Response:

```json
{
  "status": "ok",
  "service": "afrishield-ai"
}
```

### 13.2 Analyze Threat

```http
POST /api/analyze
```

Request:

```json
{
  "input_type": "email",
  "content": "Dear taxpayer, your KRA refund is ready. Verify your account at https://kra-refund-verify.com/login",
  "context": "Kenya"
}
```

Response:

```json
{
  "threat_type": "PHISHING",
  "severity": "HIGH",
  "risk_score": 88,
  "iocs": {
    "urls": ["https://kra-refund-verify.com/login"],
    "domains": ["kra-refund-verify.com"],
    "emails": [],
    "ips": [],
    "hashes": []
  },
  "mitre_mapping": [
    {
      "tactic": "Initial Access",
      "technique": "Phishing"
    }
  ],
  "summary": "The message impersonates a tax authority and attempts to steal credentials.",
  "recommended_actions": [
    "Do not click the link.",
    "Block the domain.",
    "Notify affected users."
  ],
  "report_markdown": "..."
}
```

### 13.3 Runtime Metrics

```http
GET /api/runtime
```

Response:

```json
{
  "gpu": "AMD Instinct MI300X",
  "backend": "vLLM",
  "framework": "ROCm + PyTorch",
  "model": "Qwen/Llama/Mistral",
  "latency_seconds": 2.4,
  "tokens_per_second": 45
}
```

### 13.4 Demo Samples

```http
GET /api/samples
```

Response:

```json
[
  {
    "name": "Fake KRA Refund Scam",
    "input_type": "sms",
    "content": "Dear taxpayer, your KRA refund of KES 18,450 is ready..."
  }
]
```

### 13.5 Analyst Feedback

```http
POST /api/feedback
```

Captures analyst review after a case has been analyzed.

```json
{
  "case_id": "case-123",
  "verdict": "correct",
  "rating": 4,
  "comments": "Good classification and useful next steps."
}
```

### 13.6 PDF Report Export

```http
POST /api/report/pdf
```

Converts a Markdown incident report into an `application/pdf` response.

```json
{
  "title": "AfriShield Cyber Defence Incident Report",
  "report_markdown": "# Incident Report\n\n..."
}
```

### 13.7 Document Text Extraction

```http
POST /api/document/extract
```

Accepts uploaded TXT, MD, EML, LOG, or PDF files and returns extracted text for the analyzer workflow.

---

## 14. Core Python Modules

### 14.1 `ioc_extractor.py`

Responsible for extracting:

- URLs
- Domains
- IP addresses
- Email addresses
- Hashes

Suggested implementation:

```python
import re
from urllib.parse import urlparse

URL_REGEX = r"https?://[^\s]+"
EMAIL_REGEX = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
HASH_REGEX = r"\b[a-fA-F0-9]{32,64}\b"

def extract_iocs(text: str) -> dict:
    urls = re.findall(URL_REGEX, text)
    emails = re.findall(EMAIL_REGEX, text)
    ips = re.findall(IP_REGEX, text)
    hashes = re.findall(HASH_REGEX, text)

    domains = []
    for url in urls:
        parsed = urlparse(url)
        if parsed.netloc:
            domains.append(parsed.netloc)

    return {
        "urls": list(set(urls)),
        "domains": list(set(domains)),
        "emails": list(set(emails)),
        "ips": list(set(ips)),
        "hashes": list(set(hashes))
    }
```

### 14.2 `risk_scoring.py`

Suggested scoring logic:

```python
def calculate_risk_score(text: str, iocs: dict, classification: str) -> int:
    score = 0
    lower_text = text.lower()

    risky_keywords = [
        "verify", "urgent", "suspended", "login", "password",
        "refund", "account", "confirm", "limited time",
        "click", "restore", "blocked", "security alert"
    ]

    financial_keywords = [
        "mpesa", "m-pesa", "bank", "kra", "refund",
        "payment", "loan", "grant", "donor"
    ]

    if iocs.get("urls"):
        score += 25

    if any(word in lower_text for word in risky_keywords):
        score += 25

    if any(word in lower_text for word in financial_keywords):
        score += 20

    if classification in ["PHISHING", "CREDENTIAL_THEFT", "MALWARE"]:
        score += 30

    return min(score, 100)
```

### 14.3 `mitre_mapper.py`

Suggested mapping:

```python
def map_to_mitre(threat_type: str) -> list:
    mappings = {
        "PHISHING": [
            {
                "tactic": "Initial Access",
                "technique": "Phishing"
            }
        ],
        "CREDENTIAL_THEFT": [
            {
                "tactic": "Credential Access",
                "technique": "Credential Harvesting"
            }
        ],
        "MALWARE": [
            {
                "tactic": "Execution",
                "technique": "User Execution"
            }
        ],
        "SCAM": [
            {
                "tactic": "Initial Access",
                "technique": "Social Engineering"
            }
        ],
        "BENIGN": []
    }

    return mappings.get(threat_type, [])
```

---

## 15. LLM Prompt Design

Use structured prompting to force consistent JSON output.

### Threat Classification Prompt

```text
You are AfriShield Cyber Defence, a cybersecurity threat intelligence assistant focused on African cyber defense.

Analyze the following input and classify the cyber threat.

Return only valid JSON using this schema:

{
  "threat_type": "PHISHING | SCAM | CREDENTIAL_THEFT | MALWARE | BUSINESS_EMAIL_COMPROMISE | MISINFORMATION | BENIGN | UNKNOWN_SUSPICIOUS",
  "severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "summary": "short explanation",
  "evidence": ["evidence item 1", "evidence item 2"],
  "recommended_actions": ["action 1", "action 2"]
}

Input:
{{USER_INPUT}}

Extracted IOCs:
{{IOCS}}

Context:
African/Kenyan cyber threat environment, including mobile money scams, KRA impersonation, fake university portals, banking phishing, fake job scams, and NGO grant scams.
```

### Report Generation Prompt

```text
You are AfriShield Cyber Defence, a SOC reporting assistant.

Generate a clear incident report in Markdown.

Include the following sections:

1. Executive Summary
2. Threat Classification
3. Risk Score
4. Indicators of Compromise
5. MITRE ATT&CK Mapping
6. Evidence
7. Recommended Response Actions
8. Analyst Notes

Threat Analysis:
{{THREAT_ANALYSIS}}

IOCs:
{{IOCS}}

MITRE Mapping:
{{MITRE_MAPPING}}

Risk Score:
{{RISK_SCORE}}
```

---

## 16. Risk Score Interpretation

| Score Range | Severity | Meaning |
|---|---|---|
| 0–20 | Low | Likely benign |
| 21–50 | Medium | Suspicious but not confirmed |
| 51–75 | High | Likely malicious |
| 76–100 | Critical | Strong evidence of malicious intent |

---

## 17. Localized Threat Examples

### 17.1 Fake KRA Refund Scam

```text
Dear taxpayer, your KRA refund of KES 18,450 is ready. Verify your iTax account immediately at https://kra-refund-verify.com/login to avoid expiry within 24 hours.
```

Expected classification:

```text
Threat Type: PHISHING
Severity: HIGH
Risk Score: 80+
```

### 17.2 Fake M-Pesa Suspension

```text
Your M-Pesa account has been temporarily suspended due to unusual activity. Confirm your identity at http://mpesa-secure-helpdesk.net to restore services.
```

Expected classification:

```text
Threat Type: CREDENTIAL_THEFT
Severity: HIGH
Risk Score: 80+
```

### 17.3 Fake University Portal

```text
Dear student, your fee statement has been updated. Login to confirm your payment status at https://tuk-studentportal-support.com before midnight.
```

Expected classification:

```text
Threat Type: PHISHING
Severity: HIGH
Risk Score: 75+
```

### 17.4 Benign Department Message

```text
Dear student, the department meeting will be held on Friday at 10:00 AM in Lab 3. Please come with your student ID.
```

Expected classification:

```text
Threat Type: BENIGN
Severity: LOW
Risk Score: 0–20
```

---

## 18. Frontend Design

The dashboard should be simple and judge-friendly.

### Main UI Sections

1. **Project Header**
   - AfriShield Cyber Defence
   - AMD MI300X-Powered Threat Intelligence Agent

2. **Threat Input Panel**
   - Text area
   - Input type selector: Email, URL, SMS, Social Message
   - Analyze button

3. **Risk Summary Cards**
   - Threat type
   - Severity
   - Risk score
   - Number of IOCs

4. **IOC Table**
   - Type
   - Value
   - Notes

5. **MITRE Mapping Table**
   - Tactic
   - Technique
   - Explanation

6. **Generated Report**
   - Markdown report
   - Copy button
   - Export button if available

7. **AMD Runtime Panel**
   - GPU
   - Backend
   - Model
   - Latency
   - Tokens/sec

---

## 19. AMD Runtime Panel

This is very important for the hackathon.

The dashboard should clearly show:

```text
GPU: AMD Instinct MI300X
Cloud: AMD Developer Cloud
Inference Backend: vLLM
Framework: ROCm + PyTorch
Model: Qwen/Llama/Mistral
Average Latency: 2.4 seconds
Tokens/sec: 45
```

Even if some metrics are estimated during early development, the final version should capture actual request timing from the backend.

Suggested implementation:

```python
import time

start = time.time()
response = call_llm(prompt)
end = time.time()

latency = round(end - start, 2)
```

---

## 20. Clean Build Approach

### Principle 1: Build the pipeline before the UI

Start with a working backend function:

```python
analyze_threat(input_text)
```

Only build the UI after the backend returns structured results.

### Principle 2: Use rules plus LLM

Do not depend entirely on the LLM.

Use:

- Regex for IOC extraction
- Rules for risk scoring
- Static mapping for MITRE
- LLM for reasoning and report generation

### Principle 3: Keep outputs structured

Use JSON for machine-readable output.

Use Markdown for human-readable reports.

### Principle 4: Make AMD visible

Your README, UI, and demo must clearly show that inference runs on AMD Developer Cloud.

### Principle 5: Prepare demo samples early

Do not wait until the last day to create test cases.

---

## 21. 5-Day Build Plan

### Day 1: Setup and Skeleton

Goals:

- Create GitHub repository.
- Set up backend and frontend folders.
- Create FastAPI backend.
- Create Streamlit or Next.js frontend.
- Connect to AMD-hosted vLLM endpoint.
- Test one LLM request.

Deliverables:

- `/health` endpoint working.
- Basic frontend running.
- One prompt returns a response from the model.

---

### Day 2: Core Analysis Engine

Goals:

- Build IOC extractor.
- Build threat classifier.
- Build risk scoring engine.
- Return structured JSON.

Deliverables:

- `/api/analyze` endpoint working.
- Sample phishing message classified correctly.
- IOCs extracted correctly.

---

### Day 3: MITRE Mapping and Report Generation

Goals:

- Add MITRE ATT&CK mapping.
- Add Markdown report generation.
- Add demo samples.
- Improve prompt quality.

Deliverables:

- Generated SOC report.
- Risk score and severity shown.
- MITRE mapping table working.

---

### Day 4: UI Polish and AMD Proof

Goals:

- Improve dashboard layout.
- Add AMD runtime panel.
- Add latency measurement.
- Add tokens/sec if available.
- Add copy/export report option.
- Add 3–5 strong demo samples.

Deliverables:

- Clean judge-ready dashboard.
- AMD usage clearly visible.
- Demo flow works smoothly.

---

### Day 5: Submission

Goals:

- Record demo video.
- Finalize README.
- Add architecture diagram.
- Add screenshots.
- Add setup instructions.
- Push final code to GitHub.
- Submit hackathon project.

Deliverables:

- GitHub repository.
- Demo video.
- README.
- Architecture diagram.
- Working hosted or local demo.

---

## 22. Development Setup

### 22.1 Clone Repository

```bash
git clone https://github.com/your-username/afrishield-ai.git
cd afrishield-ai
```

### 22.2 Backend Setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### 22.3 Frontend Setup with Streamlit

```bash
cd frontend
streamlit run streamlit_app.py
```

### 22.4 Environment Variables

Create a `.env` file:

```env
APP_NAME=AfriShield Cyber Defence
LLM_API_BASE=http://your-amd-vllm-endpoint:8000/v1
LLM_API_KEY=not-required-or-your-key
LLM_MODEL=qwen-or-llama-model-name
RUNTIME_GPU=AMD Instinct MI300X
RUNTIME_BACKEND=vLLM
RUNTIME_FRAMEWORK=ROCm + PyTorch
```

---

## 23. Backend Requirements

Example `requirements.txt`:

```text
fastapi
uvicorn
pydantic
python-dotenv
requests
tldextract
openai
pytest
```

If using Streamlit:

```text
streamlit
pandas
```

If using PDF export later:

```text
reportlab
markdown
weasyprint
```

---

## 24. Example FastAPI Entry Point

```python
from fastapi import FastAPI
from pydantic import BaseModel

from app.analyzer import analyze_threat

app = FastAPI(title="AfriShield Cyber Defence")

class AnalyzeRequest(BaseModel):
    input_type: str
    content: str
    context: str = "Kenya"

@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "AfriShield Cyber Defence"
    }

@app.post("/api/analyze")
def analyze(request: AnalyzeRequest):
    return analyze_threat(
        input_type=request.input_type,
        content=request.content,
        context=request.context
    )
```

---

## 25. Example Streamlit UI

```python
import streamlit as st
import requests

st.set_page_config(
    page_title="AfriShield Cyber Defence",
    layout="wide"
)

st.title("AfriShield Cyber Defence")
st.caption("AMD MI300X-Powered Autonomous Threat Intelligence Agent")

input_type = st.selectbox(
    "Input Type",
    ["email", "url", "sms", "social_message"]
)

content = st.text_area(
    "Paste suspicious content here",
    height=200
)

if st.button("Analyze Threat"):
    response = requests.post(
        "http://localhost:8000/api/analyze",
        json={
            "input_type": input_type,
            "content": content,
            "context": "Kenya"
        }
    )

    if response.status_code == 200:
        result = response.json()

        col1, col2, col3 = st.columns(3)
        col1.metric("Threat Type", result.get("threat_type"))
        col2.metric("Severity", result.get("severity"))
        col3.metric("Risk Score", result.get("risk_score"))

        st.subheader("Indicators of Compromise")
        st.json(result.get("iocs"))

        st.subheader("MITRE ATT&CK Mapping")
        st.json(result.get("mitre_mapping"))

        st.subheader("Incident Report")
        st.markdown(result.get("report_markdown", ""))

    else:
        st.error("Analysis failed.")
```

---

## 26. Testing Strategy

### Unit Tests

Test:

- IOC extraction
- Risk scoring
- MITRE mapping
- JSON response structure
- Benign input detection

### Sample Test Cases

| Test Case | Expected Result |
|---|---|
| Fake KRA link | High-risk phishing |
| Fake M-Pesa suspension | High-risk credential theft |
| Fake university portal | High-risk phishing |
| Normal department message | Low-risk benign |
| Message with no links but urgent payment request | Medium/high scam |

### Example Pytest

```python
from app.ioc_extractor import extract_iocs

def test_extract_url():
    text = "Click https://fake-login.com now"
    result = extract_iocs(text)

    assert "https://fake-login.com" in result["urls"]
    assert "fake-login.com" in result["domains"]
```

---

## 27. Evaluation Metrics

Use simple measurable indicators:

| Metric | Target |
|---|---|
| Analysis latency | Under 5 seconds for short inputs |
| IOC extraction accuracy | Correctly extracts URLs/domains/emails |
| JSON validity | 100% valid API response |
| Demo success rate | 3/3 demo cases work |
| Report usefulness | Clear executive and technical sections |
| AMD usage visibility | Clearly shown in UI and README |

---

## 28. Demo Flow

### Demo Script

1. Open AfriShield Cyber Defence dashboard.
2. Show AMD Runtime Panel.
3. Paste fake KRA phishing message.
4. Click **Analyze Threat**.
5. Show risk score and threat type.
6. Show extracted IOC domain.
7. Show MITRE mapping.
8. Show generated SOC report.
9. Repeat quickly with fake M-Pesa scam.
10. Show benign message to prove the system does not classify everything as malicious.

### Demo Message 1

```text
Dear taxpayer, your KRA refund of KES 18,450 is ready. Verify your iTax account immediately at https://kra-refund-verify.com/login to avoid expiry within 24 hours.
```

### Demo Message 2

```text
Your M-Pesa account has been temporarily suspended due to unusual activity. Confirm your identity at http://mpesa-secure-helpdesk.net to restore services.
```

### Demo Message 3

```text
Dear student, the department meeting will be held on Friday at 10:00 AM in Lab 3. Please come with your student ID.
```

---

## 29. README Checklist

Your GitHub README should include:

- Project name
- Problem statement
- Solution overview
- Features
- Architecture diagram
- AMD Developer Cloud usage
- Tech stack
- Setup instructions
- API documentation
- Demo samples
- Screenshots
- Future improvements
- Team/member information
- License

---

## 30. Submission Checklist

Before submission, confirm:

- [ ] App runs successfully.
- [ ] Backend API works.
- [ ] Frontend connects to backend.
- [ ] LLM endpoint works on AMD infrastructure.
- [ ] AMD Runtime Panel is visible.
- [ ] At least 3 demo samples work.
- [ ] IOC extraction works.
- [ ] Risk score works.
- [ ] MITRE mapping works.
- [ ] Report generation works.
- [ ] README is complete.
- [ ] Architecture diagram is included.
- [ ] Demo video is recorded.
- [ ] GitHub repo is clean.
- [ ] `.env` secrets are not committed.
- [ ] `.env.example` is included.
- [ ] Requirements file is included.
- [ ] Screenshots are added.

---

## 31. Future Improvements

After the hackathon, AfriShield Cyber Defence can be expanded into:

1. Full SOC triage assistant.
2. Email gateway integration.
3. Browser extension for suspicious link checking.
4. WhatsApp/SMS scam detection bot.
5. Threat intelligence feed integration.
6. Kenyan/African scam dataset creation.
7. Fine-tuned cyber threat classification model.
8. Multi-language support for English, Kiswahili, and Sheng.
9. SIEM integration with Wazuh, Elastic, or Splunk.
10. Cybersecurity training lab for universities.

---

## 32. Final Build Strategy

The cleanest build path is:

```text
Step 1: Build backend pipeline.
Step 2: Add IOC extraction.
Step 3: Add LLM classification.
Step 4: Add risk scoring.
Step 5: Add MITRE mapping.
Step 6: Add report generation.
Step 7: Build frontend.
Step 8: Add AMD runtime proof.
Step 9: Polish demo.
Step 10: Submit.
```

Do not start with complex UI or fine-tuning. Start with the analysis engine.

---

## 33. Final Project Statement

AfriShield Cyber Defence is a practical, localized, AMD-powered cyber defense agent that helps African organizations turn suspicious digital content into structured threat intelligence. By combining rule-based IOC extraction, LLM reasoning, risk scoring, MITRE mapping, and SOC-style reporting, the system provides a fast and accessible first layer of cyber analysis for institutions that need stronger digital protection but may lack mature security operations capacity.

The hackathon MVP should prove one thing clearly:

> Given a suspicious message or URL, AfriShield Cyber Defence can analyze it, explain the risk, extract evidence, and recommend action using AI inference accelerated on AMD infrastructure.
