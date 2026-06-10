# Threat Model

This document describes the security assumptions and risks for the AfriShield Cyber Defence MVP.

## Assets

- Uploaded evidence text and suspicious messages.
- Extracted indicators of compromise.
- Generated reports.
- Analyst feedback in `data/feedback.jsonl`.
- Runtime configuration in `backend/.env`.
- Local model files and any remote inference endpoint credentials.

## Users

- Common users checking suspicious messages.
- Analysts reviewing advanced details and reports.
- Demo operators running the app locally or on cloud infrastructure.
- Developers maintaining the codebase.

## Trust Boundaries

```text
Browser / Streamlit dashboard
        |
        v
FastAPI backend
        |
        |-- Local files: samples, feedback, uploaded document parsing
        |-- Local model runtime through Transformers
        |-- Optional remote OpenAI-compatible vLLM endpoint
```

The frontend and backend are trusted during local demo use. Uploaded content, pasted messages, extracted URLs, and model responses are untrusted.

## Key Risks

| Risk | Impact | Current Mitigation |
|---|---|---|
| Malicious uploaded document | Parser crash or unsafe content handling | Uploads are parsed as text only; no file execution is performed. |
| Prompt injection in evidence | LLM may produce misleading enrichment | Deterministic pipeline remains authoritative; LLM output is enrichment only. |
| Slow local inference | User sees timeout or failed analysis | `USE_LLM_REPORTS=false` avoids a second model call; deterministic fallback remains available. |
| Sensitive evidence in feedback | Local file may contain investigation details | Feedback is stored locally; production should add access control and retention policy. |
| Incorrect classification | User may trust wrong advice | UI supports analyst feedback and shows evidence, indicators, and reasoning. |
| Unverified external endpoint | Remote inference could leak data | Use trusted AMD/vLLM endpoints and avoid sending sensitive evidence to unknown services. |
| Missing authentication | Unauthorized local access in shared environments | MVP is intended for local/demo use; production needs authentication. |

## Non-Goals For MVP Security

- User authentication and role-based access control.
- Multi-tenant data isolation.
- SIEM integration.
- Malware sandboxing.
- Live external OSINT API calls.
- Long-term case history database.

## Production Hardening

Before production deployment:

- Add authentication and authorization.
- Store feedback and case history in a database with retention controls.
- Add file size, file type, and parsing limits at the API layer.
- Add request logging without storing unnecessary sensitive content.
- Add rate limiting for public deployments.
- Use HTTPS and secret management for model endpoint credentials.
- Review privacy requirements before sending evidence to remote LLM endpoints.
