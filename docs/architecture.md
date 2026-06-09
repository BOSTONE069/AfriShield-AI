# AfriShield AI Architecture

```text
Streamlit Dashboard
        |
        v
FastAPI Backend
        |
        |-- IOC Extractor
        |-- Rule-Based Threat Classifier
        |-- Risk Scoring Engine
        |-- MITRE Mapper
        |-- Report Generator
        |-- Optional AMD vLLM Client
        |
        v
AMD Developer Cloud / ROCm / MI300X / vLLM
```

The MVP works without an LLM endpoint so demos and tests remain reliable. When `USE_LLM=true` and `LLM_API_BASE` points to an OpenAI-compatible vLLM endpoint, the backend uses the AMD-hosted model to enrich classification evidence and recommended actions.
