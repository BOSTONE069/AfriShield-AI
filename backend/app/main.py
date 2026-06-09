"""FastAPI entry point for AfriShield AI."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.analyzer import analyze_threat
from backend.app.config import get_settings
from backend.app.runtime_metrics import runtime_payload
from backend.app.schemas import AnalyzeRequest, AnalyzeResponse
from backend.app.samples import load_samples


settings = get_settings()
app = FastAPI(title=settings.app_name)

# Streamlit and local demos can run from different ports, so the MVP allows
# cross-origin requests. Lock this down before deploying in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health_check() -> dict:
    """Lightweight readiness check for scripts, dashboards, and deployments."""
    return {"status": "ok", "service": settings.app_name}


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest) -> dict:
    """Analyze one submitted message, URL, email, or social post."""
    return analyze_threat(request.input_type, request.content, request.context)


@app.get("/api/runtime")
def runtime() -> dict:
    """Expose model/backend/latency metadata for the runtime panel."""
    return runtime_payload()


@app.get("/api/samples")
def samples() -> list[dict]:
    """Return bundled demo cases used by the dashboard sample queue."""
    return load_samples()
