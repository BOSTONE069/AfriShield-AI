"""Hardened FastAPI entry point for AfriShield Cyber Defence."""

from __future__ import annotations

import os
import re
import time
import uuid

from fastapi import Depends, FastAPI, File, HTTPException, Request, Response, UploadFile, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from backend.app.analyzer import analyze_threat
from backend.app.audit import write_audit_event
from backend.app.config import get_settings
from backend.app.document_parser import (
    DocumentParseError,
    extract_document_text_controlled,
    validate_upload_type,
)
from backend.app.feedback import (
    FeedbackStorageError,
    encryption_is_configured,
    feedback_metrics,
    purge_expired_feedback,
    save_feedback,
)
from backend.app.jobs import AnalysisQueueFullError, get_job_queue
from backend.app.pdf_export import markdown_to_pdf_bytes
from backend.app.runtime_metrics import runtime_payload
from backend.app.samples import load_samples
from backend.app.schemas import (
    AnalysisJobAccepted,
    AnalysisJobResponse,
    AnalyzeRequest,
    AnalyzeResponse,
    FeedbackRequest,
    FeedbackResponse,
    ReportExportRequest,
)
from backend.app.security import (
    Principal,
    RateLimitMiddleware,
    require_admin,
    require_analyst,
    require_viewer,
    security_is_configured,
)

settings = get_settings()
app = FastAPI(title=settings.app_name)

_cors_origins = os.getenv("AFRISHIELD_CORS_ORIGINS", "http://localhost:8501").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in _cors_origins],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Request-ID"],
    expose_headers=["X-Request-ID"],
)
app.add_middleware(RateLimitMiddleware)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach request IDs and emit body-free audit metadata for every request."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        supplied = request.headers.get("x-request-id", "")
        request_id = supplied if re.fullmatch(r"[A-Za-z0-9._-]{8,64}", supplied) else str(uuid.uuid4())
        request.state.request_id = request_id
        started = time.perf_counter()
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        principal = getattr(request.state, "principal", None)
        write_audit_event(
            {
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                "actor_id": getattr(principal, "key_id", "anonymous"),
                "actor_role": getattr(principal, "role", "anonymous"),
            }
        )
        return response


app.add_middleware(RequestContextMiddleware)


class TechnologyHeaderMiddleware(BaseHTTPMiddleware):
    """Remove application-provided technology banners from responses."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        for header in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"):
            if header in response.headers:
                del response.headers[header]
        return response


app.add_middleware(TechnologyHeaderMiddleware)


def _error_response(request: Request, status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "request_id": getattr(request.state, "request_id", "unknown"),
            }
        },
    )


@app.exception_handler(HTTPException)
async def http_error_handler(request: Request, exc: HTTPException) -> JSONResponse:
    codes = {
        401: "authentication_required",
        403: "authorization_denied",
        404: "not_found",
        408: "parser_timeout",
        409: "sync_analysis_disabled",
        413: "upload_too_large",
        415: "unsupported_media_type",
        422: "invalid_request",
        429: "rate_limit_exceeded",
        503: "service_unavailable",
    }
    detail = exc.detail if isinstance(exc.detail, str) else "Request could not be completed."
    return _error_response(request, exc.status_code, codes.get(exc.status_code, "http_error"), detail)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, _exc: RequestValidationError) -> JSONResponse:
    return _error_response(request, 422, "validation_error", "The request payload failed validation.")


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, _exc: Exception) -> JSONResponse:
    return _error_response(request, 500, "internal_error", "The request failed. Use the request ID for support.")


@app.get("/health")
def health_check() -> dict:
    return {"status": "ok", "service": settings.app_name}


@app.get("/ready")
def readiness_check() -> dict:
    llm_configured = (
        not settings.use_llm or settings.llm_provider == "local_transformers" or bool(settings.llm_api_base)
    )
    security_configured = security_is_configured()
    encryption_configured = encryption_is_configured()
    legacy_plaintext_feedback = settings.legacy_feedback_path.exists()
    ready = llm_configured and security_configured and encryption_configured and not legacy_plaintext_feedback
    return {
        "status": "ready" if ready else "not_ready",
        "service": settings.app_name,
        "analysis_mode": "llm_enriched" if settings.use_llm and llm_configured else "deterministic",
        "llm_configured": llm_configured,
        "security_configured": security_configured,
        "encryption_configured": encryption_configured,
        "legacy_plaintext_feedback": legacy_plaintext_feedback,
    }


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest, _principal: Principal = Depends(require_analyst)) -> dict:
    """Compatibility endpoint; production should use the bounded job API."""
    if not settings.allow_sync_analysis:
        raise HTTPException(status_code=409, detail="Synchronous analysis is disabled; use /api/analysis/jobs.")
    return analyze_threat(
        request.input_type,
        request.content,
        request.context,
        remote_processing_consent=request.remote_processing_consent,
    )


@app.post("/api/analysis/jobs", response_model=AnalysisJobAccepted, status_code=status.HTTP_202_ACCEPTED)
def submit_analysis_job(request: AnalyzeRequest, principal: Principal = Depends(require_analyst)) -> dict:
    """Queue analysis on bounded background workers and return immediately."""
    try:
        job = get_job_queue().submit(
            principal.key_id,
            request.input_type,
            request.content,
            request.context,
            request.remote_processing_consent,
        )
    except AnalysisQueueFullError as exc:
        raise HTTPException(status_code=429, detail="Analysis queue is full; retry later.") from exc
    return {"job_id": job.job_id, "status": "queued"}


@app.get("/api/analysis/jobs/{job_id}", response_model=AnalysisJobResponse)
def analysis_job(job_id: str, principal: Principal = Depends(require_viewer)) -> dict:
    job = get_job_queue().get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Analysis job was not found or has expired.")
    if principal.role != "admin" and principal.key_id != job.owner_id:
        raise HTTPException(status_code=403, detail="This analysis job belongs to another caller.")
    return job.public()


@app.get("/api/runtime")
def runtime(_principal: Principal = Depends(require_viewer)) -> dict:
    return runtime_payload()


@app.get("/api/samples")
def samples(_principal: Principal = Depends(require_viewer)) -> list[dict]:
    return load_samples()


@app.post("/api/feedback", response_model=FeedbackResponse)
def feedback(request: FeedbackRequest, principal: Principal = Depends(require_analyst)) -> dict:
    try:
        payload = request.model_dump(mode="json")
        payload.update(
            {
                "reviewer_identity": principal.key_id,
                "reviewer_role": principal.role,
                "component_versions": payload["analysis"]["component_versions"],
                "original_score_components": payload["analysis"]["score_factors"],
                "original_threat_type": payload["analysis"]["threat_type"],
                "original_severity": payload["analysis"]["severity"],
                "original_risk_score": payload["analysis"]["risk_score"],
            }
        )
        return save_feedback(payload)
    except FeedbackStorageError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.delete("/api/admin/retention")
def enforce_retention(_principal: Principal = Depends(require_admin)) -> dict:
    return {"expired_feedback_deleted": purge_expired_feedback()}


@app.get("/api/admin/feedback/metrics")
def feedback_improvement_metrics(_principal: Principal = Depends(require_admin)) -> dict:
    try:
        return feedback_metrics()
    except FeedbackStorageError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/report/pdf")
def export_pdf(request: ReportExportRequest, _principal: Principal = Depends(require_viewer)) -> Response:
    pdf_bytes = markdown_to_pdf_bytes(request.title, request.report_markdown)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="afrishield-incident-report.pdf"'},
    )


@app.post("/api/document/extract")
def document_extract(file: UploadFile = File(...), _principal: Principal = Depends(require_analyst)) -> dict:
    """Stream an allow-listed upload and parse it inside a restricted subprocess."""
    content = bytearray()
    while chunk := file.file.read(min(64 * 1024, settings.max_upload_bytes + 1)):
        content.extend(chunk)
        if len(content) > settings.max_upload_bytes:
            raise HTTPException(status_code=413, detail=f"Upload exceeds {settings.max_upload_bytes} bytes.")
    try:
        validate_upload_type(file.filename or "", file.content_type, bytes(content[:4096]))
        text = extract_document_text_controlled(
            file.filename or "uploaded-document",
            bytes(content),
            max_pages=settings.max_pdf_pages,
            max_chars=settings.max_extracted_chars,
            timeout_seconds=settings.max_parser_seconds,
            memory_limit_mb=settings.max_parser_memory_mb,
        )
    except DocumentParseError as exc:
        error_status = 408 if exc.code == "parser_timeout" else 415 if "type" in exc.code else 422
        raise HTTPException(status_code=error_status, detail=str(exc)) from exc
    return {"filename": file.filename, "content": text}
