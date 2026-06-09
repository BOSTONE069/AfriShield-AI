"""API contract tests without a live HTTP server."""

import os

os.environ["USE_LLM"] = "false"
os.environ["USE_LLM_REPORTS"] = "false"

from backend.app.document_parser import extract_document_text
from backend.app.main import analyze, export_pdf, feedback, health_check, runtime
from backend.app.schemas import AnalyzeRequest, FeedbackRequest, ReportExportRequest


def test_health_endpoint():
    """The health endpoint should confirm the service is reachable."""
    assert health_check()["status"] == "ok"


def test_runtime_endpoint_shape():
    """Runtime metadata should include model/backend fields for the dashboard."""
    body = runtime()

    assert {"gpu", "backend", "model", "llm_enabled"}.issubset(body)


def test_analyze_endpoint_includes_enrichment_and_mitre_ids():
    """Analysis API should return enriched IOCs and richer MITRE mappings."""
    body = analyze(
        AnalyzeRequest(
            input_type="sms",
            context="Kenya",
            content="Verify your KRA refund at https://kra-refund-verify.com/login",
        )
    )

    assert body["enrichment"]
    assert body["mitre_mapping"][0]["technique_id"]


def test_pdf_export_endpoint_returns_pdf():
    """Markdown reports should be convertible to application/pdf."""
    response = export_pdf(ReportExportRequest(report_markdown="# Test\n\nBody"))

    assert response.media_type == "application/pdf"
    assert response.body.startswith(b"%PDF")


def test_document_extract_txt_upload():
    """TXT uploads should be extracted into plain text."""
    assert extract_document_text("sample.txt", b"Suspicious text") == "Suspicious text"


def test_feedback_endpoint_saves_review():
    """Analyst feedback should be accepted by the API."""
    analysis = analyze(AnalyzeRequest(input_type="text", context="Kenya", content="Normal department meeting"))
    response = feedback(
        FeedbackRequest(
            case_id="AFS-TEST",
            verdict="correct",
            rating=5,
            analyst_note="ok",
            analysis=analysis,
        )
    )

    assert response["status"] == "saved"
