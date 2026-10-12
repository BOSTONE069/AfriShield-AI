"""API contract tests without a live HTTP server."""

import os

os.environ["USE_LLM"] = "false"
os.environ["USE_LLM_REPORTS"] = "false"

from backend.app.document_parser import extract_document_text
from backend.app.feedback import load_feedback
from backend.app.main import analyze, export_pdf, feedback, health_check, readiness_check, runtime
from backend.app.schemas import AnalyzeRequest, FeedbackRequest, ReportExportRequest
from backend.app.security import Principal


def test_health_endpoint():
    """The health endpoint should confirm the service is reachable."""
    assert health_check()["status"] == "ok"


def test_readiness_endpoint_reports_analysis_mode():
    """Readiness should distinguish service health from optional model state."""
    body = readiness_check()

    assert body["status"] == "ready"
    assert body["analysis_mode"] in {"deterministic", "llm_enriched"}


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
    assert "incident_ticket" in body["report_variants"]
    assert body["confidence"] in {"LOW", "MEDIUM", "HIGH"}
    assert body["evidence_strength"] in {"LOW", "MEDIUM", "HIGH"}
    assert body["score_factors"]
    assert body["decision_details"]["policy"] == "deterministic_minimum_v1"
    assert sum(factor["points"] for factor in body["score_factors"]) == body["risk_score"]


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
            original_content="Normal department meeting",
            original_input_type="text",
            original_context="Kenya",
            analysis=analysis,
        ),
        Principal("reviewer-test", "analyst"),
    )

    assert response["status"] == "saved"
    stored = next(record for record in load_feedback() if record["feedback_id"] == response["feedback_id"])
    assert stored["reviewer_identity"] == "reviewer-test"
    assert stored["component_versions"]["ruleset"]
    assert stored["original_score_components"] == analysis["score_factors"]
