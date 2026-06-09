"""Integration-style tests for the analyzer pipeline."""

import os

# Unit tests should be fast and deterministic, so they exercise rules mode
# instead of loading the local language model.
os.environ["USE_LLM"] = "false"

from backend.app.analyzer import analyze_threat


def test_analyzer_returns_structured_phishing_result():
    """A localized phishing lure should produce a complete malicious report."""
    result = analyze_threat(
        "sms",
        "Dear taxpayer, your KRA refund is ready. Verify your account at https://kra-refund-verify.com/login",
        "Kenya",
    )

    assert result["threat_type"] in {"PHISHING", "CREDENTIAL_THEFT"}
    assert result["risk_score"] >= 75
    assert "kra-refund-verify.com" in result["iocs"]["domains"]
    assert result["mitre_mapping"]
    assert "Incident Report" in result["report_markdown"]


def test_analyzer_handles_benign_message():
    """A normal department message should remain low severity and benign."""
    result = analyze_threat(
        "email",
        "Dear student, the department meeting will be held on Friday at 10:00 AM in Lab 3.",
        "Kenya",
    )

    assert result["threat_type"] == "BENIGN"
    assert result["severity"] == "LOW"
