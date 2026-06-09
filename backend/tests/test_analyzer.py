import os

os.environ["USE_LLM"] = "false"

from backend.app.analyzer import analyze_threat


def test_analyzer_returns_structured_phishing_result():
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
    result = analyze_threat(
        "email",
        "Dear student, the department meeting will be held on Friday at 10:00 AM in Lab 3.",
        "Kenya",
    )

    assert result["threat_type"] == "BENIGN"
    assert result["severity"] == "LOW"
