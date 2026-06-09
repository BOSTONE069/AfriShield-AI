"""Tests for risk score and severity behavior."""

from backend.app.risk_scoring import calculate_risk_score, severity_from_score


def test_high_risk_phishing_scores_high():
    """A KRA-style phishing link should score in the critical range."""
    text = "Verify your KRA refund at https://kra-refund-verify.com/login within 24 hours."
    iocs = {"urls": ["https://kra-refund-verify.com/login"], "domains": ["kra-refund-verify.com"]}

    score = calculate_risk_score(text, iocs, "PHISHING", ["tax authority impersonation", "external link"])

    assert score >= 75
    assert severity_from_score(score) == "CRITICAL"


def test_benign_is_capped_low():
    """Benign classifications should not become high-risk from stray keywords."""
    text = "The department meeting will be held on Friday at 10:00 AM."
    iocs = {"urls": [], "domains": [], "ips": [], "hashes": []}

    assert calculate_risk_score(text, iocs, "BENIGN", []) <= 20
