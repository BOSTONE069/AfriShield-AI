"""Tests for audience-specific report generation."""

from backend.app.report_generator import generate_report_bundle


def test_report_bundle_contains_all_supported_formats():
    """One analysis should produce executive, SOC, user, and ticket reports."""
    reports = generate_report_bundle(
        input_type="sms",
        context="Kenya",
        threat_type="PHISHING",
        severity="HIGH",
        risk_score=88,
        iocs={
            "urls": ["https://kra-refund-verify.com/login"],
            "domains": ["kra-refund-verify.com"],
            "emails": [],
            "ips": [],
            "hashes": [],
        },
        enrichment=[],
        mitre_mapping=[{"tactic": "Initial Access", "technique": "Phishing", "technique_id": "T1566"}],
        summary="The message impersonates a tax authority.",
        evidence=["Contains a suspicious refund lure."],
        recommended_actions=["Do not click the link.", "Block the domain."],
        confidence="HIGH",
        evidence_strength="HIGH",
        score_factors=[
            {
                "name": "URL detected",
                "points": 20,
                "source": "deterministic",
                "description": "A URL was extracted.",
            }
        ],
        decision_details={"conflicts": []},
    )

    assert "Executive Summary" in reports["executive_summary"]
    assert "Technical SOC Report" in reports["technical_soc_report"]
    assert "User Advisory" in reports["user_advisory"]
    assert "Incident Ticket" in reports["incident_ticket"]
    assert "- [ ] Do not click the link." in reports["incident_ticket"]
    assert "Decision Confidence: HIGH" in reports["technical_soc_report"]
    assert "URL detected: +20 points" in reports["technical_soc_report"]
