"""Tests for local threat-feed enrichment."""

from backend.app.enrichment import enrich_iocs


def test_known_demo_domain_is_flagged_malicious():
    """Bundled demo phishing domains should match the local feed."""
    findings = enrich_iocs({"domains": ["kra-refund-verify.com"], "urls": [], "ips": [], "hashes": []})

    assert any(item["verdict"] == "malicious" for item in findings)


def test_url_heuristic_flags_verify_link():
    """Account-action URLs should produce heuristic enrichment."""
    findings = enrich_iocs({"domains": [], "urls": ["https://example.com/verify"], "ips": [], "hashes": []})

    assert any(item["observable_type"] == "url" and item["verdict"] == "suspicious" for item in findings)
