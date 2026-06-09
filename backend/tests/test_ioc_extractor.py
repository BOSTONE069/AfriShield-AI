"""Tests for deterministic IOC extraction."""

from backend.app.ioc_extractor import extract_iocs


def test_extracts_url_domain_email_ip_and_hash():
    """Structured observables should be detected from mixed message text."""
    text = (
        "Contact admin@bank.co.ke and visit https://fake-login.co.ke/path. "
        "Host 192.168.1.10 served d41d8cd98f00b204e9800998ecf8427e."
    )

    result = extract_iocs(text)

    assert "https://fake-login.co.ke/path" in result["urls"]
    assert "fake-login.co.ke" in result["domains"]
    assert "admin@bank.co.ke" in result["emails"]
    assert "192.168.1.10" in result["ips"]
    assert "d41d8cd98f00b204e9800998ecf8427e" in result["hashes"]


def test_extracts_bare_domain():
    """Domains without a URL scheme should still be treated as IOCs."""
    result = extract_iocs("Open kra-refund-verify.com now")

    assert "kra-refund-verify.com" in result["domains"]
