"""Local threat-feed and heuristic enrichment for extracted IOCs.

The MVP does not call live OSINT services by default because demos should work
offline and avoid leaking submitted evidence. Instead, it checks a bundled local
feed plus clear heuristics. A future production version can add VirusTotal,
URLhaus, MISP, OpenPhish, or other external feeds behind this same interface.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LOCAL_FEED_PATH = ROOT / "samples" / "threat_feed.json"


def enrich_iocs(iocs: dict) -> list[dict]:
    """Return enrichment findings for domains, URLs, IPs, and hashes."""
    feed = _load_local_feed()
    findings: list[dict] = []

    for domain in iocs.get("domains", []):
        normalized = domain.lower()
        if normalized in feed.get("domains", {}):
            findings.append(_finding("domain", domain, "Local threat feed", "malicious", "high", feed["domains"][normalized]))
        findings.extend(_domain_heuristics(domain))

    for url in iocs.get("urls", []):
        if any(marker in url.lower() for marker in ("login", "verify", "secure", "restore", "refund")):
            findings.append(
                _finding(
                    "url",
                    url,
                    "URL heuristic",
                    "suspicious",
                    "medium",
                    "URL contains account-action wording commonly used in phishing lures.",
                )
            )

    for ip in iocs.get("ips", []):
        findings.append(_ip_finding(ip))

    for file_hash in iocs.get("hashes", []):
        if file_hash.lower() in feed.get("hashes", {}):
            findings.append(_finding("hash", file_hash, "Local threat feed", "malicious", "high", feed["hashes"][file_hash.lower()]))

    return _dedupe_findings(findings)


def _load_local_feed() -> dict:
    """Load a tiny local feed used by tests and offline demos."""
    if not LOCAL_FEED_PATH.exists():
        return {"domains": {}, "hashes": {}}
    with LOCAL_FEED_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _domain_heuristics(domain: str) -> list[dict]:
    """Flag obvious brand-impersonation and risky-domain patterns."""
    lower_domain = domain.lower()
    findings = []
    brand_markers = {
        "kra": "Domain references KRA/tax branding and may impersonate a public service.",
        "mpesa": "Domain references M-Pesa/mobile money branding.",
        "sacco": "Domain references SACCO/financial services branding.",
        "studentportal": "Domain references a student portal lure.",
        "donor": "Domain references donor/grant language common in NGO scams.",
    }
    for marker, details in brand_markers.items():
        if marker in lower_domain.replace("-", ""):
            findings.append(_finding("domain", domain, "Brand heuristic", "suspicious", "medium", details))

    if lower_domain.endswith((".site", ".online", ".biz")):
        findings.append(
            _finding(
                "domain",
                domain,
                "TLD heuristic",
                "suspicious",
                "low",
                "Domain uses a low-cost TLD often seen in short-lived phishing infrastructure.",
            )
        )
    return findings


def _ip_finding(ip: str) -> dict:
    """Classify IP addresses as private/reserved/public for triage context."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return _finding("ip", ip, "IP parser", "unknown", "low", "IP address could not be parsed.")
    if address.is_private:
        return _finding("ip", ip, "IP parser", "informational", "low", "Private IP address; likely internal context.")
    if address.is_reserved or address.is_loopback:
        return _finding("ip", ip, "IP parser", "informational", "low", "Reserved or loopback IP address.")
    return _finding("ip", ip, "IP parser", "observable", "medium", "Public IP address should be enriched with external TI in production.")


def _finding(observable_type: str, value: str, source: str, verdict: str, confidence: str, details: str) -> dict:
    """Build one normalized enrichment finding."""
    return {
        "observable_type": observable_type,
        "value": value,
        "source": source,
        "verdict": verdict,
        "confidence": confidence,
        "details": details,
    }


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    """Remove duplicate findings while preserving first-seen order."""
    seen = set()
    result = []
    for finding in findings:
        key = (finding["observable_type"], finding["value"], finding["source"], finding["verdict"])
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result
