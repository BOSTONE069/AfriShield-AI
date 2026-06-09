"""Regex-based indicator-of-compromise extraction.

This module is intentionally deterministic. IOC extraction should not depend on
an LLM because URLs, domains, emails, IPs, and hashes are structured artifacts.
"""

import re
from urllib.parse import urlparse


# Precompiled regexes keep repeated analysis calls fast and centralize the IOC
# vocabulary in one place.
URL_REGEX = re.compile(r"https?://[^\s<>\")\]]+", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b")
IP_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
HASH_REGEX = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
BARE_DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|ke|co|ac|go|info|biz|site|online|app|dev)\b",
    re.IGNORECASE,
)


def _clean_url(url: str) -> str:
    """Remove punctuation that often trails URLs in natural-language messages."""
    return url.rstrip(".,;:!?")


def _unique(values: list[str]) -> list[str]:
    """Deduplicate while preserving first-seen order for stable UI output."""
    seen = set()
    result = []
    for value in values:
        normalized = value.lower()
        if normalized not in seen:
            seen.add(normalized)
            result.append(value)
    return result


def extract_iocs(text: str) -> dict:
    """Extract URLs, domains, emails, IP addresses, and hashes from text."""
    urls = [_clean_url(url) for url in URL_REGEX.findall(text)]
    emails = EMAIL_REGEX.findall(text)
    ips = IP_REGEX.findall(text)
    hashes = HASH_REGEX.findall(text)

    domains = []
    for url in urls:
        parsed = urlparse(url)
        if parsed.netloc:
            # Strip credentials and ports so the domain list contains only hosts.
            domains.append(parsed.netloc.lower().split("@")[-1].split(":")[0])

    for domain in BARE_DOMAIN_REGEX.findall(text):
        # Avoid duplicating the domain part of an email address as a standalone
        # domain IOC unless it also appears independently in the message.
        if not any(email.lower().endswith(f"@{domain.lower()}") for email in emails):
            domains.append(domain.lower())

    return {
        "urls": _unique(urls),
        "domains": _unique(domains),
        "emails": _unique(emails),
        "ips": _unique(ips),
        "hashes": _unique(hashes),
    }
