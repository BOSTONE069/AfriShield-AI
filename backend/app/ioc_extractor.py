import re
from urllib.parse import urlparse


URL_REGEX = re.compile(r"https?://[^\s<>\")\]]+", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b")
IP_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
HASH_REGEX = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
BARE_DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|ke|co|ac|go|info|biz|site|online|app|dev)\b",
    re.IGNORECASE,
)


def _clean_url(url: str) -> str:
    return url.rstrip(".,;:!?")


def _unique(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        normalized = value.lower()
        if normalized not in seen:
            seen.add(normalized)
            result.append(value)
    return result


def extract_iocs(text: str) -> dict:
    urls = [_clean_url(url) for url in URL_REGEX.findall(text)]
    emails = EMAIL_REGEX.findall(text)
    ips = IP_REGEX.findall(text)
    hashes = HASH_REGEX.findall(text)

    domains = []
    for url in urls:
        parsed = urlparse(url)
        if parsed.netloc:
            domains.append(parsed.netloc.lower().split("@")[-1].split(":")[0])

    for domain in BARE_DOMAIN_REGEX.findall(text):
        if not any(email.lower().endswith(f"@{domain.lower()}") for email in emails):
            domains.append(domain.lower())

    return {
        "urls": _unique(urls),
        "domains": _unique(domains),
        "emails": _unique(emails),
        "ips": _unique(ips),
        "hashes": _unique(hashes),
    }
