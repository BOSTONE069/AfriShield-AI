"""Risk scoring logic for converting evidence into a 0-100 score."""

from backend.app.threat_classifier import FINANCIAL_KEYWORDS, RISKY_KEYWORDS


# Base weights give each threat category an initial seriousness before evidence
# such as URLs, credential language, and urgency is added.
CLASSIFICATION_WEIGHTS = {
    "BENIGN": 0,
    "UNKNOWN_SUSPICIOUS": 15,
    "MISINFORMATION": 25,
    "SCAM": 30,
    "BUSINESS_EMAIL_COMPROMISE": 35,
    "PHISHING": 35,
    "CREDENTIAL_THEFT": 40,
    "MALWARE": 45,
}


def calculate_risk_score(text: str, iocs: dict, classification: str, evidence: list[str] | None = None) -> int:
    """Calculate an analyst-friendly risk score from rules and extracted IOCs."""
    lower_text = text.lower()
    evidence = evidence or []
    score = CLASSIFICATION_WEIGHTS.get(classification, 10)

    if iocs.get("urls"):
        score += 20
    if iocs.get("domains"):
        score += 10
    if iocs.get("ips") or iocs.get("hashes"):
        score += 15
    if any(word in lower_text for word in RISKY_KEYWORDS):
        score += 15
    if any(word in lower_text for word in FINANCIAL_KEYWORDS):
        score += 15
    if any(word in lower_text for word in {"password", "identity", "otp", "pin", "credentials"}):
        score += 15
    if any(word in lower_text for word in {"24 hours", "immediately", "before midnight", "final notice"}):
        score += 10
    if len(evidence) >= 3:
        score += 10

    if classification == "BENIGN":
        # Benign classifications should remain low-risk even if harmless words
        # overlap with suspicious keywords.
        score = min(score, 20)

    return min(max(score, 0), 100)


def severity_from_score(score: int) -> str:
    """Map the numeric score to the severity labels used by the UI and API."""
    if score <= 20:
        return "LOW"
    if score <= 50:
        return "MEDIUM"
    if score <= 75:
        return "HIGH"
    return "CRITICAL"
