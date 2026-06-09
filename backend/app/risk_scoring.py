from backend.app.threat_classifier import FINANCIAL_KEYWORDS, RISKY_KEYWORDS


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
        score = min(score, 20)

    return min(max(score, 0), 100)


def severity_from_score(score: int) -> str:
    if score <= 20:
        return "LOW"
    if score <= 50:
        return "MEDIUM"
    if score <= 75:
        return "HIGH"
    return "CRITICAL"
