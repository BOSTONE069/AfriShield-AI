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
    # NEEDS_REVIEW is a decision state, not a source classification. Its
    # effective score is assembled from the deterministic and enrichment floors.
    "NEEDS_REVIEW": 15,
}


def calculate_risk_score(text: str, iocs: dict, classification: str, evidence: list[str] | None = None) -> int:
    """Calculate an analyst-friendly risk score from rules and extracted IOCs."""
    score, _ = calculate_risk_score_with_factors(text, iocs, classification, evidence)
    return score


def calculate_risk_score_with_factors(
    text: str, iocs: dict, classification: str, evidence: list[str] | None = None
) -> tuple[int, list[dict]]:
    """Return the deterministic risk score and every contributing factor."""
    lower_text = text.lower()
    evidence = evidence or []
    factors: list[dict] = []

    def add(name: str, points: int, source: str, description: str) -> None:
        if points:
            factors.append({"name": name, "points": points, "source": source, "description": description})

    base_points = CLASSIFICATION_WEIGHTS.get(classification, 10)
    add(
        "Deterministic classification",
        base_points,
        "deterministic",
        f"Base weight for {classification.replace('_', ' ').lower()}.",
    )

    if iocs.get("urls"):
        add("URL detected", 20, "deterministic", "One or more URLs were extracted from the content.")
    if iocs.get("domains"):
        add("Domain detected", 10, "deterministic", "One or more domains were extracted from the content.")
    if iocs.get("ips") or iocs.get("hashes"):
        add("Technical IOC detected", 15, "deterministic", "An IP address or file hash was extracted.")
    if any(word in lower_text for word in RISKY_KEYWORDS):
        add("Risk language", 15, "deterministic", "Urgent account or action-oriented language was found.")
    if any(word in lower_text for word in FINANCIAL_KEYWORDS):
        add("Financial lure", 15, "deterministic", "Financial or institutional language was found.")
    if any(word in lower_text for word in {"password", "identity", "otp", "pin", "credentials"}):
        add("Credential request", 15, "deterministic", "Credential or identity terms were found.")
    if any(word in lower_text for word in {"24 hours", "immediately", "before midnight", "final notice"}):
        add("Time pressure", 10, "deterministic", "Explicit urgency or deadline pressure was found.")
    if len(evidence) >= 3:
        add("Corroborating evidence", 10, "deterministic", "At least three deterministic evidence items agree.")

    score = sum(factor["points"] for factor in factors)

    if classification == "BENIGN":
        # Benign classifications should remain low-risk even if harmless words
        # overlap with suspicious keywords.
        capped_score = min(score, 20)
        add(
            "Benign ceiling",
            capped_score - score,
            "policy",
            "The deterministic engine classified the content as benign.",
        )
        score = capped_score

    bounded_score = min(max(score, 0), 100)
    add("Score ceiling", bounded_score - score, "policy", "Risk scores are bounded to the 0-100 range.")
    return bounded_score, factors


def severity_from_score(score: int) -> str:
    """Map the numeric score to the severity labels used by the UI and API."""
    if score <= 20:
        return "LOW"
    if score <= 50:
        return "MEDIUM"
    if score <= 75:
        return "HIGH"
    return "CRITICAL"
