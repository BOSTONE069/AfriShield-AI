from dataclasses import dataclass


@dataclass(frozen=True)
class Classification:
    threat_type: str
    summary: str
    evidence: list[str]
    recommended_actions: list[str]


RISKY_KEYWORDS = {
    "verify",
    "urgent",
    "suspended",
    "login",
    "password",
    "refund",
    "account",
    "confirm",
    "click",
    "restore",
    "blocked",
    "security alert",
    "expiry",
    "immediately",
    "before midnight",
}

FINANCIAL_KEYWORDS = {
    "mpesa",
    "m-pesa",
    "bank",
    "kra",
    "refund",
    "payment",
    "loan",
    "grant",
    "donor",
    "kes",
    "wallet",
}

LOCAL_IMPERSONATION_KEYWORDS = {
    "kra": "tax authority impersonation",
    "itax": "tax portal lure",
    "m-pesa": "mobile money impersonation",
    "mpesa": "mobile money impersonation",
    "sacco": "financial institution lure",
    "student portal": "university portal lure",
    "fee statement": "university payment lure",
    "donor": "NGO donor impersonation",
}


def classify_threat(text: str, iocs: dict) -> Classification:
    lower_text = text.lower()
    evidence: list[str] = []

    for keyword, label in LOCAL_IMPERSONATION_KEYWORDS.items():
        if keyword in lower_text:
            evidence.append(label)

    if any(word in lower_text for word in RISKY_KEYWORDS):
        evidence.append("urgent account or action-oriented language")

    if any(word in lower_text for word in FINANCIAL_KEYWORDS):
        evidence.append("financial or institutional lure")

    if iocs.get("urls") or iocs.get("domains"):
        evidence.append("external link or domain present")

    credential_terms = {"password", "login", "verify", "confirm", "identity", "account"}
    financial_terms = {"payment", "refund", "loan", "grant", "fee", "kes", "bank", "mpesa", "m-pesa"}
    malware_terms = {"attachment", "invoice.exe", ".scr", ".bat", "macro", "enable content", "payload"}
    bec_terms = {"wire transfer", "invoice", "supplier", "change bank details", "ceo", "finance team"}
    misinformation_terms = {"forward to everyone", "breaking", "secret cure", "election rigged", "do not trust"}

    has_url = bool(iocs.get("urls") or iocs.get("domains"))
    asks_for_credentials = any(term in lower_text for term in credential_terms)
    has_financial_lure = any(term in lower_text for term in financial_terms)

    if any(term in lower_text for term in malware_terms):
        threat_type = "MALWARE"
        summary = "The content appears to encourage opening or enabling potentially malicious files."
    elif any(term in lower_text for term in bec_terms):
        threat_type = "BUSINESS_EMAIL_COMPROMISE"
        summary = "The message resembles a business email compromise or payment diversion attempt."
    elif has_url and asks_for_credentials:
        threat_type = "CREDENTIAL_THEFT" if "identity" in lower_text or "password" in lower_text else "PHISHING"
        summary = "The message uses a link and account verification language to solicit sensitive information."
    elif has_url and has_financial_lure:
        threat_type = "PHISHING"
        summary = "The message combines an external link with a financial or institutional lure."
    elif has_financial_lure and any(term in lower_text for term in {"urgent", "immediately", "confirm", "send", "pay"}):
        threat_type = "SCAM"
        summary = "The message uses financial pressure and social engineering indicators."
    elif any(term in lower_text for term in misinformation_terms):
        threat_type = "MISINFORMATION"
        summary = "The message contains patterns associated with harmful coordinated or misleading messaging."
    elif evidence:
        threat_type = "UNKNOWN_SUSPICIOUS"
        summary = "The message contains suspicious cues but does not strongly match a single threat category."
    else:
        threat_type = "BENIGN"
        summary = "No strong malicious indicators were detected in the submitted content."

    actions = _recommended_actions(threat_type)
    return Classification(threat_type, summary, sorted(set(evidence)), actions)


def _recommended_actions(threat_type: str) -> list[str]:
    common = ["Preserve the message and analysis output for audit records."]
    actions = {
        "PHISHING": ["Do not click the link.", "Block or monitor the domain.", "Warn targeted users about the campaign."],
        "CREDENTIAL_THEFT": ["Do not enter credentials.", "Reset credentials if the link was used.", "Enable MFA and review account activity."],
        "MALWARE": ["Do not open attachments.", "Isolate affected endpoints.", "Submit artifacts to the security team for malware analysis."],
        "BUSINESS_EMAIL_COMPROMISE": ["Verify payment requests out of band.", "Review mailbox rules and sign-in logs.", "Escalate to finance and security teams."],
        "SCAM": ["Do not send money or personal information.", "Report the sender.", "Notify users through trusted channels."],
        "MISINFORMATION": ["Avoid resharing the message.", "Verify claims with authoritative sources.", "Monitor for coordinated spread."],
        "UNKNOWN_SUSPICIOUS": ["Treat the content with caution.", "Request analyst review.", "Block links until validated."],
        "BENIGN": ["No immediate security action required.", "Continue routine monitoring."],
    }
    return actions.get(threat_type, []) + common
