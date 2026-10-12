"""Rule-based threat classification for reliable first-pass triage.

The LLM can enrich the analysis, but this classifier provides a deterministic
baseline tuned to common African/Kenyan scam and phishing patterns.
"""

import re
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Classification:
    """Normalized classification output consumed by the analyzer pipeline."""

    threat_type: str
    summary: str
    evidence: list[str]
    recommended_actions: list[str]


RISKY_KEYWORDS = frozenset(
    {
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
)

FINANCIAL_KEYWORDS = frozenset(
    {
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
)

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

URGENCY_TERMS = frozenset(
    {
        "urgent",
        "urgently",
        "immediately",
        "suspended",
        "blocked",
        "security alert",
        "expiry",
        "expires",
        "final notice",
        "before midnight",
        "within 24 hours",
        "24 hours",
        "today only",
    }
)
CREDENTIAL_TERMS = frozenset(
    {
        "password",
        "passcode",
        "pin",
        "otp",
        "one-time code",
        "verification code",
        "security code",
        "login",
        "log in",
        "sign in",
        "credentials",
        "identity",
    }
)
# Credential theft is reserved for explicit secret or identity requests;
# account-verification lures without them are reported as phishing.
SECRET_TERMS = frozenset({"password", "passcode", "pin", "otp", "credentials", "identity"})
FINANCIAL_LURE_TERMS = frozenset(
    {"payment", "refund", "loan", "grant", "fee", "kes", "bank", "mpesa", "m-pesa", "wallet"}
)
PAYMENT_PRESSURE_TERMS = frozenset({"urgent", "immediately", "confirm", "send", "pay", "deposit", "today"})
# Advance-fee, prize, and mistaken-transfer scams ask the target to move money
# first, which distinguishes them from credential-harvesting phishing links.
SCAM_PATTERNS = (
    re.compile(r"\b(?:pay|send|deposit)\b[^.!?\n]{0,60}\b(?:fee|charge|deposit)\b"),
    re.compile(r"\b(?:processing|registration|clearance|activation|unlocking|release)\s+fee\b"),
    re.compile(r"\b(?:you(?:'ve| have)? won|winner|lottery|jackpot|claim your (?:prize|reward|winnings))\b"),
    re.compile(r"\b(?:sent|transferred) to you by mistake\b|\bsend (?:it|the money) back\b"),
)
MALWARE_TERMS = frozenset({"enable content", "enable macros", "enable editing", "macro", "invoice.exe"})
# Executables, scripts, disk images, and macro-enabled Office documents.
RISKY_EXTENSION_REGEX = re.compile(
    r"\.(?:exe|scr|bat|cmd|vbs|vbe|wsf|hta|lnk|iso|msi|jar|apk|ps1|docm|xlsm|pptm|dotm)\b"
)
BEC_PAYMENT_TERMS = frozenset(
    {"wire transfer", "bank transfer", "transfer", "remit", "send", "pay", "payment", "change bank details"}
)
BEC_ROLE_TERMS = frozenset(
    {"ceo", "cfo", "managing director", "director", "finance team", "accounts payable", "supplier", "vendor"}
)
BEC_PRESSURE_TERMS = frozenset(
    {
        "do not call",
        "don't call",
        "in a meeting",
        "confidential",
        "keep this between us",
        "new account",
        "new bank details",
        "updated bank details",
        "change bank details",
        "urgent",
        "today",
    }
)
MISINFORMATION_STRONG_TERMS = frozenset(
    {
        "forward to everyone",
        "share with everyone",
        "forward this to",
        "before it is deleted",
        "before they delete",
        "they don't want you to know",
        "secret cure",
        "miracle cure",
        "election rigged",
    }
)
MISINFORMATION_WEAK_TERMS = frozenset(
    {"breaking", "hiding", "secret", "rigged", "do not trust", "share widely", "forward"}
)

ACCOUNT_ACTION_REGEX = re.compile(
    r"\b(?:verify|confirm|restore|unlock|reactivate|update|validate|reset)\b(?:\W+\w+){0,3}?\W+"
    r"(?:account|details|identity|information|info|access|pin|password|login|profile|wallet|card|number)\b"
)
# Legitimate notices often reassure recipients that nothing is required
# ("no payment or password is required"); those clauses are not requests.
REASSURANCE_REGEX = re.compile(r"\b(?:no|not|never|without)\b[^.;!?\n]*\b(?:required|needed|necessary|ask|asked)\b")
CLAUSE_SPLIT_REGEX = re.compile(r"(?<=[.;!?\n])")


@lru_cache(maxsize=64)
def _term_pattern(terms: frozenset[str]) -> re.Pattern[str]:
    """Compile a whole-word alternation so "pin" does not match "shipping"."""
    parts = []
    for term in sorted(terms, key=len, reverse=True):
        left = r"(?<!\w)" if term[0].isalnum() else ""
        right = r"(?!\w)" if term[-1].isalnum() else ""
        parts.append(f"{left}{re.escape(term)}{right}")
    return re.compile("|".join(parts))


def contains_any(text: str, terms: frozenset[str]) -> bool:
    """Return whether lower-cased text contains any term as a whole word or phrase."""
    return bool(_term_pattern(terms).search(text))


def strip_reassurances(text: str) -> str:
    """Drop link-free clauses that tell the reader nothing is being requested."""
    clauses = CLAUSE_SPLIT_REGEX.split(text)
    return "".join(clause for clause in clauses if "http" in clause or not REASSURANCE_REGEX.search(clause))


def classify_threat(text: str, iocs: dict) -> Classification:
    """Classify submitted content using local evidence and keyword rules."""
    lower_text = strip_reassurances(text.lower())
    reassured = lower_text != text.lower()
    evidence: list[str] = []

    # Localized impersonation signals help the tool understand common regional
    # lures such as KRA, M-Pesa, SACCO, university portal, and donor scams.
    brand_lure = False
    for keyword, label in LOCAL_IMPERSONATION_KEYWORDS.items():
        if contains_any(lower_text, frozenset({keyword})):
            evidence.append(label)
            brand_lure = True

    if contains_any(lower_text, RISKY_KEYWORDS):
        evidence.append("urgent account or action-oriented language")

    if contains_any(lower_text, FINANCIAL_KEYWORDS):
        evidence.append("financial or institutional lure")

    has_url = bool(iocs.get("urls") or iocs.get("domains"))
    if has_url:
        evidence.append("external link or domain present")

    asks_for_credentials = contains_any(lower_text, CREDENTIAL_TERMS)
    asks_for_account_action = bool(ACCOUNT_ACTION_REGEX.search(lower_text))
    has_financial_lure = contains_any(lower_text, FINANCIAL_LURE_TERMS)
    has_urgency = contains_any(lower_text, URGENCY_TERMS)
    requests_payment = any(pattern.search(lower_text) for pattern in SCAM_PATTERNS)

    # Ordered checks give more specific classifications a chance before generic
    # suspicious/benign outcomes.
    if contains_any(lower_text, MALWARE_TERMS) or RISKY_EXTENSION_REGEX.search(lower_text):
        threat_type = "MALWARE"
        summary = "The content appears to encourage opening or enabling potentially malicious files."
    elif (
        contains_any(lower_text, BEC_PAYMENT_TERMS)
        and contains_any(lower_text, BEC_ROLE_TERMS)
        and contains_any(lower_text, BEC_PRESSURE_TERMS)
    ):
        threat_type = "BUSINESS_EMAIL_COMPROMISE"
        summary = "The message resembles a business email compromise or payment diversion attempt."
    elif requests_payment:
        threat_type = "SCAM"
        summary = "The message asks the recipient to pay or send money to receive a promised benefit."
    elif has_url and (asks_for_credentials or asks_for_account_action):
        threat_type = "CREDENTIAL_THEFT" if contains_any(lower_text, SECRET_TERMS) else "PHISHING"
        summary = "The message uses a link and account verification language to solicit sensitive information."
    elif has_url and has_financial_lure:
        threat_type = "PHISHING"
        summary = "The message combines an external link with a financial or institutional lure."
    elif has_financial_lure and contains_any(lower_text, PAYMENT_PRESSURE_TERMS):
        threat_type = "SCAM"
        summary = "The message uses financial pressure and social engineering indicators."
    elif contains_any(lower_text, MISINFORMATION_STRONG_TERMS) or (
        sum(contains_any(lower_text, frozenset({term})) for term in MISINFORMATION_WEAK_TERMS) >= 2
    ):
        threat_type = "MISINFORMATION"
        summary = "The message contains patterns associated with harmful coordinated or misleading messaging."
    elif (
        has_urgency
        or asks_for_credentials
        or asks_for_account_action
        or has_url
        or ((brand_lure or has_financial_lure) and not reassured)
    ):
        # Any remaining risk cue goes to analyst review rather than BENIGN: the
        # rules only understand English phrasing, and a missed threat costs more
        # than a review. A bare brand mention is benign only when the message
        # explicitly says nothing is required of the reader.
        threat_type = "UNKNOWN_SUSPICIOUS"
        summary = "The message contains suspicious cues but does not strongly match a single threat category."
    else:
        threat_type = "BENIGN"
        summary = "No strong malicious indicators were detected in the submitted content."

    actions = _recommended_actions(threat_type)
    return Classification(threat_type, summary, sorted(set(evidence)), actions)


def _recommended_actions(threat_type: str) -> list[str]:
    """Return analyst response actions matched to the final threat category."""
    common = ["Preserve the message and analysis output for audit records."]
    actions = {
        "PHISHING": [
            "Do not click the link.",
            "Block or monitor the domain.",
            "Warn targeted users about the campaign.",
        ],
        "CREDENTIAL_THEFT": [
            "Do not enter credentials.",
            "Reset credentials if the link was used.",
            "Enable MFA and review account activity.",
        ],
        "MALWARE": [
            "Do not open attachments.",
            "Isolate affected endpoints.",
            "Submit artifacts to the security team for malware analysis.",
        ],
        "BUSINESS_EMAIL_COMPROMISE": [
            "Verify payment requests out of band.",
            "Review mailbox rules and sign-in logs.",
            "Escalate to finance and security teams.",
        ],
        "SCAM": [
            "Do not send money or personal information.",
            "Report the sender.",
            "Notify users through trusted channels.",
        ],
        "MISINFORMATION": [
            "Avoid resharing the message.",
            "Verify claims with authoritative sources.",
            "Monitor for coordinated spread.",
        ],
        "UNKNOWN_SUSPICIOUS": [
            "Treat the content with caution.",
            "Request analyst review.",
            "Block links until validated.",
        ],
        "BENIGN": ["No immediate security action required.", "Continue routine monitoring."],
    }
    return actions.get(threat_type, []) + common
