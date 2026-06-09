"""Static mapping from AfriShield threat types to ATT&CK-style techniques."""

# This is deliberately small for the MVP. It keeps the demo explainable and can
# later be replaced with richer ATT&CK technique IDs and references.
MITRE_MAPPINGS = {
    "PHISHING": [
        {
            "tactic": "Initial Access",
            "technique": "Phishing",
            "explanation": "The content attempts to lure the user into interacting with a deceptive message or link.",
        }
    ],
    "CREDENTIAL_THEFT": [
        {
            "tactic": "Initial Access",
            "technique": "Phishing",
            "explanation": "The message uses a lure to direct the user toward a credential capture flow.",
        },
        {
            "tactic": "Credential Access",
            "technique": "Credential Harvesting",
            "explanation": "The wording asks the user to verify, confirm, or submit account information.",
        },
    ],
    "MALWARE": [
        {
            "tactic": "Execution",
            "technique": "User Execution",
            "explanation": "The user is encouraged to open or enable content that may execute malicious code.",
        }
    ],
    "BUSINESS_EMAIL_COMPROMISE": [
        {
            "tactic": "Collection",
            "technique": "Email Collection",
            "explanation": "BEC activity often relies on mailbox access and payment context gathered from email.",
        },
        {
            "tactic": "Impact",
            "technique": "Financial Theft",
            "explanation": "The message attempts to redirect or authorize fraudulent payment activity.",
        },
    ],
    "SCAM": [
        {
            "tactic": "Initial Access",
            "technique": "Social Engineering",
            "explanation": "The message applies persuasion, urgency, or impersonation to influence user action.",
        }
    ],
    "MISINFORMATION": [
        {
            "tactic": "Impact",
            "technique": "Influence",
            "explanation": "The content may aim to manipulate perception or behavior at scale.",
        }
    ],
    "UNKNOWN_SUSPICIOUS": [
        {
            "tactic": "Reconnaissance",
            "technique": "Gather Victim Information",
            "explanation": "Suspicious content may be probing for user interaction or trust signals.",
        }
    ],
    "BENIGN": [],
}


def map_to_mitre(threat_type: str) -> list[dict]:
    """Return MITRE mappings for a normalized threat type."""
    return MITRE_MAPPINGS.get(threat_type, [])
