"""Unit tests for deterministic threat classification rules."""

import pytest

from backend.app.ioc_extractor import extract_iocs
from backend.app.threat_classifier import classify_threat, contains_any, strip_reassurances


def _classify(text: str) -> str:
    return classify_threat(text, extract_iocs(text)).threat_type


@pytest.mark.parametrize(
    "text",
    [
        "Your shipping opinion makes sense, thanks.",
        "Meeting with the CEO is moved to Friday.",
        "I will confirm the agenda tomorrow, send the slides.",
        "Please pay the supplier invoice by Friday as usual.",
        "Reminder from M-Pesa: the meeting is on Monday. No payment or password is required.",
        "See the attachment for the workshop agenda.",
    ],
)
def test_everyday_messages_are_benign(text: str) -> None:
    assert _classify(text) == "BENIGN"


def test_unresolved_risk_cues_go_to_review_instead_of_benign() -> None:
    # The rules only understand English, so a lone brand cue is reviewed, not cleared.
    assert _classify("Ujumbe wa M-Pesa: akaunti yako itafungwa.") == "UNKNOWN_SUSPICIOUS"


def test_keywords_match_whole_words_only() -> None:
    assert contains_any("verify your pin now", frozenset({"pin"}))
    assert not contains_any("shipping opinion", frozenset({"pin"}))
    assert contains_any("pay kes 2,000", frozenset({"kes"}))
    assert not contains_any("it makes sense", frozenset({"kes"}))


def test_reassurance_clauses_are_removed_but_links_are_kept() -> None:
    assert "password" not in strip_reassurances("meeting monday. no password is required.")
    linked = "no password is required at https://x.invalid/login."
    assert strip_reassurances(linked) == linked


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "Congratulations, you have been approved for KES 2,000. Pay a processing fee today "
            "to claim it at https://jobs-onboarding.invalid/form.",
            "SCAM",
        ),
        ("You have won KES 50,000! Send the clearance fee to receive your prize.", "SCAM"),
        ("URGENT: verify your login now at https://mpesa-security.invalid/verify.", "PHISHING"),
        ("Your account is locked. Confirm your password at https://bank-help.invalid.", "CREDENTIAL_THEFT"),
        ("Open the attached invoice.pdf.exe and enable content to view it.", "MALWARE"),
        ("Fungua kiambatisho results.docm kutoka kwa msambazaji.", "MALWARE"),
        (
            "CEO request: finance team, send a wire transfer to the new supplier account today. Do not call.",
            "BUSINESS_EMAIL_COMPROMISE",
        ),
        ("BREAKING: the clinic is hiding this secret. Forward to everyone before it is deleted.", "MISINFORMATION"),
    ],
)
def test_threats_are_classified(text: str, expected: str) -> None:
    assert _classify(text) == expected
