"""Pydantic schemas for FastAPI request and response validation."""

from typing import Literal

from pydantic import BaseModel, Field


# Literal types document and enforce the small vocabulary the UI/API expects.
InputType = Literal["email", "url", "sms", "social_message", "text"]
ThreatType = Literal[
    "PHISHING",
    "SCAM",
    "CREDENTIAL_THEFT",
    "MALWARE",
    "BUSINESS_EMAIL_COMPROMISE",
    "MISINFORMATION",
    "BENIGN",
    "UNKNOWN_SUSPICIOUS",
]
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class AnalyzeRequest(BaseModel):
    """Client payload submitted to /api/analyze."""

    input_type: InputType = "text"
    content: str = Field(..., min_length=1, max_length=20000)
    context: str = "Kenya"


class IOCSet(BaseModel):
    """Indicators of compromise extracted from submitted text."""

    urls: list[str] = []
    domains: list[str] = []
    emails: list[str] = []
    ips: list[str] = []
    hashes: list[str] = []


class MitreMapping(BaseModel):
    """Single ATT&CK-style mapping item displayed in the dashboard."""

    tactic: str
    technique: str
    explanation: str = ""


class AnalyzeResponse(BaseModel):
    """Complete analysis result returned by the backend."""

    threat_type: ThreatType
    severity: Severity
    risk_score: int = Field(..., ge=0, le=100)
    iocs: IOCSet
    mitre_mapping: list[MitreMapping]
    summary: str
    evidence: list[str]
    recommended_actions: list[str]
    report_markdown: str
    runtime: dict
