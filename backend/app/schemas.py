"""Pydantic schemas for FastAPI request and response validation."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

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
    "NEEDS_REVIEW",
]
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
ConfidenceLevel = Literal["LOW", "MEDIUM", "HIGH"]


class AnalyzeRequest(BaseModel):
    """Client payload submitted to /api/analyze."""

    input_type: InputType = "text"
    content: str = Field(..., min_length=1, max_length=20000)
    context: str = Field(default="Kenya", min_length=1, max_length=200)
    remote_processing_consent: bool = False


class IOCSet(BaseModel):
    """Indicators of compromise extracted from submitted text."""

    urls: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)


class MitreMapping(BaseModel):
    """Single ATT&CK-style mapping item displayed in the dashboard."""

    tactic: str
    technique: str
    technique_id: str = ""
    explanation: str = ""


class EnrichmentFinding(BaseModel):
    """Local threat-feed or heuristic enrichment for one observable."""

    observable_type: str
    value: str
    source: str
    verdict: str
    confidence: str
    details: str


class ScoreFactor(BaseModel):
    """One transparent contribution to the final risk score."""

    name: str
    points: int
    source: Literal["deterministic", "threat_feed", "llm", "policy"]
    description: str


class DecisionDetails(BaseModel):
    """Source verdicts and conflicts used by the monotonic decision policy."""

    policy: Literal["deterministic_minimum_v1"]
    deterministic_threat_type: ThreatType
    llm_threat_type: ThreatType | None = None
    threat_feed_lock: bool
    deterministic_minimum_score: int = Field(..., ge=0, le=100)
    conflicts: list[str] = Field(default_factory=list)


class PrivacyDecision(BaseModel):
    """Explicit record of whether submitted evidence could leave the deployment."""

    llm_provider: str
    remote_processing_consent: bool
    remote_processing_allowed: bool
    evidence_transmitted_to_remote_llm: bool


class ComponentVersions(BaseModel):
    """Reproducibility metadata attached to every decision."""

    model_config = ConfigDict(protected_namespaces=())

    ruleset: str
    prompt: str
    threat_feed: str
    decision_policy: str
    model: str
    model_provider: str
    component_fingerprint: str


class AnalyzeResponse(BaseModel):
    """Complete analysis result returned by the backend."""

    threat_type: ThreatType
    severity: Severity
    risk_score: int = Field(..., ge=0, le=100)
    confidence: ConfidenceLevel
    evidence_strength: ConfidenceLevel
    score_factors: list[ScoreFactor]
    decision_details: DecisionDetails
    privacy: PrivacyDecision
    component_versions: ComponentVersions
    iocs: IOCSet
    enrichment: list[EnrichmentFinding] = Field(default_factory=list)
    mitre_mapping: list[MitreMapping]
    summary: str
    evidence: list[str]
    recommended_actions: list[str]
    report_markdown: str
    report_variants: dict[str, str] = Field(default_factory=dict)
    runtime: dict


class FeedbackRequest(BaseModel):
    """Analyst feedback saved from the dashboard after reviewing a case."""

    case_id: str = Field(..., min_length=1, max_length=100)
    verdict: Literal["correct", "incorrect", "needs_review"]
    rating: int = Field(..., ge=1, le=5)
    analyst_note: str = Field(default="", max_length=5000)
    original_content: str = Field(..., min_length=1, max_length=20000)
    original_input_type: InputType
    original_context: str = Field(..., min_length=1, max_length=200)
    corrected_threat_type: ThreatType | None = None
    corrected_severity: Severity | None = None
    error_category: (
        Literal[
            "FALSE_POSITIVE",
            "FALSE_NEGATIVE",
            "WRONG_TYPE",
            "WRONG_SEVERITY",
            "IOC_ERROR",
            "ACTION_ERROR",
            "OTHER",
        ]
        | None
    ) = None
    error_reason: str = Field(default="", max_length=2000)
    corrected_iocs: IOCSet | None = None
    corrected_recommended_actions: list[str] = Field(default_factory=list, max_length=25)
    review_status: Literal["pending", "reviewed", "adjudicated"] = "reviewed"
    analysis: AnalyzeResponse

    @model_validator(mode="after")
    def validate_corrections(self) -> "FeedbackRequest":
        if self.verdict == "incorrect" and self.error_category is None:
            raise ValueError("Incorrect verdicts require an error category.")
        if self.error_category in {"FALSE_POSITIVE", "FALSE_NEGATIVE"} and not self.error_reason.strip():
            raise ValueError("False-positive and false-negative corrections require a reason.")
        if self.verdict == "incorrect" and not any(
            (
                self.corrected_threat_type,
                self.corrected_severity,
                self.corrected_iocs,
                self.corrected_recommended_actions,
                self.error_reason.strip(),
            )
        ):
            raise ValueError("Incorrect verdicts require at least one correction or explanation.")
        return self


class FeedbackResponse(BaseModel):
    """Acknowledgement returned after feedback is stored."""

    status: str
    feedback_id: str


class AnalysisJobAccepted(BaseModel):
    """Acknowledgement returned when analysis is queued."""

    job_id: str
    status: Literal["queued", "running"]


class AnalysisJobResponse(BaseModel):
    """Pollable background-analysis state."""

    job_id: str
    status: Literal["queued", "running", "completed", "failed"]
    submitted_at: str
    updated_at: str
    result: AnalyzeResponse | None = None
    error_code: str | None = None


class ReportExportRequest(BaseModel):
    """Markdown report payload converted to PDF by /api/report/pdf."""

    title: str = Field(default="AfriShield Cyber Defence Incident Report", min_length=1, max_length=200)
    report_markdown: str = Field(..., min_length=1, max_length=100000)
