"""Threat analysis orchestration.

This module is the backend pipeline:
1. Normalize submitted content.
2. Extract IOCs deterministically.
3. Classify with local rules.
4. Ask the configured LLM for enrichment when available.
5. Validate model output before it affects the result.
6. Score risk, map MITRE techniques, and generate a report.
"""

import json

from backend.app.agents import (
    ClassificationAgent,
    EnrichmentAgent,
    IOCAgent,
    MitreAgent,
    PreprocessingAgent,
    ReportAgent,
    RiskAgent,
)
from backend.app.config import get_settings
from backend.app.llm_client import call_chat_json, call_chat_text
from backend.app.runtime_metrics import Timer, runtime_payload


# These allow-lists protect the API schema from loose model output. If the LLM
# returns something unexpected, the deterministic classifier remains in charge.
ALLOWED_THREAT_TYPES = {
    "PHISHING",
    "SCAM",
    "CREDENTIAL_THEFT",
    "MALWARE",
    "BUSINESS_EMAIL_COMPROMISE",
    "MISINFORMATION",
    "BENIGN",
    "UNKNOWN_SUSPICIOUS",
}
ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def analyze_threat(input_type: str, content: str, context: str = "Kenya") -> dict:
    """Run the complete analysis pipeline and return the API response object."""
    settings = get_settings()
    preprocessing_agent = PreprocessingAgent()
    ioc_agent = IOCAgent()
    classification_agent = ClassificationAgent()
    enrichment_agent = EnrichmentAgent()
    risk_agent = RiskAgent()
    mitre_agent = MitreAgent()
    report_agent = ReportAgent()

    normalized = preprocessing_agent.run(content)

    with Timer() as timer:
        # The rule-based pipeline always runs so the app remains useful even
        # when the model is unavailable or emits invalid JSON.
        iocs = ioc_agent.run(normalized)
        classification = classification_agent.run(normalized, iocs)
        llm_analysis, llm_metrics = _try_llm_classification(normalized, context, iocs)

        threat_type = classification.threat_type
        summary = classification.summary
        evidence = classification.evidence
        recommended_actions = classification.recommended_actions

        if llm_analysis:
            # LLM output is treated as enrichment, not blind authority. Every
            # field is normalized and validated before it replaces rule output.
            threat_type = _valid_threat_type(llm_analysis.get("threat_type"), threat_type)
            summary = _valid_string(llm_analysis.get("summary"), summary)
            evidence = _valid_string_list(llm_analysis.get("evidence"), evidence)
            recommended_actions = _valid_string_list(llm_analysis.get("recommended_actions"), recommended_actions)

        enrichment = enrichment_agent.run(iocs)
        risk_score, severity = risk_agent.run(normalized, iocs, threat_type, evidence)
        if llm_analysis and llm_analysis.get("severity") in ALLOWED_SEVERITIES:
            # A small local model may understate risk. Never let it downgrade
            # severity below what the scoring engine calculated.
            severity = _max_severity(severity, llm_analysis["severity"])

        mitre_mapping = mitre_agent.run(threat_type)
        deterministic_report = report_agent.run(
            input_type,
            context,
            threat_type,
            severity,
            risk_score,
            iocs,
            enrichment,
            mitre_mapping,
            summary,
            evidence,
            recommended_actions,
        )
        report_markdown, report_metrics = _try_llm_report(
            settings.use_llm_reports,
            deterministic_report,
            {
                "input_type": input_type,
                "context": context,
                "threat_type": threat_type,
                "severity": severity,
                "risk_score": risk_score,
                "iocs": iocs,
                "enrichment": enrichment,
                "mitre_mapping": mitre_mapping,
                "summary": summary,
                "evidence": evidence,
                "recommended_actions": recommended_actions,
            },
        )

    latency = max(llm_metrics.get("latency_seconds", 0.0), report_metrics.get("latency_seconds", 0.0), getattr(timer, "latency_seconds", 0.0))
    tokens_per_second = max(llm_metrics.get("tokens_per_second", 0.0), report_metrics.get("tokens_per_second", 0.0))

    return {
        "threat_type": threat_type,
        "severity": severity,
        "risk_score": risk_score,
        "iocs": iocs,
        "enrichment": enrichment,
        "mitre_mapping": mitre_mapping,
        "summary": summary,
        "evidence": evidence,
        "recommended_actions": recommended_actions,
        "report_markdown": report_markdown,
        "runtime": runtime_payload(latency, tokens_per_second),
    }


def _try_llm_classification(text: str, context: str, iocs: dict) -> tuple[dict | None, dict]:
    """Build the structured prompt and call the configured LLM provider."""
    system = (
        "You are AfriShield AI, a cybersecurity threat intelligence assistant focused on African cyber defense. "
        "Return only valid JSON."
    )
    user = f"""
Analyze the following input and classify the cyber threat.

Return JSON using this schema:
{{
  "threat_type": "PHISHING | SCAM | CREDENTIAL_THEFT | MALWARE | BUSINESS_EMAIL_COMPROMISE | MISINFORMATION | BENIGN | UNKNOWN_SUSPICIOUS",
  "severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "summary": "short explanation",
  "evidence": ["evidence item"],
  "recommended_actions": ["action"]
}}

Input:
{text}

Extracted IOCs:
{json.dumps(iocs)}

Context:
{context}
"""
    try:
        return call_chat_json([{"role": "system", "content": system}, {"role": "user", "content": user}])
    except Exception:
        # The MVP should keep working during demos even if model inference fails.
        return None, {"latency_seconds": 0.0, "tokens_per_second": 0.0}


def _try_llm_report(enabled: bool, fallback_report: str, analysis: dict) -> tuple[str, dict]:
    """Ask the LLM to write the report, falling back to the deterministic one."""
    if not enabled:
        return fallback_report, {"latency_seconds": 0.0, "tokens_per_second": 0.0}
    system = "You are AfriShield AI, a SOC reporting assistant. Write concise Markdown only."
    user = f"""
Generate a clear incident report in Markdown using these sections:
1. Executive Summary
2. Threat Classification
3. Risk Score
4. Indicators of Compromise
5. Threat Feed Enrichment
6. MITRE ATT&CK Mapping
7. Evidence
8. Recommended Response Actions
9. Analyst Notes

Threat analysis JSON:
{json.dumps(analysis)}
"""
    try:
        report, metrics = call_chat_text([{"role": "system", "content": system}, {"role": "user", "content": user}])
    except Exception:
        return fallback_report, {"latency_seconds": 0.0, "tokens_per_second": 0.0}
    if not report or "# " not in report:
        return fallback_report, metrics
    return report, metrics


def _valid_threat_type(value: object, fallback: str) -> str:
    """Normalize model threat labels into the API vocabulary."""
    if not isinstance(value, str):
        return fallback
    normalized = value.upper().replace(" ", "_").replace("-", "_")
    aliases = {
        "MALICIOUS": "UNKNOWN_SUSPICIOUS",
        "SUSPICIOUS": "UNKNOWN_SUSPICIOUS",
        "CREDENTIAL_HARVESTING": "CREDENTIAL_THEFT",
        "CREDENTIALS_THEFT": "CREDENTIAL_THEFT",
        "BEC": "BUSINESS_EMAIL_COMPROMISE",
    }
    return aliases.get(normalized, normalized) if aliases.get(normalized, normalized) in ALLOWED_THREAT_TYPES else fallback


def _valid_string(value: object, fallback: str) -> str:
    """Accept non-empty model text, otherwise keep the deterministic fallback."""
    return value.strip() if isinstance(value, str) and value.strip() else fallback


def _valid_string_list(value: object, fallback: list[str]) -> list[str]:
    """Clean model-provided evidence/actions while preserving safe fallbacks."""
    if not isinstance(value, list):
        return fallback
    cleaned = [item.strip() for item in value if isinstance(item, str) and item.strip()]
    return cleaned or fallback


def _max_severity(left: str, right: str) -> str:
    """Return the higher of two severity labels."""
    return left if SEVERITY_RANK[left] >= SEVERITY_RANK[right] else right
