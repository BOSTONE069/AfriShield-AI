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
from backend.app.versioning import component_versions

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
    "NEEDS_REVIEW",
}
LLM_THREAT_TYPES = ALLOWED_THREAT_TYPES - {"NEEDS_REVIEW"}
ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
SEVERITY_SCORE_FLOORS = {"LOW": 0, "MEDIUM": 21, "HIGH": 51, "CRITICAL": 76}


# Agents are stateless; instantiate once at module load to avoid per-request overhead.
_preprocessing = PreprocessingAgent()
_ioc = IOCAgent()
_classification = ClassificationAgent()
_enrichment = EnrichmentAgent()
_risk = RiskAgent()
_mitre = MitreAgent()
_report = ReportAgent()


def analyze_threat(
    input_type: str,
    content: str,
    context: str = "Kenya",
    *,
    remote_processing_consent: bool = False,
) -> dict:
    """Run the complete analysis pipeline and return the API response object."""
    settings = get_settings()
    normalized = _preprocessing.run(content)
    remote_provider = settings.llm_provider == "openai_compatible"
    remote_processing_allowed = not remote_provider or remote_processing_consent
    privacy = {
        "llm_provider": settings.llm_provider,
        "remote_processing_consent": remote_processing_consent,
        "remote_processing_allowed": remote_processing_allowed,
        "evidence_transmitted_to_remote_llm": bool(settings.use_llm and remote_provider and remote_processing_consent),
    }
    versions = component_versions()

    with Timer() as timer:
        iocs = _ioc.run(normalized)
        classification = _classification.run(normalized, iocs)
        if remote_processing_allowed:
            llm_analysis, llm_metrics = _try_llm_classification(normalized, context, iocs)
        else:
            llm_analysis, llm_metrics = None, {"latency_seconds": 0.0, "tokens_per_second": 0.0}
        enrichment = _enrichment.run(iocs)
        locked_feed_findings = _locked_feed_findings(enrichment)

        threat_type = classification.threat_type
        summary = classification.summary
        deterministic_evidence = list(classification.evidence)
        evidence = list(deterministic_evidence)
        recommended_actions = list(classification.recommended_actions)
        llm_threat_type: str | None = None
        conflicts: list[str] = []

        if llm_analysis:
            llm_threat_type = _valid_threat_type(llm_analysis.get("threat_type"), threat_type)
            threat_type, conflicts = _resolve_threat_type(classification.threat_type, llm_threat_type)
            if classification.threat_type == "UNKNOWN_SUSPICIOUS" and threat_type not in {
                "UNKNOWN_SUSPICIOUS",
                "NEEDS_REVIEW",
            }:
                summary = _valid_string(llm_analysis.get("summary"), summary)
            llm_evidence = [
                f"LLM observation (untrusted): {item}" for item in _valid_string_list(llm_analysis.get("evidence"), [])
            ]
            evidence = _merge_string_lists(evidence, llm_evidence)

        if locked_feed_findings:
            evidence = _merge_string_lists(
                evidence,
                [f"Threat-feed match: {finding['details']}" for finding in locked_feed_findings],
            )
            if llm_threat_type == "BENIGN":
                conflicts.append("The LLM returned BENIGN despite a malicious threat-feed match.")
                threat_type = "NEEDS_REVIEW"
            if classification.threat_type == "BENIGN":
                conflicts.append("The deterministic classification conflicts with a malicious threat-feed match.")
                threat_type = "NEEDS_REVIEW"

        if conflicts:
            summary = (
                "Automated sources disagree. Keep protective controls in place and route this case to a human analyst."
            )
            recommended_actions = _review_actions(classification.threat_type, recommended_actions)

        # Establish the immutable deterministic minimum before considering
        # threat intelligence or untrusted model output.
        risk_score, _, score_factors = _risk.run(normalized, iocs, classification.threat_type, deterministic_evidence)
        deterministic_minimum = risk_score

        if locked_feed_findings:
            risk_score = _apply_score_floor(
                risk_score,
                80,
                score_factors,
                "Malicious threat-feed lock",
                "threat_feed",
                "A local threat-feed match enforces a critical-risk floor.",
                record_when_satisfied=True,
            )

        if llm_analysis and llm_threat_type:
            llm_score, _, _ = _risk.run(normalized, iocs, llm_threat_type, evidence)
            risk_score = _apply_score_floor(
                risk_score,
                llm_score,
                score_factors,
                "LLM risk escalation",
                "llm",
                "The untrusted model may increase, but never decrease, the deterministic score.",
            )
            llm_severity = llm_analysis.get("severity")
            if llm_severity in ALLOWED_SEVERITIES:
                risk_score = _apply_score_floor(
                    risk_score,
                    SEVERITY_SCORE_FLOORS[llm_severity],
                    score_factors,
                    "LLM severity escalation",
                    "llm",
                    f"The model proposed {llm_severity} severity; only upward movement is permitted.",
                )

        severity = _severity_from_score(risk_score)
        evidence_strength = _evidence_strength(deterministic_evidence, iocs, locked_feed_findings)
        confidence = _decision_confidence(
            classification.threat_type,
            deterministic_evidence,
            locked_feed_findings,
            conflicts,
        )
        decision_details = {
            "policy": "deterministic_minimum_v1",
            "deterministic_threat_type": classification.threat_type,
            "llm_threat_type": llm_threat_type,
            "threat_feed_lock": bool(locked_feed_findings),
            "deterministic_minimum_score": deterministic_minimum,
            "conflicts": list(dict.fromkeys(conflicts)),
        }

        mapping_type = classification.threat_type if threat_type == "NEEDS_REVIEW" else threat_type
        mitre_mapping = _mitre.run(mapping_type)
        deterministic_reports = _report.run_all(
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
            confidence,
            evidence_strength,
            score_factors,
            decision_details,
        )
        deterministic_report = deterministic_reports["technical_soc_report"]
        report_markdown, report_metrics = _try_llm_report(
            settings.use_llm_reports and remote_processing_allowed,
            deterministic_report,
            {
                "input_type": input_type,
                "context": context,
                "threat_type": threat_type,
                "severity": severity,
                "risk_score": risk_score,
                "confidence": confidence,
                "evidence_strength": evidence_strength,
                "score_factors": score_factors,
                "decision_details": decision_details,
                "privacy": privacy,
                "component_versions": versions,
                "iocs": iocs,
                "enrichment": enrichment,
                "mitre_mapping": mitre_mapping,
                "summary": summary,
                "evidence": evidence,
                "recommended_actions": recommended_actions,
            },
        )
        report_variants = {**deterministic_reports, "technical_soc_report": report_markdown}

    latency = max(
        llm_metrics.get("latency_seconds", 0.0),
        report_metrics.get("latency_seconds", 0.0),
        getattr(timer, "latency_seconds", 0.0),
    )
    tokens_per_second = max(llm_metrics.get("tokens_per_second", 0.0), report_metrics.get("tokens_per_second", 0.0))

    return {
        "threat_type": threat_type,
        "severity": severity,
        "risk_score": risk_score,
        "confidence": confidence,
        "evidence_strength": evidence_strength,
        "score_factors": score_factors,
        "decision_details": decision_details,
        "privacy": privacy,
        "component_versions": versions,
        "iocs": iocs,
        "enrichment": enrichment,
        "mitre_mapping": mitre_mapping,
        "summary": summary,
        "evidence": evidence,
        "recommended_actions": recommended_actions,
        "report_markdown": report_markdown,
        "report_variants": report_variants,
        "runtime": runtime_payload(latency, tokens_per_second),
    }


def _try_llm_classification(text: str, context: str, iocs: dict) -> tuple[dict | None, dict]:
    """Build the structured prompt and call the configured LLM provider."""
    system = (
        "You are AfriShield Cyber Defence, a cybersecurity threat intelligence assistant focused on African cyber defense. "
        "Return only valid JSON."
    )
    user = f"""
Analyze the following input and classify the cyber threat.

Return JSON using this schema:
{{
  "threat_type": "PHISHING | SCAM | CREDENTIAL_THEFT | MALWARE | BUSINESS_EMAIL_COMPROMISE | MISINFORMATION | BENIGN | UNKNOWN_SUSPICIOUS",
  "severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "confidence": "LOW | MEDIUM | HIGH",
  "evidence_strength": "LOW | MEDIUM | HIGH",
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
    system = "You are AfriShield Cyber Defence, a SOC reporting assistant. Write concise Markdown only."
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
    return aliases.get(normalized, normalized) if aliases.get(normalized, normalized) in LLM_THREAT_TYPES else fallback


def _valid_string(value: object, fallback: str) -> str:
    """Accept non-empty model text, otherwise keep the deterministic fallback."""
    return value.strip() if isinstance(value, str) and value.strip() else fallback


def _valid_string_list(value: object, fallback: list[str]) -> list[str]:
    """Clean model-provided evidence/actions while preserving safe fallbacks."""
    if not isinstance(value, list):
        return fallback
    cleaned = [item.strip() for item in value if isinstance(item, str) and item.strip()]
    return cleaned or fallback


def _resolve_threat_type(deterministic: str, llm_value: str) -> tuple[str, list[str]]:
    """Merge labels while making material source disagreement explicit."""
    if deterministic == llm_value:
        return deterministic, []
    if deterministic == "UNKNOWN_SUSPICIOUS" and llm_value not in {"BENIGN", "UNKNOWN_SUSPICIOUS"}:
        return llm_value, []
    return (
        "NEEDS_REVIEW",
        [f"Deterministic and LLM classifications disagree: {deterministic} versus {llm_value}."],
    )


def _merge_string_lists(primary: list[str], additions: list[str], limit: int = 12) -> list[str]:
    """Append unique model evidence without discarding deterministic evidence."""
    merged = list(primary)
    seen = {item.casefold() for item in merged}
    for item in additions:
        if item.casefold() not in seen:
            merged.append(item)
            seen.add(item.casefold())
        if len(merged) >= limit:
            break
    return merged


def _locked_feed_findings(enrichment: list[dict]) -> list[dict]:
    """Return authoritative malicious feed hits that impose a risk floor."""
    return [
        finding
        for finding in enrichment
        if finding.get("verdict") == "malicious" and "threat feed" in str(finding.get("source", "")).lower()
    ]


def _apply_score_floor(
    current: int,
    proposed: int,
    factors: list[dict],
    name: str,
    source: str,
    description: str,
    *,
    record_when_satisfied: bool = False,
) -> int:
    """Apply only upward score movement and record the exact contribution."""
    bounded = min(max(proposed, 0), 100)
    if bounded <= current:
        if record_when_satisfied:
            factors.append(
                {
                    "name": name,
                    "points": 0,
                    "source": source,
                    "description": f"{description} The existing score already satisfies this floor.",
                }
            )
        return current
    factors.append(
        {
            "name": name,
            "points": bounded - current,
            "source": source,
            "description": description,
        }
    )
    return bounded


def _severity_from_score(score: int) -> str:
    if score <= 20:
        return "LOW"
    if score <= 50:
        return "MEDIUM"
    if score <= 75:
        return "HIGH"
    return "CRITICAL"


def _evidence_strength(deterministic_evidence: list[str], iocs: dict, locked_feed_findings: list[dict]) -> str:
    """Rate the strength of trusted evidence separately from verdict confidence."""
    if locked_feed_findings or iocs.get("hashes") or len(deterministic_evidence) >= 3:
        return "HIGH"
    if deterministic_evidence or any(iocs.get(key) for key in ("urls", "domains", "ips")):
        return "MEDIUM"
    return "LOW"


def _decision_confidence(
    deterministic_type: str,
    deterministic_evidence: list[str],
    locked_feed_findings: list[dict],
    conflicts: list[str],
) -> str:
    """Rate confidence in the decision without conflating it with severity."""
    if conflicts:
        return "LOW"
    if locked_feed_findings or len(deterministic_evidence) >= 3:
        return "HIGH"
    if deterministic_type == "BENIGN" and not deterministic_evidence:
        return "MEDIUM"
    return "MEDIUM"


def _review_actions(deterministic_type: str, deterministic_actions: list[str]) -> list[str]:
    """Return safe actions while an automated disagreement awaits review."""
    actions = [
        "Escalate the conflicting verdicts to a human security analyst.",
        "Keep links, attachments, accounts, and payments blocked pending review.",
        "Preserve the message and all analysis evidence for investigation.",
    ]
    if deterministic_type != "BENIGN":
        actions = _merge_string_lists(actions, deterministic_actions)
    return actions
