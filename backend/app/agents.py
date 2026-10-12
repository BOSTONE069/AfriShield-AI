"""Small agent classes that make the analysis pipeline explicit.

This is not a heavy multi-agent framework. Each agent owns one step of the SOC
workflow, which keeps the code readable while satisfying the multi-agent MVP
idea from the project brief.
"""

from backend.app.enrichment import enrich_iocs
from backend.app.ioc_extractor import extract_iocs
from backend.app.mitre_mapper import map_to_mitre
from backend.app.report_generator import generate_report, generate_report_bundle
from backend.app.risk_scoring import calculate_risk_score_with_factors, severity_from_score
from backend.app.threat_classifier import Classification, classify_threat


class PreprocessingAgent:
    """Normalizes raw user input before downstream analysis."""

    def run(self, content: str) -> str:
        return " ".join(content.strip().split())


class IOCAgent:
    """Extracts indicators of compromise from normalized text."""

    def run(self, text: str) -> dict:
        return extract_iocs(text)


class ClassificationAgent:
    """Produces a deterministic threat classification baseline."""

    def run(self, text: str, iocs: dict) -> Classification:
        return classify_threat(text, iocs)


class EnrichmentAgent:
    """Enriches IOCs with bundled local threat-feed and heuristic findings."""

    def run(self, iocs: dict) -> list[dict]:
        return enrich_iocs(iocs)


class RiskAgent:
    """Calculates score and severity from classification evidence."""

    def run(self, text: str, iocs: dict, threat_type: str, evidence: list[str]) -> tuple[int, str, list[dict]]:
        score, factors = calculate_risk_score_with_factors(text, iocs, threat_type, evidence)
        return score, severity_from_score(score), factors


class MitreAgent:
    """Maps the final threat type to ATT&CK-style techniques."""

    def run(self, threat_type: str) -> list[dict]:
        return map_to_mitre(threat_type)


class ReportAgent:
    """Builds the final Markdown reports for different audiences."""

    def run(
        self,
        input_type: str,
        context: str,
        threat_type: str,
        severity: str,
        risk_score: int,
        iocs: dict,
        enrichment: list[dict],
        mitre_mapping: list[dict],
        summary: str,
        evidence: list[str],
        recommended_actions: list[str],
    ) -> str:
        return generate_report(
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

    def run_all(
        self,
        input_type: str,
        context: str,
        threat_type: str,
        severity: str,
        risk_score: int,
        iocs: dict,
        enrichment: list[dict],
        mitre_mapping: list[dict],
        summary: str,
        evidence: list[str],
        recommended_actions: list[str],
        confidence: str = "MEDIUM",
        evidence_strength: str = "LOW",
        score_factors: list[dict] | None = None,
        decision_details: dict | None = None,
    ) -> dict[str, str]:
        """Return all supported report variants for one analysis."""
        return generate_report_bundle(
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
