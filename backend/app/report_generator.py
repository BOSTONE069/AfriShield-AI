"""Markdown incident report generation."""


def generate_report(
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
    """Build the SOC-ready Markdown report returned by /api/analyze."""
    ioc_lines = []
    for key, values in iocs.items():
        display = ", ".join(values) if values else "None detected"
        ioc_lines.append(f"- {key.title()}: {display}")

    # Keep empty MITRE/evidence sections explicit so the report reads cleanly
    # for benign cases as well as malicious ones.
    mitre_lines = [
        f"- {item['tactic']} / {item['technique']} ({item.get('technique_id', 'N/A')}): {item.get('explanation', '')}".rstrip()
        for item in mitre_mapping
    ] or ["- No MITRE ATT&CK mapping required for current classification."]

    enrichment_lines = [
        "- {type}: {value} | {verdict} ({confidence}) | {source} - {details}".format(
            type=item.get("observable_type", "observable").title(),
            value=item.get("value", ""),
            verdict=item.get("verdict", "unknown"),
            confidence=item.get("confidence", "unknown"),
            source=item.get("source", "enrichment"),
            details=item.get("details", ""),
        ).rstrip()
        for item in enrichment
    ] or ["- No enrichment findings were produced for the extracted observables."]

    evidence_lines = [f"- {item}" for item in evidence] or ["- No strong malicious evidence detected."]
    action_lines = [f"- {item}" for item in recommended_actions]

    return "\n".join(
        [
            "# AfriShield AI Incident Report",
            "",
            "## Executive Summary",
            summary,
            "",
            "## Threat Classification",
            f"- Input Type: {input_type}",
            f"- Context: {context}",
            f"- Threat Type: {threat_type}",
            f"- Severity: {severity}",
            "",
            "## Risk Score",
            f"{risk_score}/100",
            "",
            "## Indicators of Compromise",
            *ioc_lines,
            "",
            "## MITRE ATT&CK Mapping",
            *mitre_lines,
            "",
            "## Threat Feed Enrichment",
            *enrichment_lines,
            "",
            "## Evidence",
            *evidence_lines,
            "",
            "## Recommended Response Actions",
            *action_lines,
            "",
            "## Analyst Notes",
            "This report combines deterministic IOC extraction, local scoring rules, and optional LLM reasoning when configured.",
        ]
    )
