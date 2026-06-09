def generate_report(
    input_type: str,
    context: str,
    threat_type: str,
    severity: str,
    risk_score: int,
    iocs: dict,
    mitre_mapping: list[dict],
    summary: str,
    evidence: list[str],
    recommended_actions: list[str],
) -> str:
    ioc_lines = []
    for key, values in iocs.items():
        display = ", ".join(values) if values else "None detected"
        ioc_lines.append(f"- {key.title()}: {display}")

    mitre_lines = [
        f"- {item['tactic']} / {item['technique']}: {item.get('explanation', '')}".rstrip()
        for item in mitre_mapping
    ] or ["- No MITRE ATT&CK mapping required for current classification."]

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
