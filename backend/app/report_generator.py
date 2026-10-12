"""Markdown incident report generation.

Each report variant is built from the same normalized analysis result. That
keeps exports consistent while letting different audiences see the level of
detail they actually need.
"""

REPORT_TYPES = {
    "executive_summary": "Executive Summary",
    "technical_soc_report": "Technical SOC Report",
    "user_advisory": "User Advisory",
    "incident_ticket": "Incident Ticket",
}


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
    confidence: str = "MEDIUM",
    evidence_strength: str = "LOW",
    score_factors: list[dict] | None = None,
    decision_details: dict | None = None,
) -> str:
    """Build the default SOC-ready Markdown report returned by /api/analyze."""
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
    )["technical_soc_report"]


def generate_report_bundle(
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
    """Build every supported Markdown report variant for one analysis."""
    sections = _report_sections(
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

    return {
        "executive_summary": _executive_summary_report(sections),
        "technical_soc_report": _technical_soc_report(sections),
        "user_advisory": _user_advisory_report(sections),
        "incident_ticket": _incident_ticket_report(sections),
    }


def _report_sections(
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
    confidence: str,
    evidence_strength: str,
    score_factors: list[dict] | None,
    decision_details: dict | None,
) -> dict:
    """Prepare reusable display lines for all report formats."""
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
    factor_lines = [
        f"- {item.get('name', 'Factor')}: {item.get('points', 0):+} points "
        f"[{item.get('source', 'unknown')}] — {item.get('description', '')}"
        for item in (score_factors or [])
    ] or ["- No score factors were recorded."]
    conflicts = (decision_details or {}).get("conflicts", [])
    conflict_lines = [f"- {item}" for item in conflicts] or ["- No automated-source conflicts detected."]

    return {
        "input_type": input_type,
        "context": context,
        "threat_type": threat_type,
        "severity": severity,
        "risk_score": risk_score,
        "confidence": confidence,
        "evidence_strength": evidence_strength,
        "summary": summary,
        "ioc_lines": ioc_lines,
        "mitre_lines": mitre_lines,
        "enrichment_lines": enrichment_lines,
        "evidence_lines": evidence_lines,
        "action_lines": action_lines,
        "factor_lines": factor_lines,
        "conflict_lines": conflict_lines,
        "primary_actions": recommended_actions[:3] or ["No immediate response action required."],
    }


def _technical_soc_report(sections: dict) -> str:
    """Full technical report for SOC analysts and security teams."""
    return "\n".join(
        [
            "# AfriShield Cyber Defence Technical SOC Report",
            "",
            "## Executive Summary",
            sections["summary"],
            "",
            "## Threat Classification",
            f"- Input Type: {sections['input_type']}",
            f"- Context: {sections['context']}",
            f"- Threat Type: {sections['threat_type']}",
            f"- Severity: {sections['severity']}",
            f"- Decision Confidence: {sections['confidence']}",
            f"- Evidence Strength: {sections['evidence_strength']}",
            "",
            "## Risk Score",
            f"{sections['risk_score']}/100",
            *sections["factor_lines"],
            "",
            "## Decision Conflicts",
            *sections["conflict_lines"],
            "",
            "## Indicators of Compromise",
            *sections["ioc_lines"],
            "",
            "## MITRE ATT&CK Mapping",
            *sections["mitre_lines"],
            "",
            "## Threat Feed Enrichment",
            *sections["enrichment_lines"],
            "",
            "## Evidence",
            *sections["evidence_lines"],
            "",
            "## Recommended Response Actions",
            *sections["action_lines"],
            "",
            "## Analyst Notes",
            "This report combines deterministic IOC extraction, local scoring rules, and optional LLM reasoning when configured.",
        ]
    )


def _executive_summary_report(sections: dict) -> str:
    """Brief leadership-facing report focused on impact and decision points."""
    return "\n".join(
        [
            "# AfriShield Cyber Defence Executive Summary",
            "",
            "## Situation",
            sections["summary"],
            "",
            "## Business Risk",
            f"- Severity: {sections['severity']}",
            f"- Risk Score: {sections['risk_score']}/100",
            f"- Decision Confidence: {sections['confidence']}",
            f"- Evidence Strength: {sections['evidence_strength']}",
            f"- Threat Type: {sections['threat_type'].replace('_', ' ')}",
            f"- Context: {sections['context']}",
            "",
            "## Recommended Decision",
            *_bullet_lines(sections["primary_actions"]),
            "",
            "## Security Team Follow-Up",
            "- Review the technical SOC report for indicators, enrichment, and ATT&CK mapping.",
            "- Confirm whether any user interacted with the suspicious message or link.",
        ]
    )


def _user_advisory_report(sections: dict) -> str:
    """Plain-language advisory suitable for staff, students, or customers."""
    return "\n".join(
        [
            "# AfriShield Cyber Defence User Advisory",
            "",
            "## What We Found",
            sections["summary"],
            "",
            "## Risk Level",
            f"{sections['severity']} ({sections['risk_score']}/100)",
            "",
            "## What You Should Do Now",
            *_bullet_lines(sections["primary_actions"]),
            "",
            "## Safety Reminder",
            "- Do not enter passwords, PINs, bank details, or verification codes on suspicious pages.",
            "- If you already clicked the link or shared information, contact your IT or security team immediately.",
        ]
    )


def _incident_ticket_report(sections: dict) -> str:
    """Ticket-style report that can be pasted into Jira, TheHive, or a SIEM note."""
    title = f"{sections['severity']} - {sections['threat_type'].replace('_', ' ')} - {sections['context']}"
    return "\n".join(
        [
            "# AfriShield Cyber Defence Incident Ticket",
            "",
            "## Title",
            title,
            "",
            "## Priority",
            sections["severity"],
            "",
            "## Category",
            sections["threat_type"],
            "",
            "## Description",
            sections["summary"],
            "",
            "## Observable Evidence",
            *sections["ioc_lines"],
            "",
            "## ATT&CK Mapping",
            *sections["mitre_lines"],
            "",
            "## Tasks",
            *_checkbox_lines(sections["primary_actions"]),
            "- [ ] Record analyst disposition and affected users.",
            "- [ ] Close ticket after containment and user notification are complete.",
        ]
    )


def _bullet_lines(items: list[str]) -> list[str]:
    """Render action strings as Markdown bullets."""
    return [f"- {item}" for item in items]


def _checkbox_lines(items: list[str]) -> list[str]:
    """Render action strings as Markdown task-list items."""
    return [f"- [ ] {item}" for item in items]
