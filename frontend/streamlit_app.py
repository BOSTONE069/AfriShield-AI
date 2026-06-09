"""Streamlit dashboard for the African Cyber Defense threat intelligence console.

The page is organized like a lightweight SOC workspace:
- sidebar: runtime and demo queue
- top band: case verdict, severity, score, latency
- left pane: evidence intake
- right pane: case assessment
- tabs: intelligence, observables, ATT&CK mapping, response, report
"""

import hashlib
import html
import json
import os
from datetime import datetime, timezone
from typing import Any

import pandas as pd
import requests
import streamlit as st
import streamlit.components.v1 as components


# API_BASE can be overridden when the backend runs on a different host/port.
API_BASE = os.getenv("AFRISHIELD_API_BASE", "http://localhost:8000")
INPUT_TYPES = ["email", "url", "sms", "social_message", "text"]
SEVERITY_COLORS = {
    "LOW": "#10b981",
    "MEDIUM": "#f59e0b",
    "HIGH": "#ef4444",
    "CRITICAL": "#991b1b",
}


st.set_page_config(page_title="African Cyber Defense", layout="wide", initial_sidebar_state="expanded")


APP_THEME = st.sidebar.selectbox("Choose app theme", ["Light", "Dark"], key="app_theme")


def esc(value: object) -> str:
    """Escape dynamic values before embedding them in custom HTML blocks."""
    return html.escape(str(value))


def inject_styles(app_theme: str) -> None:
    """Inject custom CSS for a threat-intelligence-console visual style."""
    st.markdown(
        """
        <style>
        :root {
            --bg: #eef2f6;
            --ink: #111827;
            --muted: #647084;
            --line: #d7dee8;
            --panel: #ffffff;
            --nav: #0b1220;
            --nav-2: #111c2f;
            --teal: #0f766e;
            --blue: #2563eb;
            --amber: #d97706;
            --red: #dc2626;
        }

        .stApp {
            background: var(--bg);
            color: var(--ink);
        }

        .block-container {
            max-width: 1480px;
            padding-top: 20px;
            padding-bottom: 46px;
        }

        [data-testid="stSidebar"] {
            background: var(--nav);
            border-right: 1px solid #1f2a3d;
        }

        [data-testid="stSidebar"] * {
            color: #dbe7f3;
        }

        [data-testid="stSidebar"] .stSelectbox label,
        [data-testid="stSidebar"] .stTextInput label {
            color: #a8b6c7;
        }

        .sidebar-brand {
            padding: 12px 4px 18px 4px;
            border-bottom: 1px solid #22314a;
            margin-bottom: 18px;
        }

        .brand-title {
            font-size: 1.34rem;
            line-height: 1.15;
            font-weight: 800;
            color: #ffffff;
        }

        .brand-subtitle {
            color: #9fb0c4;
            font-size: 0.82rem;
            margin-top: 4px;
        }

        .runtime-row {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 14px;
            background: #121e31;
            border: 1px solid #26364f;
            border-radius: 8px;
            padding: 10px 12px;
            margin-bottom: 8px;
        }

        .runtime-label {
            color: #93a4bb;
            font-size: 0.74rem;
            font-weight: 760;
            text-transform: uppercase;
        }

        .runtime-value {
            color: #f8fafc;
            font-size: 0.84rem;
            font-weight: 650;
            text-align: right;
            overflow-wrap: anywhere;
        }

        .console-header {
            background: #ffffff;
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 18px 20px;
            box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
            margin-bottom: 10px;
            overflow: visible;
        }

        .console-title {
            color: #0f172a;
            font-size: 1.46rem;
            font-weight: 820;
            line-height: 1.25;
            margin: 0;
            padding: 0;
        }

        .console-subtitle {
            color: #475569;
            font-size: 0.92rem;
            font-weight: 620;
            line-height: 1.45;
            margin-top: 6px;
            overflow-wrap: anywhere;
        }

        .runtime-statusbar {
            background: #f8fafc;
            border: 1px solid #d7dee8;
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 14px;
            overflow: visible;
        }

        .runtime-chip-grid {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 8px;
        }

        .runtime-chip {
            background: #ffffff;
            border: 1px solid #cbd5e1;
            border-radius: 8px;
            padding: 10px 12px;
            min-height: 58px;
            overflow: visible;
        }

        .runtime-chip-label {
            color: #334155;
            font-size: 0.72rem;
            font-weight: 820;
            text-transform: uppercase;
            line-height: 1.2;
        }

        .runtime-chip-value {
            color: #0f172a;
            font-size: 0.86rem;
            font-weight: 760;
            line-height: 1.28;
            margin-top: 5px;
            overflow-wrap: anywhere;
            white-space: normal;
        }

        .shell-band {
            background: #0b1220;
            color: #e5edf5;
            border: 1px solid #1d2a3f;
            border-radius: 8px;
            padding: 14px 16px;
            margin-bottom: 16px;
        }

        .band-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }

        .band-item {
            border-left: 3px solid #334155;
            padding-left: 12px;
            min-height: 52px;
        }

        .band-label {
            color: #94a3b8;
            font-size: 0.72rem;
            font-weight: 760;
            text-transform: uppercase;
        }

        .band-value {
            color: #ffffff;
            font-size: 1.05rem;
            font-weight: 780;
            margin-top: 4px;
            overflow-wrap: anywhere;
        }

        .section-label {
            color: #334155;
            font-size: 0.78rem;
            font-weight: 820;
            text-transform: uppercase;
            margin: 4px 0 8px 0;
        }

        .workspace-panel {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 16px;
            box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
            min-height: 100%;
        }

        .case-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 14px;
            border-bottom: 1px solid #e2e8f0;
            padding-bottom: 12px;
            margin-bottom: 14px;
        }

        .case-id {
            color: #0f172a;
            font-size: 1.12rem;
            font-weight: 820;
        }

        .case-meta {
            color: #64748b;
            font-size: 0.82rem;
            margin-top: 3px;
        }

        .risk-grid {
            display: grid;
            grid-template-columns: 136px minmax(0, 1fr);
            gap: 18px;
            align-items: center;
        }

        .score-ring {
            width: 122px;
            height: 122px;
            border-radius: 50%;
            display: grid;
            place-items: center;
            background: conic-gradient(var(--risk-color) calc(var(--score) * 1%), #e5e7eb 0);
            position: relative;
        }

        .score-ring::after {
            content: "";
            position: absolute;
            width: 86px;
            height: 86px;
            border-radius: 50%;
            background: #ffffff;
        }

        .score-text {
            position: relative;
            z-index: 1;
            color: #0f172a;
            font-size: 1.55rem;
            line-height: 1;
            font-weight: 860;
        }

        .score-caption {
            position: relative;
            z-index: 1;
            color: #64748b;
            font-size: 0.7rem;
            font-weight: 780;
            margin-top: 2px;
            text-align: center;
        }

        .verdict {
            color: #0f172a;
            font-size: 1.5rem;
            font-weight: 850;
            line-height: 1.16;
            overflow-wrap: anywhere;
        }

        .summary {
            color: #334155;
            line-height: 1.56;
            margin-top: 8px;
        }

        .severity-badge {
            display: inline-flex;
            align-items: center;
            background: var(--severity-bg);
            color: var(--severity-color);
            border: 1px solid var(--severity-color);
            border-radius: 999px;
            padding: 6px 10px;
            font-size: 0.78rem;
            font-weight: 820;
            white-space: nowrap;
        }

        .signal-strip {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 10px;
            margin-top: 16px;
        }

        .signal {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 12px;
        }

        .signal-label {
            color: #64748b;
            font-size: 0.72rem;
            font-weight: 800;
            text-transform: uppercase;
        }

        .signal-value {
            color: #111827;
            font-size: 1.15rem;
            font-weight: 820;
            margin-top: 4px;
            overflow-wrap: anywhere;
        }

        .empty-state {
            border: 1px dashed #aab6c5;
            background: #f8fafc;
            border-radius: 8px;
            padding: 24px;
            color: #475569;
            min-height: 256px;
            display: grid;
            align-content: center;
        }

        .queue-item {
            border: 1px solid #d8e0ea;
            border-radius: 8px;
            padding: 10px 12px;
            background: #ffffff;
            margin-bottom: 8px;
        }

        .queue-title {
            color: #0f172a;
            font-weight: 780;
            font-size: 0.92rem;
        }

        .queue-meta {
            color: #64748b;
            font-size: 0.78rem;
            margin-top: 3px;
        }

        .stButton > button {
            border-radius: 8px;
            height: 44px;
            font-weight: 800;
            border: 1px solid #0f766e;
        }

        .stDownloadButton > button {
            border-radius: 8px;
            border: 1px solid #0f766e;
            color: #0f766e;
        }

        div[data-testid="stSelectbox"] label,
        div[data-testid="stTextInput"] label,
        div[data-testid="stTextArea"] label,
        div[data-testid="stFileUploader"] label {
            color: #1f2937;
            font-weight: 760;
        }

        div[data-testid="stTextArea"] textarea,
        div[data-testid="stTextInput"] input {
            background: #ffffff;
            color: #0f172a;
            border: 1px solid #cbd5e1;
            border-radius: 8px;
            caret-color: #0f766e;
        }

        div[data-testid="stTextArea"] textarea::placeholder,
        div[data-testid="stTextInput"] input::placeholder {
            color: #64748b;
            opacity: 1;
        }

        div[data-baseweb="select"] > div {
            background: #ffffff;
            border-color: #cbd5e1;
            border-radius: 8px;
        }

        div[data-baseweb="select"] span,
        div[data-baseweb="select"] input,
        div[data-baseweb="select"] svg {
            color: #0f172a;
            fill: #0f172a;
        }

        div[data-testid="stFileUploaderDropzone"] {
            background: #ffffff;
            border: 1px dashed #94a3b8;
            border-radius: 8px;
        }

        div[data-testid="stFileUploaderDropzone"] * {
            color: #334155;
        }

        .stTabs [data-baseweb="tab-list"] {
            gap: 3px;
            border-bottom: 1px solid #cfd8e3;
        }

        .stTabs [data-baseweb="tab"] {
            border-radius: 8px 8px 0 0;
            padding: 10px 14px;
            font-weight: 760;
        }

        @media (max-width: 860px) {
            .case-header {
                display: block;
            }

            .chip-row {
                justify-content: flex-start;
                margin-top: 12px;
            }

            .runtime-chip-grid,
            .band-grid,
            .signal-strip,
            .risk-grid {
                grid-template-columns: 1fr;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    inject_theme_overrides(app_theme)


def inject_theme_overrides(app_theme: str) -> None:
    """Apply light/dark theme overrides to the custom Streamlit CSS.

    Streamlit's built-in app theme does not automatically rewrite custom CSS,
    so this selector explicitly updates the dashboard surfaces and form fields.
    """
    if app_theme == "Dark":
        st.markdown(
            """
            <style>
            .stApp {
                background: #0f172a !important;
                color: #e5edf5 !important;
            }

            .console-header,
            .runtime-statusbar,
            .workspace-panel,
            .queue-item,
            .signal,
            .empty-state,
            .subtitlebar {
                background: #111827 !important;
                border-color: #334155 !important;
                color: #e5edf5 !important;
            }

            .console-title,
            .verdict,
            .case-id,
            .signal-value,
            .runtime-chip-value,
            .queue-title {
                color: #f8fafc !important;
            }

            .console-subtitle,
            .subtitlebar-text,
            .summary,
            .case-meta,
            .queue-meta,
            .signal-label,
            .runtime-chip-label,
            .section-label {
                color: #b6c2d1 !important;
            }

            .runtime-chip {
                background: #172033 !important;
                border-color: #334155 !important;
            }

            div[data-testid="stSelectbox"] label,
            div[data-testid="stTextInput"] label,
            div[data-testid="stTextArea"] label,
            div[data-testid="stFileUploader"] label {
                color: #e5edf5 !important;
            }

            div[data-testid="stTextArea"] textarea,
            div[data-testid="stTextInput"] input,
            div[data-baseweb="select"] > div,
            div[data-testid="stFileUploaderDropzone"] {
                background: #111827 !important;
                color: #f8fafc !important;
                border-color: #475569 !important;
            }

            div[data-baseweb="select"] span,
            div[data-baseweb="select"] input,
            div[data-testid="stFileUploaderDropzone"] * {
                color: #f8fafc !important;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
            <style>
            .stApp {
                background: #eef2f6 !important;
                color: #111827 !important;
            }

            div[data-testid="stTextArea"] textarea,
            div[data-testid="stTextInput"] input,
            div[data-baseweb="select"] > div,
            div[data-testid="stFileUploaderDropzone"] {
                background: #ffffff !important;
                color: #0f172a !important;
                border-color: #cbd5e1 !important;
            }

            div[data-baseweb="select"] span,
            div[data-baseweb="select"] input,
            div[data-testid="stFileUploaderDropzone"] * {
                color: #0f172a !important;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )


@st.cache_data(ttl=30)
def load_samples() -> list[dict[str, Any]]:
    """Fetch bundled demo cases from the backend and cache them briefly."""
    try:
        response = requests.get(f"{API_BASE}/api/samples", timeout=5)
        response.raise_for_status()
        return response.json()
    except requests.RequestException:
        return []


@st.cache_data(ttl=10)
def load_runtime() -> dict[str, Any]:
    """Fetch model/runtime metadata for the sidebar and status chips."""
    try:
        response = requests.get(f"{API_BASE}/api/runtime", timeout=5)
        response.raise_for_status()
        return response.json()
    except requests.RequestException:
        return {
            "gpu": "AMD Instinct MI300X",
            "cloud": "AMD Developer Cloud",
            "backend": "vLLM",
            "framework": "ROCm + PyTorch",
            "model": "Qwen/Qwen3-0.6B",
            "latency_seconds": 0,
            "tokens_per_second": 0,
            "llm_enabled": False,
            "llm_provider": "unavailable",
        }


def api_post_analyze(input_type: str, content: str, context: str) -> dict[str, Any]:
    """Submit one case to the FastAPI analysis endpoint."""
    response = requests.post(
        f"{API_BASE}/api/analyze",
        json={"input_type": input_type, "content": content, "context": context},
        timeout=60,
    )
    response.raise_for_status()
    return response.json()


def api_extract_document(filename: str, content: bytes) -> str:
    """Send an uploaded document to the backend text-extraction endpoint."""
    response = requests.post(
        f"{API_BASE}/api/document/extract",
        files={"file": (filename, content)},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["content"]


def api_export_pdf(report_markdown: str) -> bytes:
    """Ask the backend to convert Markdown report text into PDF bytes."""
    response = requests.post(
        f"{API_BASE}/api/report/pdf",
        json={"title": "African Cyber Defense Incident Report", "report_markdown": report_markdown},
        timeout=30,
    )
    response.raise_for_status()
    return response.content


def api_save_feedback(payload: dict[str, Any]) -> dict[str, Any]:
    """Submit analyst feedback for persistence in backend JSONL storage."""
    response = requests.post(f"{API_BASE}/api/feedback", json=payload, timeout=15)
    response.raise_for_status()
    return response.json()


def runtime_row(label: str, value: object) -> None:
    """Render one compact runtime key/value row in the sidebar."""
    st.markdown(
        f"""
        <div class="runtime-row">
            <div class="runtime-label">{esc(label)}</div>
            <div class="runtime-value">{esc(value)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_sidebar(runtime: dict[str, Any], samples: list[dict[str, Any]]) -> None:
    """Render the left-side operations rail with model status and sample queue."""
    with st.sidebar:
        st.markdown(
            """
            <div class="sidebar-brand">
                <div class="brand-title">African Cyber Defense</div>
                <div class="brand-subtitle">Threat Intelligence Operations</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown("#### Runtime")
        runtime_row("Provider", runtime.get("llm_provider", "local_transformers"))
        runtime_row("Model", runtime.get("model", "Qwen/Qwen3-0.6B"))
        runtime_row("Backend", runtime.get("backend", "Transformers local"))
        runtime_row("Framework", runtime.get("framework", "PyTorch"))
        runtime_row("Compute", runtime.get("gpu", "Local CPU"))
        runtime_row("Tokens/sec", runtime.get("tokens_per_second", 0))
        st.markdown("#### Sample Queue")
        for sample in samples[:5]:
            st.markdown(
                f"""
                <div class="queue-item">
                    <div class="queue-title">{esc(sample.get("name", "Sample"))}</div>
                    <div class="queue-meta">{esc(sample.get("input_type", "text")).upper()} · {esc(sample.get("context", "Kenya"))}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )


def render_topbar(runtime: dict[str, Any]) -> None:
    """Render the console title and a separate full runtime status bar."""
    model_state = "LLM ACTIVE" if runtime.get("llm_enabled") else "RULES MODE"
    st.markdown(
        f"""
        <div class="console-header">
            <div class="console-title">African Cyber Defense</div>
            <div class="console-subtitle">Case triage, IOC extraction, ATT&CK mapping, and SOC reporting</div>
        </div>
        <div class="runtime-statusbar">
            <div class="runtime-chip-grid">
                <div class="runtime-chip">
                    <div class="runtime-chip-label">Runtime</div>
                    <div class="runtime-chip-value">{esc(model_state)}</div>
                </div>
                <div class="runtime-chip">
                    <div class="runtime-chip-label">Provider</div>
                    <div class="runtime-chip-value">{esc(runtime.get("llm_provider", "local_transformers"))}</div>
                </div>
                <div class="runtime-chip">
                    <div class="runtime-chip-label">Model</div>
                    <div class="runtime-chip-value">{esc(runtime.get("model", "Qwen/Qwen3-0.6B"))}</div>
                </div>
                <div class="runtime-chip">
                    <div class="runtime-chip-label">Backend</div>
                    <div class="runtime-chip-value">{esc(runtime.get("backend", "Transformers local"))}</div>
                </div>
                <div class="runtime-chip">
                    <div class="runtime-chip-label">Compute</div>
                    <div class="runtime-chip-value">{esc(runtime.get("gpu", "Local CPU"))}</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_band(result: dict[str, Any] | None, runtime: dict[str, Any]) -> None:
    """Render the dark command band that summarizes the current case state."""
    threat = result["threat_type"].replace("_", " ") if result else "Awaiting Submission"
    severity = result["severity"] if result else "Not Scored"
    score = f"{result['risk_score']}/100" if result else "Pending"
    latency = f"{result.get('runtime', runtime).get('latency_seconds', 0)}s" if result else f"{runtime.get('latency_seconds', 0)}s"
    st.markdown(
        f"""
        <div class="shell-band">
            <div class="band-grid">
                <div class="band-item" style="border-left-color:#2563eb;">
                    <div class="band-label">Verdict</div>
                    <div class="band-value">{esc(threat)}</div>
                </div>
                <div class="band-item" style="border-left-color:#d97706;">
                    <div class="band-label">Severity</div>
                    <div class="band-value">{esc(severity)}</div>
                </div>
                <div class="band-item" style="border-left-color:#0f766e;">
                    <div class="band-label">Risk Score</div>
                    <div class="band-value">{esc(score)}</div>
                </div>
                <div class="band-item" style="border-left-color:#7c3aed;">
                    <div class="band-label">Inference Latency</div>
                    <div class="band-value">{esc(latency)}</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def ioc_rows(iocs: dict[str, list[str]]) -> list[dict[str, str]]:
    """Flatten IOC categories into table rows for the Observables tab."""
    rows = []
    dispositions = {
        "urls": "URL requiring blocklist review",
        "domains": "Domain requiring enrichment",
        "emails": "Sender or mailbox observable",
        "ips": "Network observable",
        "hashes": "File artifact",
    }
    for kind, values in iocs.items():
        for value in values:
            rows.append(
                {
                    "Observable Type": kind.upper(),
                    "Value": value,
                    "Disposition": dispositions.get(kind, "Observable"),
                    "Source": "Submitted content",
                }
            )
    return rows


def enrichment_rows(enrichment: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Format enrichment findings for the dashboard table."""
    return [
        {
            "Observable Type": item.get("observable_type", "observable").upper(),
            "Value": item.get("value", ""),
            "Verdict": item.get("verdict", "unknown").upper(),
            "Confidence": item.get("confidence", "unknown").upper(),
            "Source": item.get("source", "enrichment"),
            "Details": item.get("details", ""),
        }
        for item in enrichment
    ]


def action_rows(actions: list[str]) -> list[dict[str, str]]:
    """Format recommended actions as a response-priority table."""
    rows = []
    for index, action in enumerate(actions, start=1):
        rows.append(
            {
                "Priority": "P1" if index <= 2 else "P2",
                "Owner": "SOC Analyst" if index <= 3 else "Security Team",
                "Response Action": action,
            }
        )
    return rows


def case_id(content: str) -> str:
    """Generate a stable short case ID from the submitted evidence text."""
    digest = hashlib.sha1(content.encode("utf-8")).hexdigest()[:8].upper()
    return f"AFS-{digest}"


def severity_badge(severity: str) -> str:
    """Build the colored severity badge used in the case card."""
    color = SEVERITY_COLORS.get(severity, "#64748b")
    return (
        f'<span class="severity-badge" style="--severity-color:{color};'
        f'--severity-bg:{color}18;">{esc(severity)}</span>'
    )


def render_copy_report_button(report_markdown: str) -> None:
    """Render a small browser-side copy button for report text."""
    report_json = json.dumps(report_markdown)
    components.html(
        f"""
        <button id="copy-report" style="
            border:1px solid #0f766e;
            border-radius:8px;
            background:#ffffff;
            color:#0f766e;
            padding:9px 12px;
            font-weight:700;
            cursor:pointer;
        ">Copy report</button>
        <span id="copy-status" style="margin-left:10px;color:#64748b;font-size:13px;"></span>
        <script>
        const report = {report_json};
        const button = document.getElementById("copy-report");
        const status = document.getElementById("copy-status");
        button.onclick = async () => {{
            try {{
                await navigator.clipboard.writeText(report);
                status.textContent = "Copied";
            }} catch (err) {{
                status.textContent = "Copy failed";
            }}
        }};
        </script>
        """,
        height=48,
    )


def render_case(result: dict[str, Any], content: str, input_type: str, context: str, runtime: dict[str, Any]) -> None:
    """Render the active case card with score ring, verdict, and key signals."""
    iocs = result["iocs"]
    rows = ioc_rows(iocs)
    runtime_after = result.get("runtime", runtime)
    score = int(result["risk_score"])
    severity = result["severity"]
    risk_color = SEVERITY_COLORS.get(severity, "#64748b")
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    st.markdown(
        f"""
        <div class="workspace-panel">
            <div class="case-header">
                <div>
                    <div class="case-id">{esc(case_id(content))}</div>
                    <div class="case-meta">{esc(input_type.upper())} · {esc(context)} · Generated {esc(generated_at)}</div>
                </div>
                {severity_badge(severity)}
            </div>
            <div class="risk-grid">
                <div class="score-ring" style="--score:{score}; --risk-color:{risk_color};">
                    <div>
                        <div class="score-text">{score}</div>
                        <div class="score-caption">RISK</div>
                    </div>
                </div>
                <div>
                    <div class="verdict">{esc(result["threat_type"].replace("_", " "))}</div>
                    <div class="summary">{esc(result["summary"])}</div>
                </div>
            </div>
            <div class="signal-strip">
                <div class="signal">
                    <div class="signal-label">Observables</div>
                    <div class="signal-value">{len(rows)}</div>
                </div>
                <div class="signal">
                    <div class="signal-label">Evidence Items</div>
                    <div class="signal-value">{len(result.get("evidence") or [])}</div>
                </div>
                <div class="signal">
                    <div class="signal-label">ATT&CK Links</div>
                    <div class="signal-value">{len(result.get("mitre_mapping") or [])}</div>
                </div>
                <div class="signal">
                    <div class="signal-label">Model Speed</div>
                    <div class="signal-value">{esc(runtime_after.get("tokens_per_second", 0))}</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_empty_queue(samples: list[dict[str, Any]]) -> None:
    """Render the queue preview shown before any case has been analyzed."""
    preview_rows = [
        {
            "Case": sample.get("name", "Sample"),
            "Input": sample.get("input_type", "text").upper(),
            "Region": sample.get("context", "Kenya"),
            "Status": "Ready",
        }
        for sample in samples
    ]
    st.markdown('<div class="section-label">Triage Queue</div>', unsafe_allow_html=True)
    st.dataframe(pd.DataFrame(preview_rows), width="stretch", hide_index=True)


# Page composition starts here. Streamlit reruns the file top-to-bottom after
# every interaction, so persistent analysis state lives in st.session_state.
inject_styles(APP_THEME)
runtime = load_runtime()
samples = load_samples()
render_sidebar(runtime, samples)
render_topbar(runtime)

result = st.session_state.get("analysis_result")
render_band(result, runtime)

sample_names = ["Custom investigation"] + [sample["name"] for sample in samples]
left, right = st.columns([0.82, 1.18], gap="large")

# Evidence intake panel: choose a sample or paste a new suspicious message.
with left:
    st.markdown('<div class="section-label">Evidence Intake</div>', unsafe_allow_html=True)
    selected_sample = st.selectbox("Case Template", sample_names)
    selected = next((sample for sample in samples if sample["name"] == selected_sample), None)
    input_type = st.selectbox(
        "Channel",
        INPUT_TYPES,
        index=INPUT_TYPES.index(selected["input_type"]) if selected else 0,
    )
    context = st.text_input("Context", value=selected.get("context", "Kenya") if selected else "Kenya")
    uploaded_file = st.file_uploader("Upload Evidence Document", type=["txt", "md", "eml", "log", "pdf"])
    if uploaded_file is not None and st.button("Extract Document Text", width="stretch"):
        with st.spinner("Extracting document text..."):
            try:
                st.session_state.upload_text = api_extract_document(uploaded_file.name, uploaded_file.getvalue())
                st.session_state.upload_error = ""
            except requests.RequestException as exc:
                st.session_state.upload_error = str(exc)
    if st.session_state.get("upload_error"):
        st.warning(f"Document extraction failed: {st.session_state.upload_error}")
    default_content = st.session_state.get("upload_text") or (selected.get("content", "") if selected else "")
    content = st.text_area(
        "Evidence",
        value=default_content,
        height=316,
    )
    analyze = st.button("Run Triage", type="primary", width="stretch")

# Case assessment panel: shows either the active result or a neutral empty state.
with right:
    st.markdown('<div class="section-label">Case Assessment</div>', unsafe_allow_html=True)
    if result:
        render_case(
            result,
            st.session_state.get("analysis_content", content),
            st.session_state.get("analysis_input_type", input_type),
            st.session_state.get("analysis_context", context),
            runtime,
        )
    else:
        st.markdown(
            """
            <div class="empty-state">
                <div>
                    <div class="verdict">No active case selected</div>
                    <div class="summary">Queue a sample or submit new evidence to create a threat intelligence case.</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

if analyze:
    if not content.strip():
        st.warning("Evidence is required before triage can run.")
    else:
        with st.spinner("Running model-assisted threat triage..."):
            try:
                # Store request metadata with the response so the case card
                # remains stable after Streamlit reruns the page.
                st.session_state.analysis_result = api_post_analyze(input_type, content, context)
                st.session_state.analysis_content = content
                st.session_state.analysis_input_type = input_type
                st.session_state.analysis_context = context
                st.session_state.analysis_error = ""
                st.rerun()
            except requests.RequestException as exc:
                st.session_state.analysis_error = str(exc)

if st.session_state.get("analysis_error"):
    st.error(f"Analysis failed: {st.session_state.analysis_error}")

result = st.session_state.get("analysis_result")
if not result:
    st.divider()
    render_empty_queue(samples)
else:
    # Once analysis exists, the lower workspace becomes the analyst detail area.
    iocs = result["iocs"]
    rows = ioc_rows(iocs)
    evidence = result.get("evidence") or ["No strong malicious evidence detected."]
    mappings = result["mitre_mapping"] or [
        {
            "tactic": "None",
            "technique": "No mapping required",
            "explanation": "Current classification did not require ATT&CK mapping.",
        }
    ]

    st.divider()
    overview_tab, observables_tab, enrichment_tab, mitre_tab, response_tab, report_tab = st.tabs(
        ["Intelligence", "Observables", "Enrichment", "ATT&CK", "Response", "Report"]
    )

    with overview_tab:
        col_evidence, col_actions = st.columns([1, 1], gap="large")
        with col_evidence:
            st.markdown('<div class="section-label">Analytic Evidence</div>', unsafe_allow_html=True)
            st.dataframe(pd.DataFrame({"Evidence": evidence}), width="stretch", hide_index=True)
        with col_actions:
            st.markdown('<div class="section-label">Response Priorities</div>', unsafe_allow_html=True)
            st.dataframe(pd.DataFrame(action_rows(result["recommended_actions"])), width="stretch", hide_index=True)

    with observables_tab:
        st.markdown('<div class="section-label">Indicators Of Compromise</div>', unsafe_allow_html=True)
        st.dataframe(
            pd.DataFrame(rows or [{"Observable Type": "NONE", "Value": "No IOCs detected", "Disposition": "None", "Source": "Analyzer"}]),
            width="stretch",
            hide_index=True,
        )

    with enrichment_tab:
        st.markdown('<div class="section-label">Threat Feed Enrichment</div>', unsafe_allow_html=True)
        enriched = enrichment_rows(result.get("enrichment") or [])
        st.dataframe(
            pd.DataFrame(enriched or [{"Observable Type": "NONE", "Value": "No enrichment findings", "Verdict": "NONE", "Confidence": "NONE", "Source": "Local", "Details": ""}]),
            width="stretch",
            hide_index=True,
        )

    with mitre_tab:
        st.markdown('<div class="section-label">MITRE ATT&CK Mapping</div>', unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(mappings), width="stretch", hide_index=True)

    with response_tab:
        st.markdown('<div class="section-label">Containment And Follow-Up</div>', unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(action_rows(result["recommended_actions"])), width="stretch", hide_index=True)
        st.markdown('<div class="section-label">Analyst Feedback</div>', unsafe_allow_html=True)
        feedback_col_1, feedback_col_2 = st.columns([0.45, 0.55], gap="large")
        with feedback_col_1:
            feedback_verdict = st.radio("Review Result", ["correct", "incorrect", "needs_review"], horizontal=True)
            feedback_rating = st.slider("Confidence Rating", min_value=1, max_value=5, value=4)
        with feedback_col_2:
            analyst_note = st.text_area("Analyst Note", height=96)
            if st.button("Submit Feedback", width="stretch"):
                try:
                    saved = api_save_feedback(
                        {
                            "case_id": case_id(st.session_state.get("analysis_content", "")),
                            "verdict": feedback_verdict,
                            "rating": feedback_rating,
                            "analyst_note": analyst_note,
                            "analysis": result,
                        }
                    )
                    st.success(f"Feedback saved: {saved['feedback_id']}")
                except requests.RequestException as exc:
                    st.error(f"Feedback failed: {exc}")

    with report_tab:
        st.markdown(result["report_markdown"])
        export_col_1, export_col_2, export_col_3 = st.columns([0.25, 0.25, 0.5])
        with export_col_1:
            st.download_button(
                "Download Markdown",
                result["report_markdown"],
                file_name="afrishield-incident-report.md",
                mime="text/markdown",
                width="stretch",
            )
        with export_col_2:
            try:
                pdf_bytes = api_export_pdf(result["report_markdown"])
                st.download_button(
                    "Download PDF",
                    pdf_bytes,
                    file_name="afrishield-incident-report.pdf",
                    mime="application/pdf",
                    width="stretch",
                )
            except requests.RequestException as exc:
                st.warning(f"PDF export unavailable: {exc}")
        with export_col_3:
            render_copy_report_button(result["report_markdown"])
