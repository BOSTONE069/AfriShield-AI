import hashlib
import html
import os
from datetime import datetime, timezone
from typing import Any

import pandas as pd
import requests
import streamlit as st


API_BASE = os.getenv("AFRISHIELD_API_BASE", "http://localhost:8000")
INPUT_TYPES = ["email", "url", "sms", "social_message", "text"]
SEVERITY_COLORS = {
    "LOW": "#10b981",
    "MEDIUM": "#f59e0b",
    "HIGH": "#ef4444",
    "CRITICAL": "#991b1b",
}


st.set_page_config(page_title="AfriShield AI", layout="wide", initial_sidebar_state="expanded")


def esc(value: object) -> str:
    return html.escape(str(value))


def inject_styles() -> None:
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

        .topbar {
            background: #ffffff;
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 16px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 20px;
            box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
            margin-bottom: 14px;
        }

        .topbar-title {
            color: #0f172a;
            font-size: 1.46rem;
            font-weight: 820;
            line-height: 1.2;
        }

        .topbar-subtitle {
            color: var(--muted);
            font-size: 0.9rem;
            margin-top: 3px;
        }

        .chip-row {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            justify-content: flex-end;
        }

        .chip {
            border: 1px solid #cbd5e1;
            background: #f8fafc;
            color: #334155;
            border-radius: 999px;
            padding: 6px 10px;
            font-weight: 720;
            font-size: 0.78rem;
            white-space: nowrap;
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

        div[data-testid="stTextArea"] textarea,
        div[data-testid="stTextInput"] input,
        div[data-baseweb="select"] {
            border-radius: 8px;
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
            .topbar,
            .case-header {
                display: block;
            }

            .chip-row {
                justify-content: flex-start;
                margin-top: 12px;
            }

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


@st.cache_data(ttl=30)
def load_samples() -> list[dict[str, Any]]:
    try:
        response = requests.get(f"{API_BASE}/api/samples", timeout=5)
        response.raise_for_status()
        return response.json()
    except requests.RequestException:
        return []


@st.cache_data(ttl=10)
def load_runtime() -> dict[str, Any]:
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
    response = requests.post(
        f"{API_BASE}/api/analyze",
        json={"input_type": input_type, "content": content, "context": context},
        timeout=60,
    )
    response.raise_for_status()
    return response.json()


def runtime_row(label: str, value: object) -> None:
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
    with st.sidebar:
        st.markdown(
            """
            <div class="sidebar-brand">
                <div class="brand-title">AfriShield AI</div>
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
    model_state = "LLM ACTIVE" if runtime.get("llm_enabled") else "RULES MODE"
    st.markdown(
        f"""
        <div class="topbar">
            <div>
                <div class="topbar-title">Threat Intelligence Console</div>
                <div class="topbar-subtitle">Case triage, IOC extraction, ATT&CK mapping, and SOC reporting</div>
            </div>
            <div class="chip-row">
                <span class="chip">{esc(model_state)}</span>
                <span class="chip">{esc(runtime.get("model", "Qwen/Qwen3-0.6B"))}</span>
                <span class="chip">{esc(runtime.get("cloud", "Local Workstation"))}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_band(result: dict[str, Any] | None, runtime: dict[str, Any]) -> None:
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


def action_rows(actions: list[str]) -> list[dict[str, str]]:
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
    digest = hashlib.sha1(content.encode("utf-8")).hexdigest()[:8].upper()
    return f"AFS-{digest}"


def severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#64748b")
    return (
        f'<span class="severity-badge" style="--severity-color:{color};'
        f'--severity-bg:{color}18;">{esc(severity)}</span>'
    )


def render_case(result: dict[str, Any], content: str, input_type: str, context: str, runtime: dict[str, Any]) -> None:
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


inject_styles()
runtime = load_runtime()
samples = load_samples()
render_sidebar(runtime, samples)
render_topbar(runtime)

result = st.session_state.get("analysis_result")
render_band(result, runtime)

sample_names = ["Custom investigation"] + [sample["name"] for sample in samples]
left, right = st.columns([0.82, 1.18], gap="large")

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
    content = st.text_area(
        "Evidence",
        value=selected.get("content", "") if selected else "",
        height=316,
    )
    analyze = st.button("Run Triage", type="primary", width="stretch")

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
    overview_tab, observables_tab, mitre_tab, response_tab, report_tab = st.tabs(
        ["Intelligence", "Observables", "ATT&CK", "Response", "Report"]
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

    with mitre_tab:
        st.markdown('<div class="section-label">MITRE ATT&CK Mapping</div>', unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(mappings), width="stretch", hide_index=True)

    with response_tab:
        st.markdown('<div class="section-label">Containment And Follow-Up</div>', unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(action_rows(result["recommended_actions"])), width="stretch", hide_index=True)

    with report_tab:
        st.markdown(result["report_markdown"])
        st.download_button(
            "Download Report",
            result["report_markdown"],
            file_name="afrishield-incident-report.md",
            mime="text/markdown",
        )
