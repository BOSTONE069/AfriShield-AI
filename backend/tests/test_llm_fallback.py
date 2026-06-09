"""Tests for graceful LLM failure handling."""

import backend.app.analyzer as analyzer


def test_analyzer_falls_back_when_llm_fails(monkeypatch):
    """Analyzer should still return a report if model inference raises."""

    def broken_llm(_messages):
        raise RuntimeError("model unavailable")

    monkeypatch.setattr(analyzer, "call_chat_json", broken_llm)
    monkeypatch.setattr(analyzer, "_try_llm_report", lambda _enabled, fallback, _analysis: (fallback, {}))
    result = analyzer.analyze_threat("sms", "Verify account at https://kra-refund-verify.com/login", "Kenya")

    assert result["threat_type"] in {"PHISHING", "CREDENTIAL_THEFT"}
    assert result["report_markdown"]
