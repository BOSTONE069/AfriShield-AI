"""Tests for parser isolation, encrypted persistence, retention, and privacy."""

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import backend.app.analyzer as analyzer
from backend.app.audit import write_audit_event
from backend.app.config import get_settings
from backend.app.document_parser import (
    DocumentParseError,
    extract_document_text_controlled,
    validate_upload_type,
)
from backend.app.feedback import (
    feedback_metrics,
    import_feedback_records,
    load_feedback,
    purge_expired_feedback,
    save_feedback,
)
from backend.app.schemas import FeedbackRequest


def test_upload_type_requires_matching_mime_and_signature() -> None:
    validate_upload_type("message.txt", "text/plain", b"hello")
    validate_upload_type("message.pdf", "application/pdf", b"%PDF-1.7")

    with pytest.raises(DocumentParseError) as mime_error:
        validate_upload_type("message.pdf", "text/plain", b"%PDF-1.7")
    with pytest.raises(DocumentParseError) as signature_error:
        validate_upload_type("message.pdf", "application/pdf", b"not-pdf")

    assert mime_error.value.code == "invalid_mime_type"
    assert signature_error.value.code == "invalid_file_signature"


def test_controlled_parser_extracts_text_and_enforces_deadline() -> None:
    text = extract_document_text_controlled(
        "message.txt",
        b"safe text",
        max_pages=2,
        max_chars=100,
        timeout_seconds=3,
        memory_limit_mb=128,
    )
    assert text == "safe text"

    with pytest.raises(DocumentParseError, match="time limit") as exc_info:
        extract_document_text_controlled(
            "message.txt",
            b"safe text",
            max_pages=2,
            max_chars=100,
            timeout_seconds=0.0001,
            memory_limit_mb=128,
        )
    assert exc_info.value.code == "parser_timeout"


def test_feedback_is_encrypted_and_expired_rows_are_removed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = get_settings()
    database = tmp_path / "feedback.db"
    monkeypatch.setattr(settings, "feedback_database_path", database)
    saved = save_feedback({"analyst_note": "private investigation note", "verdict": "correct"})

    assert saved["status"] == "saved"
    assert b"private investigation note" not in database.read_bytes()
    assert load_feedback()[0]["analyst_note"] == "private investigation note"

    expired = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE feedback SET expires_at = ?", (expired,))
    assert purge_expired_feedback() == 1
    assert load_feedback() == []

    legacy = {
        "feedback_id": "legacy-id",
        "created_at": datetime.now(UTC).isoformat(),
        "analyst_note": "legacy private note",
    }
    assert import_feedback_records([legacy]) == 1
    assert import_feedback_records([legacy]) == 0
    assert load_feedback()[0]["feedback_id"] == "legacy-id"
    metrics = feedback_metrics()
    assert metrics["total_records"] == 1


def test_remote_llm_requires_explicit_consent(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "llm_provider", "openai_compatible")
    monkeypatch.setattr(settings, "use_llm", True)

    def unexpected_remote_call(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("Remote LLM must not be called without consent")

    monkeypatch.setattr(analyzer, "call_chat_json", unexpected_remote_call)
    result = analyzer.analyze_threat("text", "Normal department meeting", "Kenya")

    assert result["privacy"]["remote_processing_allowed"] is False
    assert result["privacy"]["evidence_transmitted_to_remote_llm"] is False


def test_audit_log_excludes_request_content(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "audit_log_path", tmp_path)
    write_audit_event({"request_id": "audit-test", "path": "/api/analyze", "status": 200})

    content = next(tmp_path.glob("audit-*.jsonl")).read_text(encoding="utf-8")
    assert "audit-test" in content
    assert "evidence" not in content


def test_false_negative_feedback_requires_a_reason() -> None:
    analysis = analyzer.analyze_threat("text", "safe", "Kenya")
    with pytest.raises(ValueError, match="require a reason"):
        FeedbackRequest.model_validate(
            {
                "case_id": "AFS-1",
                "verdict": "incorrect",
                "rating": 5,
                "original_content": "safe",
                "original_input_type": "text",
                "original_context": "Kenya",
                "error_category": "FALSE_NEGATIVE",
                "analysis": analysis,
            }
        )
