"""Encrypted SQLite persistence with automatic feedback retention."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta

from cryptography.fernet import Fernet, InvalidToken

from backend.app.config import get_settings

_WRITE_LOCK = threading.Lock()


class FeedbackStorageError(RuntimeError):
    """Raised when encrypted feedback storage is unavailable or misconfigured."""


def _cipher() -> Fernet:
    key = get_settings().data_encryption_key
    if not key:
        raise FeedbackStorageError("DATA_ENCRYPTION_KEY is required for feedback persistence")
    try:
        return Fernet(key.encode())
    except (ValueError, TypeError) as exc:
        raise FeedbackStorageError("DATA_ENCRYPTION_KEY must be a valid Fernet key") from exc


def encryption_is_configured() -> bool:
    """Validate the at-rest encryption key without exposing it."""
    try:
        _cipher()
    except FeedbackStorageError:
        return False
    return True


def _connect() -> sqlite3.Connection:
    path = get_settings().feedback_database_path
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    connection = sqlite3.connect(path, timeout=5)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS feedback (
            feedback_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            encrypted_payload BLOB NOT NULL
        )
        """
    )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return connection


def save_feedback(payload: dict) -> dict:
    """Encrypt and persist one analyst review, then enforce retention."""
    now = datetime.now(UTC)
    feedback_id = str(uuid.uuid4())
    record = {"feedback_id": feedback_id, "created_at": now.isoformat(), **payload}
    encrypted = _cipher().encrypt(json.dumps(record, ensure_ascii=True).encode())
    expires_at = now + timedelta(days=get_settings().feedback_retention_days)
    with _WRITE_LOCK, _connect() as connection:
        connection.execute("DELETE FROM feedback WHERE expires_at <= ?", (now.isoformat(),))
        connection.execute(
            "INSERT INTO feedback (feedback_id, created_at, expires_at, encrypted_payload) VALUES (?, ?, ?, ?)",
            (feedback_id, now.isoformat(), expires_at.isoformat(), encrypted),
        )
    return {"status": "saved", "feedback_id": feedback_id}


def load_feedback() -> list[dict]:
    """Decrypt unexpired feedback for authorized administrative workflows."""
    now = datetime.now(UTC).isoformat()
    cipher = _cipher()
    with _WRITE_LOCK, _connect() as connection:
        connection.execute("DELETE FROM feedback WHERE expires_at <= ?", (now,))
        rows = connection.execute("SELECT encrypted_payload FROM feedback ORDER BY created_at").fetchall()
    try:
        return [json.loads(cipher.decrypt(row[0])) for row in rows]
    except (InvalidToken, json.JSONDecodeError) as exc:
        raise FeedbackStorageError("Stored feedback could not be decrypted") from exc


def purge_expired_feedback() -> int:
    """Delete expired encrypted rows and return the affected count."""
    with _WRITE_LOCK, _connect() as connection:
        cursor = connection.execute("DELETE FROM feedback WHERE expires_at <= ?", (datetime.now(UTC).isoformat(),))
        return cursor.rowcount


def import_feedback_records(records: list[dict]) -> int:
    """Atomically import legacy records using stable IDs and encrypted payloads."""
    cipher = _cipher()
    retention = timedelta(days=get_settings().feedback_retention_days)
    rows: list[tuple[str, str, str, bytes]] = []
    for payload in records:
        feedback_id = str(payload.get("feedback_id") or uuid.uuid4())
        created_at = str(payload.get("created_at") or datetime.now(UTC).isoformat())
        try:
            created = datetime.fromisoformat(created_at)
        except ValueError as exc:
            raise FeedbackStorageError(f"Invalid created_at for feedback {feedback_id}") from exc
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        normalized = {**payload, "feedback_id": feedback_id, "created_at": created.isoformat()}
        encrypted = cipher.encrypt(json.dumps(normalized, ensure_ascii=True).encode())
        rows.append((feedback_id, created.isoformat(), (created + retention).isoformat(), encrypted))

    with _WRITE_LOCK, _connect() as connection:
        before = connection.total_changes
        connection.executemany(
            "INSERT OR IGNORE INTO feedback (feedback_id, created_at, expires_at, encrypted_payload) VALUES (?, ?, ?, ?)",
            rows,
        )
        return connection.total_changes - before


def feedback_metrics() -> dict:
    """Summarize analyst outcomes without exposing encrypted case content."""
    records = load_feedback()
    reviewed = [record for record in records if record.get("review_status") in {"reviewed", "adjudicated"}]
    verdicts = Counter(str(record.get("verdict", "unknown")) for record in reviewed)
    categories = Counter(
        str(record["error_category"]) for record in reviewed if record.get("error_category") is not None
    )
    fingerprints = Counter(
        str(record.get("component_versions", {}).get("component_fingerprint", "unknown")) for record in reviewed
    )
    correct = verdicts.get("correct", 0)
    return {
        "total_records": len(records),
        "reviewed_records": len(reviewed),
        "pending_records": len(records) - len(reviewed),
        "verdict_counts": dict(sorted(verdicts.items())),
        "error_category_counts": dict(sorted(categories.items())),
        "analyst_agreement_rate": round(correct / len(reviewed), 4) if reviewed else 0.0,
        "component_fingerprint_counts": dict(sorted(fingerprints.items())),
    }
