"""Persistence helpers for analyst feedback.

Feedback is stored as JSON Lines to keep the MVP lightweight and transparent.
Each line is one analyst review that can later be imported into SQLite,
PostgreSQL, or an evaluation notebook.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
FEEDBACK_PATH = DATA_DIR / "feedback.jsonl"


def save_feedback(payload: dict) -> dict:
    """Append one analyst feedback record and return its generated ID."""
    DATA_DIR.mkdir(exist_ok=True)
    feedback_id = str(uuid.uuid4())
    record = {
        "feedback_id": feedback_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    with FEEDBACK_PATH.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=True) + "\n")
    return {"status": "saved", "feedback_id": feedback_id}


def load_feedback() -> list[dict]:
    """Load stored analyst feedback for review or tests."""
    if not FEEDBACK_PATH.exists():
        return []
    with FEEDBACK_PATH.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]
