"""Privacy-preserving JSON audit events for API access."""

from __future__ import annotations

import json
import logging
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

from backend.app.config import get_settings

LOGGER = logging.getLogger("afrishield.audit")
_LOCK = threading.Lock()


def write_audit_event(event: dict) -> None:
    """Log request metadata without request bodies, evidence, or API keys."""
    record = {"timestamp": datetime.now(UTC).isoformat(), **event}
    line = json.dumps(record, ensure_ascii=True, sort_keys=True)
    LOGGER.info(line)
    directory = get_settings().audit_log_path
    if directory is None:
        return
    with _LOCK:
        directory.mkdir(parents=True, exist_ok=True)
        destination = directory / f"audit-{datetime.now(UTC):%Y-%m-%d}.jsonl"
        with destination.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        _purge_expired_logs(directory, get_settings().audit_retention_days)


def _purge_expired_logs(directory: Path, retention_days: int) -> None:
    cutoff = datetime.now(UTC).date() - timedelta(days=retention_days)
    for path in directory.glob("audit-*.jsonl"):
        try:
            log_date = datetime.strptime(path.stem.removeprefix("audit-"), "%Y-%m-%d").date()
        except ValueError:
            continue
        if log_date < cutoff:
            path.unlink(missing_ok=True)
