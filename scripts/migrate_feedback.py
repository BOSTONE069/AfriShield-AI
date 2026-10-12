#!/usr/bin/env python3
"""Migrate legacy plaintext feedback into encrypted SQLite storage."""

from __future__ import annotations

import json
import os

from cryptography.fernet import Fernet

from backend.app.config import get_settings
from backend.app.feedback import import_feedback_records


def main() -> int:
    settings = get_settings()
    source = settings.legacy_feedback_path
    if not source.exists():
        print(f"No legacy feedback file found at {source}")
        return 0
    if not settings.data_encryption_key:
        raise SystemExit("DATA_ENCRYPTION_KEY is required before migration")

    records = []
    with source.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"Malformed JSON on line {line_number}; no files were changed") from exc

    imported = import_feedback_records(records)

    cipher = Fernet(settings.data_encryption_key.encode())
    archive = source.with_suffix(source.suffix + ".fernet")
    archive.write_bytes(cipher.encrypt(source.read_bytes()))
    os.chmod(archive, 0o600)
    source.unlink()
    print(f"Migrated {imported} new records to {settings.feedback_database_path}")
    print(f"Encrypted recovery archive: {archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
