#!/usr/bin/env python3
"""Safely import the UCI SMS Spam Collection into AfriShield JSONL splits."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import unicodedata
import zipfile
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any

SOURCE_ID = "uci_sms_spam_collection"
SOURCE_URL = "https://archive.ics.uci.edu/dataset/228/sms"
SOURCE_DOI = "10.24432/C5CC84"
LICENSE = "CC BY 4.0"
EXPECTED_MEMBER = "SMSSpamCollection"
VALID_LABELS = {"ham", "spam"}

EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])")
URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)\S+")
PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d\s().-]{5,}\d)(?!\w)")
LONG_CODE_RE = re.compile(r"(?<!\w)\d{5,}(?!\w)")
WHITESPACE_RE = re.compile(r"\s+")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def anonymize(text: str) -> str:
    """Normalize text and redact common direct identifiers."""
    text = unicodedata.normalize("NFKC", text).replace("\x00", "")
    text = EMAIL_RE.sub("[EMAIL]", text)
    text = URL_RE.sub("[URL]", text)
    text = PHONE_RE.sub("[PHONE_OR_CODE]", text)
    text = LONG_CODE_RE.sub("[PHONE_OR_CODE]", text)
    return WHITESPACE_RE.sub(" ", text).strip()


def read_archive(archive: Path) -> list[dict[str, Any]]:
    """Read the expected member directly, rejecting unsafe or malformed archives."""
    if not zipfile.is_zipfile(archive):
        raise ValueError(f"Not a valid ZIP archive: {archive}")

    with zipfile.ZipFile(archive) as bundle:
        names = set(bundle.namelist())
        if EXPECTED_MEMBER not in names:
            raise ValueError(f"Archive does not contain {EXPECTED_MEMBER}")
        member = bundle.getinfo(EXPECTED_MEMBER)
        if member.file_size > 10 * 1024 * 1024:
            raise ValueError("Dataset member exceeds the 10 MiB safety limit")
        raw_lines = bundle.read(member).decode("utf-8", errors="replace").splitlines()

    records: list[dict[str, Any]] = []
    seen_text: set[str] = set()
    for line_number, line in enumerate(raw_lines, start=1):
        try:
            source_label, raw_text = line.split("\t", 1)
        except ValueError as exc:
            raise ValueError(f"Malformed dataset row {line_number}") from exc
        if source_label not in VALID_LABELS:
            raise ValueError(f"Unsupported label {source_label!r} on row {line_number}")
        text = anonymize(raw_text)
        if not text:
            continue
        dedupe_key = text.casefold()
        if dedupe_key in seen_text:
            continue
        seen_text.add(dedupe_key)
        identity = hashlib.sha256(f"{SOURCE_ID}\0{source_label}\0{text}".encode()).hexdigest()
        records.append(
            {
                "id": f"UCI-SMS-{identity[:16]}",
                "text": text,
                "input_type": "sms",
                "language": "en",
                "label": "spam" if source_label == "spam" else "benign",
                "is_malicious": source_label == "spam",
                "source": SOURCE_ID,
                "source_label": source_label,
                "anonymization": "automated_direct_identifier_redaction_v1",
                "privacy_review_required": True,
            }
        )
    return records


def stratified_split(
    records: list[dict[str, Any]], validation_fraction: float = 0.2
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Create stable, label-stratified splits with no record overlap."""
    if not 0 < validation_fraction < 1:
        raise ValueError("validation_fraction must be between 0 and 1")
    grouped: dict[str, list[dict[str, Any]]] = {label: [] for label in VALID_LABELS}
    for record in records:
        grouped[record["source_label"]].append(record)

    train: list[dict[str, Any]] = []
    validation: list[dict[str, Any]] = []
    for label in sorted(grouped):
        ordered = sorted(grouped[label], key=lambda item: item["id"])
        validation_count = round(len(ordered) * validation_fraction)
        validation.extend(ordered[:validation_count])
        train.extend(ordered[validation_count:])
    return sorted(train, key=lambda item: item["id"]), sorted(validation, key=lambda item: item["id"])


def write_jsonl(records: list[dict[str, Any]], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def build_manifest(
    archive: Path,
    records: list[dict[str, Any]],
    train: list[dict[str, Any]],
    validation: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "source_id": SOURCE_ID,
        "title": "SMS Spam Collection",
        "source_url": SOURCE_URL,
        "doi": SOURCE_DOI,
        "license": LICENSE,
        "attribution": "Almeida, T. & Hidalgo, J. (2011), UCI Machine Learning Repository",
        "archive_filename": archive.name,
        "archive_sha256": sha256_file(archive),
        "import_date": date.today().isoformat(),
        "processing": {
            "deduplication": "case-insensitive exact match after normalization and redaction",
            "anonymization": "automated direct-identifier redaction; human privacy review still required",
            "split": "deterministic 80/20 stratified by source label",
        },
        "records": {
            "processed": len(records),
            "train": len(train),
            "validation": len(validation),
            "by_source_label": dict(sorted(Counter(record["source_label"] for record in records).items())),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, default=Path("training/raw/sms+spam+collection.zip"))
    parser.add_argument("--processed", type=Path, default=Path("training/processed/uci_sms_spam.jsonl"))
    parser.add_argument("--train", type=Path, default=Path("training/splits/train.jsonl"))
    parser.add_argument("--validation", type=Path, default=Path("training/splits/validation.jsonl"))
    parser.add_argument("--manifest", type=Path, default=Path("training/manifests/uci_sms_spam_collection.json"))
    args = parser.parse_args()

    records = read_archive(args.archive)
    train, validation = stratified_split(records)
    write_jsonl(records, args.processed)
    write_jsonl(train, args.train)
    write_jsonl(validation, args.validation)
    manifest = build_manifest(args.archive, records, train, validation)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest["records"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
