"""Tests for safe and deterministic training-data ingestion."""

import zipfile
from pathlib import Path

import pytest

from training.import_sms_spam import anonymize, read_archive, stratified_split


def test_anonymize_redacts_direct_identifiers() -> None:
    text = anonymize("Email me@example.com, visit https://bad.example/x or call +254 712 345 678")

    assert "me@example.com" not in text
    assert "bad.example" not in text
    assert "712 345 678" not in text
    assert "[EMAIL]" in text
    assert "[URL]" in text
    assert "[PHONE_OR_CODE]" in text


def test_import_deduplicates_and_split_is_stable(tmp_path: Path) -> None:
    archive = tmp_path / "sms.zip"
    rows = "ham\tHello friend\nham\tHello friend\nspam\tCall 0712345678 now\nspam\tWin a prize today\n"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("SMSSpamCollection", rows)

    records = read_archive(archive)
    first = stratified_split(records, validation_fraction=0.5)
    second = stratified_split(records, validation_fraction=0.5)

    assert len(records) == 3
    assert first == second
    assert {item["id"] for item in first[0]}.isdisjoint(item["id"] for item in first[1])
    assert all(item["privacy_review_required"] is True for item in records)


def test_import_rejects_unexpected_archive(tmp_path: Path) -> None:
    archive = tmp_path / "wrong.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("unexpected.txt", "ham\tHello")

    with pytest.raises(ValueError, match="does not contain"):
        read_archive(archive)
