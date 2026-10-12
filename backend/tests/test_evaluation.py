"""Tests for evaluation dataset integrity and safety-weighted metrics."""

import json
from pathlib import Path

import pytest

from backend.app.versioning import fingerprint_manifest
from evaluation.evaluate import evaluate_records, load_dataset
from evaluation.evaluate_feedback import feedback_records_to_evaluation
from evaluation.generate_dataset import LANGUAGES, SCENARIOS, THREAT_TYPES, generate_examples, validate_examples

ROOT = Path(__file__).resolve().parents[2]


def test_checked_in_evaluation_dataset_has_required_coverage() -> None:
    records = load_dataset(ROOT / "evaluation" / "data" / "afrishield_eval_v1.jsonl")

    assert len(records) == 600
    assert records == generate_examples(600)
    assert {record["language"] for record in records} == set(LANGUAGES)
    assert {record["threat_type"] for record in records} == set(THREAT_TYPES)
    assert set().union(*map(set, SCENARIOS.values())).issubset({record["scenario"] for record in records})
    assert all(record["contains_personal_data"] is False for record in records)
    assert all(".invalid" in record["text"] or record["threat_type"] != "PHISHING" for record in records)


def test_dataset_generation_is_deterministic() -> None:
    assert generate_examples(300) == generate_examples(300)


def test_component_changes_require_a_refreshed_regression_baseline() -> None:
    baseline = json.loads((ROOT / "evaluation/baselines/component_fingerprint.json").read_text(encoding="utf-8"))

    assert baseline == fingerprint_manifest()


def test_only_reviewed_feedback_enters_improvement_evaluation() -> None:
    records = feedback_records_to_evaluation(
        [
            {
                "feedback_id": "one",
                "review_status": "adjudicated",
                "corrected_threat_type": "PHISHING",
                "original_content": "verify account",
                "original_input_type": "sms",
                "original_context": "Kenya",
                "error_category": "FALSE_NEGATIVE",
            },
            {
                "feedback_id": "two",
                "review_status": "pending",
                "corrected_threat_type": "SCAM",
                "original_content": "pending review",
            },
        ]
    )

    assert len(records) == 1
    assert records[0]["threat_type"] == "PHISHING"
    assert records[0]["scenario"] == "FALSE_NEGATIVE"


@pytest.mark.parametrize("size", [299, 1001])
def test_dataset_generator_enforces_requested_size_range(size: int) -> None:
    with pytest.raises(ValueError, match="between 300 and 1000"):
        generate_examples(size)


def test_dataset_validation_rejects_live_hostnames() -> None:
    records = generate_examples(300)
    records[0]["text"] = records[0]["text"].replace("mpesa-security.invalid", "unapproved-live.example.com")

    with pytest.raises(ValueError, match="non-reserved hostname"):
        validate_examples(records)


def test_false_negatives_receive_highest_error_cost() -> None:
    records = [
        _record("SCAM", "sw"),
        _record("BENIGN", "en"),
        _record("PHISHING", "fr"),
    ]
    predictions = iter(["BENIGN", "PHISHING", "SCAM"])

    metrics, _, _ = evaluate_records(records, lambda _record: next(predictions))

    assert metrics["binary_safety"]["false_negatives"] == 1
    assert metrics["binary_safety"]["false_positives"] == 1
    assert metrics["overall"]["weighted_error_cost"] == 8
    assert metrics["error_costs"]["false_negative"] > metrics["error_costs"]["false_positive"]


def _record(threat_type: str, language: str) -> dict:
    return {
        "dataset_version": "test",
        "source": "synthetic_template",
        "threat_type": threat_type,
        "language": language,
        "scenario": "test",
    }
