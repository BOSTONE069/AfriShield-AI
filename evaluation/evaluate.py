#!/usr/bin/env python3
"""Evaluate AfriShield predictions against a versioned JSONL benchmark."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import Counter, defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("USE_LLM", "false")
os.environ.setdefault("USE_LLM_REPORTS", "false")

from backend.app.analyzer import ALLOWED_THREAT_TYPES, analyze_threat  # noqa: E402
from backend.app.versioning import component_versions, write_fingerprint_manifest  # noqa: E402

FALSE_NEGATIVE_COST = 5
FALSE_POSITIVE_COST = 1
WRONG_MALICIOUS_TYPE_COST = 2


def load_dataset(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    if not records:
        raise ValueError("Evaluation dataset is empty.")
    return records


def evaluate_records(
    records: list[dict[str, Any]],
    predictor: Callable[[dict[str, Any]], str],
) -> tuple[dict[str, Any], list[str], dict[str, dict[str, int]]]:
    """Calculate multiclass, binary safety, and slice-level metrics."""
    predictions: list[tuple[dict[str, Any], str]] = []
    labels = set(ALLOWED_THREAT_TYPES)
    for record in records:
        predicted = predictor(record)
        if predicted not in ALLOWED_THREAT_TYPES:
            raise ValueError(f"Unsupported prediction: {predicted}")
        labels.update((record["threat_type"], predicted))
        predictions.append((record, predicted))

    ordered_labels = sorted(labels)
    matrix = {actual: {predicted: 0 for predicted in ordered_labels} for actual in ordered_labels}
    for record, predicted in predictions:
        matrix[record["threat_type"]][predicted] += 1

    per_class: dict[str, dict[str, float | int]] = {}
    for label in ordered_labels:
        true_positive = matrix[label][label]
        false_positive = sum(matrix[actual][label] for actual in ordered_labels if actual != label)
        false_negative = sum(matrix[label][predicted] for predicted in ordered_labels if predicted != label)
        support = sum(matrix[label].values())
        per_class[label] = {
            "support": support,
            "true_positive": true_positive,
            "false_positive": false_positive,
            "false_negative": false_negative,
            "precision": _ratio(true_positive, true_positive + false_positive),
            "recall": _ratio(true_positive, true_positive + false_negative),
            "false_negative_rate": _ratio(false_negative, support),
        }

    correct = sum(1 for record, predicted in predictions if record["threat_type"] == predicted)
    malicious_total = false_negatives = false_positives = detected_malicious = 0
    weighted_error_cost = 0
    for record, predicted in predictions:
        actual_malicious = record["threat_type"] != "BENIGN"
        predicted_malicious = predicted != "BENIGN"
        malicious_total += int(actual_malicious)
        detected_malicious += int(actual_malicious and predicted_malicious)
        if actual_malicious and not predicted_malicious:
            false_negatives += 1
            weighted_error_cost += FALSE_NEGATIVE_COST
        elif not actual_malicious and predicted_malicious:
            false_positives += 1
            weighted_error_cost += FALSE_POSITIVE_COST
        elif actual_malicious and predicted != record["threat_type"]:
            weighted_error_cost += WRONG_MALICIOUS_TYPE_COST

    metrics = {
        "dataset": {
            "version": records[0].get("dataset_version", "unknown"),
            "records": len(records),
            "source_counts": dict(Counter(record["source"] for record in records)),
        },
        "overall": {
            "accuracy": _ratio(correct, len(records)),
            "macro_precision": _mean([float(item["precision"]) for item in per_class.values() if item["support"]]),
            "macro_recall": _mean([float(item["recall"]) for item in per_class.values() if item["support"]]),
            "weighted_error_cost": weighted_error_cost,
            "weighted_error_cost_per_record": round(weighted_error_cost / len(records), 4),
        },
        "binary_safety": {
            "malicious_support": malicious_total,
            "detected_malicious": detected_malicious,
            "false_negatives": false_negatives,
            "false_positives": false_positives,
            "recall": _ratio(detected_malicious, malicious_total),
            "false_negative_rate": _ratio(false_negatives, malicious_total),
        },
        "error_costs": {
            "false_negative": FALSE_NEGATIVE_COST,
            "wrong_malicious_type": WRONG_MALICIOUS_TYPE_COST,
            "false_positive": FALSE_POSITIVE_COST,
        },
        "per_threat_type": per_class,
        "per_language": _slice_metrics(predictions, "language"),
        "per_scenario": _slice_metrics(predictions, "scenario"),
        "component_versions": component_versions(),
    }
    return metrics, ordered_labels, matrix


def _slice_metrics(predictions: list[tuple[dict[str, Any], str]], field: str) -> dict[str, dict[str, float | int]]:
    groups: dict[str, list[tuple[dict[str, Any], str]]] = defaultdict(list)
    for record, predicted in predictions:
        groups[str(record[field])].append((record, predicted))

    result = {}
    for name, group in sorted(groups.items()):
        correct = sum(record["threat_type"] == predicted for record, predicted in group)
        malicious = [(record, predicted) for record, predicted in group if record["threat_type"] != "BENIGN"]
        false_negatives = sum(predicted == "BENIGN" for _, predicted in malicious)
        result[name] = {
            "support": len(group),
            "accuracy": _ratio(correct, len(group)),
            "malicious_support": len(malicious),
            "false_negatives": false_negatives,
            "false_negative_rate": _ratio(false_negatives, len(malicious)),
        }
    return result


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _mean(values: list[float]) -> float:
    return round(sum(values) / len(values), 4) if values else 0.0


def default_predictor(record: dict[str, Any]) -> str:
    result = analyze_threat(record["input_type"], record["text"], record["locale"])
    return str(result["threat_type"])


def write_results(
    metrics: dict[str, Any],
    labels: list[str],
    matrix: dict[str, dict[str, int]],
    output_dir: Path,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "metrics.json").open("w", encoding="utf-8") as handle:
        json.dump(metrics, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    with (output_dir / "confusion_matrix.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["actual\\predicted", *labels])
        for actual in labels:
            writer.writerow([actual, *(matrix[actual][predicted] for predicted in labels)])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=Path("evaluation/data/afrishield_eval_v1.jsonl"))
    parser.add_argument("--output-dir", type=Path, default=Path("evaluation/results/latest"))
    parser.add_argument("--max-false-negative-rate", type=float)
    parser.add_argument("--min-accuracy", type=float)
    parser.add_argument(
        "--update-component-baseline",
        action="store_true",
        help="Update the component fingerprint only after all regression gates pass.",
    )
    args = parser.parse_args()

    records = load_dataset(args.dataset)
    metrics, labels, matrix = evaluate_records(records, default_predictor)
    write_results(metrics, labels, matrix, args.output_dir)
    print(json.dumps({"overall": metrics["overall"], "binary_safety": metrics["binary_safety"]}, indent=2))

    false_negative_rate = metrics["binary_safety"]["false_negative_rate"]
    accuracy = metrics["overall"]["accuracy"]
    if args.max_false_negative_rate is not None and false_negative_rate > args.max_false_negative_rate:
        print(
            f"False-negative rate {false_negative_rate:.4f} exceeds limit {args.max_false_negative_rate:.4f}",
            file=sys.stderr,
        )
        return 1
    if args.min_accuracy is not None and accuracy < args.min_accuracy:
        print(f"Accuracy {accuracy:.4f} is below minimum {args.min_accuracy:.4f}", file=sys.stderr)
        return 1
    if args.update_component_baseline:
        destination = Path("evaluation/baselines/component_fingerprint.json")
        write_fingerprint_manifest(destination)
        print(f"Updated component baseline: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
