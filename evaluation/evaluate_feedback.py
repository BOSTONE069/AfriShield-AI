#!/usr/bin/env python3
"""Evaluate current components against encrypted analyst-reviewed cases."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("USE_LLM", "false")
os.environ.setdefault("USE_LLM_REPORTS", "false")

from backend.app.feedback import load_feedback  # noqa: E402
from evaluation.evaluate import default_predictor, evaluate_records, write_results  # noqa: E402


def feedback_records_to_evaluation(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert reviewed feedback without changing the held-out benchmark."""
    evaluation_records = []
    for record in records:
        if record.get("review_status") not in {"reviewed", "adjudicated"}:
            continue
        actual = record.get("corrected_threat_type") or record.get("original_threat_type")
        content = record.get("original_content")
        if not actual or not content:
            continue
        evaluation_records.append(
            {
                "id": f"AFS-FEEDBACK-{record.get('feedback_id', len(evaluation_records) + 1)}",
                "dataset_version": "analyst-feedback-v1",
                "text": content,
                "input_type": record.get("original_input_type", "text"),
                "language": "unknown",
                "locale": record.get("original_context", "unknown"),
                "threat_type": actual,
                "scenario": record.get("error_category") or "analyst_review",
                "source": "encrypted_analyst_feedback",
            }
        )
    return evaluation_records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=Path("evaluation/results/feedback"))
    args = parser.parse_args()

    records = feedback_records_to_evaluation(load_feedback())
    if not records:
        print("No reviewed feedback records with usable labels are available.", file=sys.stderr)
        return 2
    metrics, labels, matrix = evaluate_records(records, default_predictor)
    write_results(metrics, labels, matrix, args.output_dir)
    print(json.dumps({"records": len(records), "overall": metrics["overall"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
