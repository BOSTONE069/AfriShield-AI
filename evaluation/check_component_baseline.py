#!/usr/bin/env python3
"""Fail when prediction-affecting components lack a refreshed baseline."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.versioning import fingerprint_manifest  # noqa: E402

BASELINE = Path("evaluation/baselines/component_fingerprint.json")


def main() -> int:
    expected = json.loads(BASELINE.read_text(encoding="utf-8"))
    current = fingerprint_manifest()
    if expected != current:
        print(
            "Rules, prompt, model configuration, or feed changed. Run the regression evaluation "
            "with --update-component-baseline after reviewing its metrics."
        )
        return 1
    print(f"Component fingerprint matches evaluated baseline: {current['component_fingerprint']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
