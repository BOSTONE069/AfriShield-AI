"""Load bundled demo samples for the dashboard and /api/samples."""

import json
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SAMPLES_DIR = ROOT / "samples"


@lru_cache(maxsize=1)
def load_samples() -> list[dict]:
    """Read all JSON sample files once and return a cached combined list."""
    samples: list[dict] = []
    for path in sorted(SAMPLES_DIR.glob("*.json")):
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
            if isinstance(data, list):
                samples.extend(data)
    return samples
