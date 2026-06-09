import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SAMPLES_DIR = ROOT / "samples"


def load_samples() -> list[dict]:
    samples = []
    for path in sorted(SAMPLES_DIR.glob("*.json")):
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
            if isinstance(data, list):
                samples.extend(data)
    return samples
