"""Version metadata and fingerprints for reproducible threat decisions."""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

from backend.app.config import get_settings

ROOT = Path(__file__).resolve().parents[2]
RULESET_VERSION = "rules-1.2.0"
PROMPT_VERSION = "analysis-prompt-1.1.0"
FEED_VERSION = "local-feed-1.1.0"
DECISION_POLICY_VERSION = "deterministic-minimum-1.0.0"

FINGERPRINT_PATHS = (
    "backend/app/analyzer.py",
    "backend/app/agents.py",
    "backend/app/threat_classifier.py",
    "backend/app/risk_scoring.py",
    "backend/app/ioc_extractor.py",
    "backend/app/enrichment.py",
    "backend/app/llm_client.py",
    "backend/app/config.py",
    "samples/threat_feed.json",
    "backend/requirements-llm.txt",
)


@lru_cache(maxsize=1)
def component_fingerprint() -> str:
    """Hash all files whose changes can alter predictions."""
    digest = hashlib.sha256()
    for relative_path in FINGERPRINT_PATHS:
        path = ROOT / relative_path
        digest.update(relative_path.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes() if path.exists() else b"<missing>")
        digest.update(b"\0")
    return digest.hexdigest()


def component_versions() -> dict:
    """Return versions stored with every result and analyst review."""
    settings = get_settings()
    return {
        "ruleset": RULESET_VERSION,
        "prompt": PROMPT_VERSION,
        "threat_feed": FEED_VERSION,
        "decision_policy": DECISION_POLICY_VERSION,
        "model": settings.llm_model if settings.use_llm else "deterministic-only",
        "model_provider": settings.llm_provider if settings.use_llm else "none",
        "component_fingerprint": component_fingerprint(),
    }


def fingerprint_manifest() -> dict:
    """Return the manifest used to guard the checked-in regression baseline."""
    return {
        "component_fingerprint": component_fingerprint(),
        "tracked_files": list(FINGERPRINT_PATHS),
        "versions": {
            "ruleset": RULESET_VERSION,
            "prompt": PROMPT_VERSION,
            "threat_feed": FEED_VERSION,
            "decision_policy": DECISION_POLICY_VERSION,
        },
    }


def write_fingerprint_manifest(destination: Path) -> dict:
    """Write a stable manifest after a successful regression evaluation."""
    manifest = fingerprint_manifest()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest
