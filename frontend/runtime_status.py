"""Runtime status helpers that are safe to use when the API is unavailable."""

from typing import Any


def offline_runtime_payload() -> dict[str, Any]:
    """Return an honest, hardware-neutral status for a disconnected backend."""
    return {
        "available": False,
        "status": "offline",
        "gpu": "Unavailable",
        "cloud": "Unavailable",
        "backend": "Backend unreachable",
        "framework": "Unavailable",
        "model": "Unavailable",
        "latency_seconds": 0,
        "tokens_per_second": 0,
        "llm_enabled": False,
        "llm_provider": "unavailable",
    }
