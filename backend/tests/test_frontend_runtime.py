"""Tests for dashboard behavior when the backend cannot be reached."""

from frontend.runtime_status import offline_runtime_payload


def test_offline_runtime_does_not_claim_specific_infrastructure() -> None:
    payload = offline_runtime_payload()

    assert payload["available"] is False
    assert payload["status"] == "offline"
    assert payload["gpu"] == "Unavailable"
    assert payload["cloud"] == "Unavailable"
    assert "AMD" not in " ".join(str(value) for value in payload.values())
