"""Tests for bundled demo sample loading."""

from backend.app.samples import load_samples


def test_samples_include_required_demo_cases():
    """The dashboard should have the core KRA, M-Pesa, and benign demos."""
    names = {sample["name"] for sample in load_samples()}

    assert "Fake KRA Refund Scam" in names
    assert "Fake M-Pesa Suspension" in names
    assert "Benign Department Message" in names
