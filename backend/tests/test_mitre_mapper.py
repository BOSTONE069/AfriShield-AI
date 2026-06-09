"""Tests for ATT&CK mapping richness."""

from backend.app.mitre_mapper import map_to_mitre


def test_phishing_mapping_includes_technique_id():
    """Mappings should include formal ATT&CK IDs, not only broad names."""
    mapping = map_to_mitre("PHISHING")

    assert mapping[0]["technique"] == "Phishing"
    assert mapping[0]["technique_id"] == "T1566"


def test_benign_has_no_mapping():
    """Benign content should not create unnecessary ATT&CK mappings."""
    assert map_to_mitre("BENIGN") == []
