from pathlib import Path

from security_agent.advisories import load_advisory_database, match_advisories


def test_match_advisories_returns_matching_entries(tmp_path: Path) -> None:
    fixture = tmp_path / "advisories.json"
    fixture.write_text(
        """[
  {
    "id": "SA-TEST-1",
    "gem_name": "rails",
    "severity": "high",
    "summary": "fixture",
    "affected_versions": [">= 7.0.0", "< 7.0.8"],
    "fixed_versions": ["7.0.8"]
  }
]"""
    )

    db = load_advisory_database(fixture)
    matches = match_advisories("rails", "7.0.7", db)

    assert len(matches) == 1
    assert matches[0].id == "SA-TEST-1"


def test_match_advisories_skips_non_matching_versions(tmp_path: Path) -> None:
    fixture = tmp_path / "advisories.json"
    fixture.write_text(
        """[
  {
    "id": "SA-TEST-1",
    "gem_name": "rails",
    "severity": "high",
    "summary": "fixture",
    "affected_versions": [">= 7.0.0", "< 7.0.8"],
    "fixed_versions": ["7.0.8"]
  }
]"""
    )

    db = load_advisory_database(fixture)
    matches = match_advisories("rails", "7.0.8", db)

    assert matches == []

