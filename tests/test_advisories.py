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
    "fixed_versions": ["7.0.8"],
    "require_names": ["rails"],
    "namespaces": ["Rails"],
    "symbols": ["Rails.application"]
  }
]"""
    )

    db = load_advisory_database(fixture)
    matches = match_advisories("rails", "7.0.7", db)

    assert len(matches) == 1
    assert matches[0].id == "SA-TEST-1"
    assert matches[0].require_names == ["rails"]
    assert matches[0].namespaces == ["Rails"]
    assert matches[0].symbols == ["Rails.application"]


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


def test_load_advisories_allows_missing_hint_fields(tmp_path: Path) -> None:
    fixture = tmp_path / "advisories.json"
    fixture.write_text(
        """[
  {
    "id": "SA-TEST-2",
    "gem_name": "rack",
    "severity": "low",
    "summary": "fixture",
    "affected_versions": [">= 2.2.0", "< 2.2.8"],
    "fixed_versions": ["2.2.8"]
  }
]"""
    )

    db = load_advisory_database(fixture)
    advisory = db.for_gem("rack")[0]

    assert advisory.require_names == []
    assert advisory.namespaces == []
    assert advisory.symbols == []
