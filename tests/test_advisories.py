import io
import json
import tarfile
from pathlib import Path

from security_agent.advisories import (
    AdvisoryDataUnavailableError,
    load_advisory_database,
    match_advisories,
    normalize_osv_record,
    update_advisory_cache,
)


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


def test_match_advisories_supports_multiple_affected_ranges(tmp_path: Path) -> None:
    fixture = tmp_path / "advisories.json"
    fixture.write_text(
        """[
  {
    "id": "GHSA-test",
    "gem_name": "rails",
    "severity": "high",
    "summary": "fixture",
    "affected_versions": [[">= 7.0.0", "< 7.0.2"], [">= 7.1.0", "< 7.1.1"]],
    "fixed_versions": ["7.0.2", "7.1.1"]
  }
]"""
    )

    db = load_advisory_database(fixture)

    assert len(match_advisories("rails", "7.0.1", db)) == 1
    assert len(match_advisories("rails", "7.1.0", db)) == 1
    assert match_advisories("rails", "7.2.0", db) == []


def test_normalize_osv_record_filters_rubygems_and_maps_ranges() -> None:
    record = {
        "id": "GHSA-1234-5678-9012",
        "aliases": ["CVE-2026-0001"],
        "summary": "Example advisory",
        "details": "Detailed advisory text.",
        "database_specific": {"severity": "high"},
        "affected": [
            {
                "package": {"ecosystem": "RubyGems", "name": "rails"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "7.0.0"}, {"fixed": "7.0.8"}],
                    }
                ],
            },
            {
                "package": {"ecosystem": "npm", "name": "ignore-me"},
                "ranges": [],
            },
        ],
        "references": [{"url": "https://example.com/advisory"}],
    }

    advisories = normalize_osv_record(record)

    assert len(advisories) == 1
    assert advisories[0].id == "GHSA-1234-5678-9012"
    assert advisories[0].cve == "CVE-2026-0001"
    assert advisories[0].gem_name == "rails"
    assert advisories[0].affected_versions == [[">= 7.0.0", "< 7.0.8"]]
    assert advisories[0].fixed_versions == ["7.0.8"]
    assert advisories[0].severity == "high"
    assert "Detailed advisory text." in (advisories[0].notes or "")


def test_update_advisory_cache_writes_normalized_json_from_archive(tmp_path: Path) -> None:
    archive_path = tmp_path / "github-advisories.tar.gz"
    destination = tmp_path / "cache" / "advisories.json"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        payload = json.dumps(
            {
                "id": "GHSA-1234-5678-9012",
                "aliases": ["CVE-2026-0001"],
                "summary": "Example advisory",
                "details": "Detailed advisory text.",
                "database_specific": {"severity": "high"},
                "affected": [
                    {
                        "package": {"ecosystem": "RubyGems", "name": "rails"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "7.0.0"}, {"fixed": "7.0.8"}],
                            }
                        ],
                    }
                ],
            }
        ).encode("utf-8")
        tarinfo = tarfile.TarInfo(
            name="advisory-database-main/advisories/github-reviewed/2026/01/GHSA-1234-5678-9012/GHSA-1234-5678-9012.json"
        )
        tarinfo.size = len(payload)
        archive.addfile(tarinfo, io.BytesIO(payload))
    archive_path.write_bytes(buffer.getvalue())

    progress_messages: list[str] = []
    count = update_advisory_cache(
        destination=destination,
        source_url=archive_path.resolve().as_uri(),
        progress_reporter=progress_messages.append,
    )

    assert count == 1
    assert destination.exists()
    cached = json.loads(destination.read_text())
    assert cached[0]["id"] == "GHSA-1234-5678-9012"
    assert cached[0]["gem_name"] == "rails"
    assert any("Downloading advisory archive" in item for item in progress_messages)


def test_load_advisory_database_raises_clear_error_when_missing(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"

    try:
        load_advisory_database(missing)
    except AdvisoryDataUnavailableError as exc:
        assert "advisories update" in str(exc)
    else:
        raise AssertionError("Expected AdvisoryDataUnavailableError")
