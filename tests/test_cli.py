import io
import json
from pathlib import Path
import tarfile

from security_agent.cli import main


def test_cli_json_keeps_stdout_machine_readable(tmp_path: Path, monkeypatch, capsys) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "routes.rb").write_text("Rails.application.routes.draw do\nend\n")
    (tmp_path / "Gemfile").write_text("source 'https://rubygems.org'\n")
    (tmp_path / "Gemfile.lock").write_text(
        """GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.7)

PLATFORMS
  ruby

DEPENDENCIES
  rails

BUNDLED WITH
   2.5.6
"""
    )
    advisories = tmp_path / "advisories.json"
    advisories.write_text(
        """[
  {
    "id": "SA-TEST-RAILS",
    "gem_name": "rails",
    "severity": "high",
    "summary": "fixture",
    "affected_versions": [">= 7.0.0", "< 7.0.8"],
    "fixed_versions": ["7.0.8"],
    "namespaces": ["Rails"]
  }
]"""
    )

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    exit_code = main(
        [
            "scan",
            str(tmp_path),
            "--config",
            str(advisories),
            "--investigator",
            "openai",
            "--json",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out.lstrip().startswith("{")
    assert "OpenAI failed, falling back to mock" in captured.err


def test_cli_advisories_update_writes_cache_from_archive(tmp_path: Path, capsys) -> None:
    archive_path = tmp_path / "github-advisories.tar.gz"
    output_path = tmp_path / "cache" / "advisories.json"
    buffer = io.BytesIO()
    
    # creates a tar.gz archive in memory with one advisory and saves to archive_path
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        payload = json.dumps(
            {
                "id": "GHSA-1234-5678-9012",
                "summary": "Example advisory",
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

    # call update to see if cache is written correctly from the archive
    exit_code = main(
        [
            "advisories",
            "update",
            "--source-url",
            archive_path.resolve().as_uri(),
            "--output",
            str(output_path),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert output_path.exists()
    assert "Updated advisory cache with 1 advisories" in captured.out
