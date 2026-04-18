from pathlib import Path

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

