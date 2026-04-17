from pathlib import Path

from security_agent.config import Config
from security_agent.scanner import run_scan


def test_run_scan_returns_findings_for_sample_rails_repo(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "routes.rb").write_text("Rails.application.routes.draw do\nend\n")
    (tmp_path / "Gemfile").write_text("source 'https://rubygems.org'\n")
    (tmp_path / "Gemfile.lock").write_text(
        """GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.16.0)
    rack (2.2.7)
    rails (7.0.7)

PLATFORMS
  ruby

DEPENDENCIES
  rails
  nokogiri

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
    "require_names": ["rails"],
    "namespaces": ["Rails"]
  },
  {
    "id": "SA-TEST-RACK",
    "gem_name": "rack",
    "severity": "low",
    "summary": "fixture",
    "affected_versions": [">= 2.2.0", "< 2.2.8"],
    "fixed_versions": ["2.2.8"]
  }
]"""
    )

    result = run_scan(str(tmp_path), Config(advisory_path=advisories))

    assert result.repo_kind == "rails"
    assert result.dependency_count == 3
    assert len(result.findings) == 2
    assert result.findings[0].gem_name == "rails"
    assert result.findings[0].priority == "high"
    assert result.findings[0].investigated is True
    assert result.findings[0].reachability_status == "reachable"
    assert result.findings[0].commands_run
    assert result.findings[1].gem_name == "rack"
    assert result.findings[1].priority == "low"
    assert result.findings[1].investigated is False


def test_run_scan_falls_back_to_mock_when_gemini_is_unavailable(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "services").mkdir(parents=True, exist_ok=True)
    (tmp_path / "app" / "services" / "parser.rb").write_text(
        "class Parser\n  def call\n    Nokogiri::XML.parse(payload)\n  end\nend\n"
    )
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "routes.rb").write_text("Rails.application.routes.draw do\nend\n")
    (tmp_path / "Gemfile").write_text("source 'https://rubygems.org'\n")
    (tmp_path / "Gemfile.lock").write_text(
        """GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.16.0)

PLATFORMS
  ruby

DEPENDENCIES
  nokogiri

BUNDLED WITH
   2.5.6
"""
    )

    advisories = tmp_path / "advisories.json"
    advisories.write_text(
        """[
  {
    "id": "SA-TEST-NOKOGIRI",
    "gem_name": "nokogiri",
    "severity": "medium",
    "summary": "fixture",
    "affected_versions": [">= 1.15.0", "< 1.16.3"],
    "fixed_versions": ["1.16.3"],
    "namespaces": ["Nokogiri"],
    "symbols": ["Nokogiri::XML.parse"]
  }
]"""
    )

    result = run_scan(
        str(tmp_path),
        Config(advisory_path=advisories, investigator_provider="gemini"),
    )

    assert len(result.findings) == 1
    assert result.findings[0].reachability_status == "reachable"
    assert result.findings[0].investigated is True
    assert any("Gemini fallback activated" in item for item in result.findings[0].assumptions)
