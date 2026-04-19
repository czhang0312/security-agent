from pathlib import Path

from security_agent.advisories import AdvisoryDataUnavailableError
from security_agent.config import Config
from security_agent.investigation import InvestigationResult
from security_agent.models import VulnerabilityFinding
from security_agent.scanner import calculate_priority, run_scan


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
    assert result.findings[0].investigator_used == "mock"
    assert result.findings[0].reachability_status == "reachable"
    assert result.findings[0].commands_run
    assert result.findings[1].gem_name == "rack"
    assert result.findings[1].priority == "low"
    assert result.findings[1].investigated is True


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
    assert result.findings[0].investigator_used == "mock_fallback"
    assert result.findings[0].priority == "high"
    assert any("Gemini fallback activated" in item for item in result.findings[0].assumptions)


def test_run_scan_falls_back_to_mock_when_openai_is_unavailable(tmp_path: Path) -> None:
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
        Config(advisory_path=advisories, investigator_provider="openai"),
    )

    assert len(result.findings) == 1
    assert result.findings[0].reachability_status == "reachable"
    assert result.findings[0].investigated is True
    assert result.findings[0].investigator_used == "mock_fallback"
    assert result.findings[0].priority == "high"
    assert any("OpenAI fallback activated" in item for item in result.findings[0].assumptions)


def test_run_scan_fails_clearly_when_advisory_cache_is_missing(tmp_path: Path) -> None:
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

    try:
        run_scan(str(tmp_path), Config(advisory_path=tmp_path / "missing.json"))
    except AdvisoryDataUnavailableError as exc:
        assert "advisories update" in str(exc)
    else:
        raise AssertionError("Expected AdvisoryDataUnavailableError")


def test_calculate_priority_promotes_high_severity_possible_reachability() -> None:
    finding = VulnerabilityFinding(
        gem_name="activestorage",
        installed_version="8.0.2",
        direct_dependency=False,
        advisory_id="GHSA-test",
        severity="high",
        summary="fixture",
        fixed_versions=["8.0.2.1"],
        investigated=True,
        reachability_status="possibly_reachable",
        confidence=0.75,
    )

    assert calculate_priority(finding) == "high"


def test_calculate_priority_keeps_critical_uninvestigated_as_medium() -> None:
    finding = VulnerabilityFinding(
        gem_name="nokogiri",
        installed_version="1.18.8",
        direct_dependency=False,
        advisory_id="GHSA-test",
        severity="critical",
        summary="fixture",
        fixed_versions=["1.18.9"],
    )

    assert calculate_priority(finding) == "medium"


def test_calculate_priority_normalizes_moderate_to_medium() -> None:
    finding = VulnerabilityFinding(
        gem_name="thor",
        installed_version="1.3.2",
        direct_dependency=True,
        advisory_id="GHSA-test",
        severity="moderate",
        summary="fixture",
        fixed_versions=["1.4.0"],
        investigated=True,
        reachability_status="not_observed",
        confidence=0.1,
    )

    assert calculate_priority(finding) == "low"


def test_run_scan_investigates_top_three_advisories_by_default(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "routes.rb").write_text("Rails.application.routes.draw do\nend\n")
    (tmp_path / "Gemfile").write_text("source 'https://rubygems.org'\n")
    (tmp_path / "Gemfile.lock").write_text(
        """GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.7)
    nokogiri (1.16.0)
    rack (2.2.7)
    rexml (3.3.9)

PLATFORMS
  ruby

DEPENDENCIES
  rails
  nokogiri
  rack
  rexml

BUNDLED WITH
   2.5.6
"""
    )
    advisories = tmp_path / "advisories.json"
    advisories.write_text(
        """[
  {"id": "SA-RAILS", "gem_name": "rails", "severity": "high", "summary": "fixture", "affected_versions": [">= 7.0.0", "< 7.0.8"], "fixed_versions": ["7.0.8"]},
  {"id": "SA-NOKOGIRI-1", "gem_name": "nokogiri", "severity": "critical", "summary": "fixture", "affected_versions": [">= 1.15.0", "< 1.16.3"], "fixed_versions": ["1.16.3"]},
  {"id": "SA-NOKOGIRI-2", "gem_name": "nokogiri", "severity": "high", "summary": "fixture", "affected_versions": [">= 1.15.0", "< 1.16.3"], "fixed_versions": ["1.16.4"]},
  {"id": "SA-RACK", "gem_name": "rack", "severity": "low", "summary": "fixture", "affected_versions": [">= 2.2.0", "< 2.2.8"], "fixed_versions": ["2.2.8"]},
  {"id": "SA-REXML", "gem_name": "rexml", "severity": "medium", "summary": "fixture", "affected_versions": [">= 3.3.0", "< 3.4.0"], "fixed_versions": ["3.4.0"]}
]"""
    )

    counter = {"value": 0}

    class StubInvestigator:
        def investigate(self, context):
            counter["value"] += 1
            return InvestigationResult(
                status="possibly_reachable",
                confidence=0.5 + (counter["value"] * 0.1),
                reasoning_summary=f"stub {context.finding.advisory_id}",
                assumptions=[],
                evidence=[],
                commands_run=[f"stub-{context.finding.advisory_id}"],
            )

    monkeypatch.setattr("security_agent.scanner.build_investigator", lambda config, progress_reporter=None: StubInvestigator())

    result = run_scan(str(tmp_path), Config(advisory_path=advisories))

    investigated_ids = [finding.advisory_id for finding in result.findings if finding.investigated]
    assert len(investigated_ids) == 3
    assert set(investigated_ids) == {"SA-NOKOGIRI-1", "SA-NOKOGIRI-2", "SA-RAILS"}
    assert any(finding.advisory_id == "SA-NOKOGIRI-1" and finding.reasoning_summary == "stub SA-NOKOGIRI-1" for finding in result.findings)
    assert any(finding.advisory_id == "SA-NOKOGIRI-2" and finding.reasoning_summary == "stub SA-NOKOGIRI-2" for finding in result.findings)
    assert any(finding.advisory_id == "SA-REXML" and finding.investigated is False for finding in result.findings)


def test_run_scan_respects_max_investigations_override(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "routes.rb").write_text("Rails.application.routes.draw do\nend\n")
    (tmp_path / "Gemfile").write_text("source 'https://rubygems.org'\n")
    (tmp_path / "Gemfile.lock").write_text(
        """GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.7)
    nokogiri (1.16.0)

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
  {"id": "SA-RAILS", "gem_name": "rails", "severity": "high", "summary": "fixture", "affected_versions": [">= 7.0.0", "< 7.0.8"], "fixed_versions": ["7.0.8"]},
  {"id": "SA-NOKOGIRI-1", "gem_name": "nokogiri", "severity": "critical", "summary": "fixture", "affected_versions": [">= 1.15.0", "< 1.16.3"], "fixed_versions": ["1.16.3"]}
]"""
    )

    class StubInvestigator:
        def investigate(self, context):
            return InvestigationResult(
                status="reachable",
                confidence=0.9,
                reasoning_summary=f"stub {context.finding.advisory_id}",
                assumptions=[],
                evidence=[],
                commands_run=[f"stub-{context.finding.advisory_id}"],
            )

    monkeypatch.setattr("security_agent.scanner.build_investigator", lambda config, progress_reporter=None: StubInvestigator())

    result = run_scan(str(tmp_path), Config(advisory_path=advisories, max_investigations=1))

    investigated_ids = [finding.advisory_id for finding in result.findings if finding.investigated]
    assert investigated_ids == ["SA-NOKOGIRI-1"]
