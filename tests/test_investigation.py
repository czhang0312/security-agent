from pathlib import Path

from security_agent.investigation import InvestigationContext, MockInvestigator
from security_agent.models import VulnerabilityFinding


def make_finding(gem_name: str) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        gem_name=gem_name,
        installed_version="1.0.0",
        direct_dependency=True,
        advisory_id="SA-TEST",
        severity="high",
        summary="fixture",
        fixed_versions=["1.0.1"],
    )


def test_mock_investigator_marks_reachable_for_app_reference(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "services").mkdir(parents=True, exist_ok=True)
    (tmp_path / "app" / "services" / "parser.rb").write_text(
        "class Parser\n  def call\n    Nokogiri::XML.parse(payload)\n  end\nend\n"
    )

    investigator = MockInvestigator()
    result = investigator.investigate(
        InvestigationContext(
            repo_root=str(tmp_path),
            finding=make_finding("Nokogiri"),
        )
    )

    assert result.status == "reachable"
    assert result.confidence > 0.8
    assert result.evidence
    assert result.commands_run[0].startswith("rg ")


def test_mock_investigator_marks_possibly_reachable_for_metadata_only(tmp_path: Path) -> None:
    (tmp_path / "Gemfile").write_text("gem 'rack'\n")
    (tmp_path / "Gemfile.lock").write_text("rack (2.2.7)\n")

    investigator = MockInvestigator()
    result = investigator.investigate(
        InvestigationContext(
            repo_root=str(tmp_path),
            finding=make_finding("rack"),
        )
    )

    assert result.status == "possibly_reachable"
    assert result.evidence
    assert "dependency metadata" in result.reasoning_summary


def test_mock_investigator_marks_not_observed_when_no_match_exists(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "models").mkdir(parents=True, exist_ok=True)
    (tmp_path / "app" / "models" / "user.rb").write_text("class User < ApplicationRecord\nend\n")

    investigator = MockInvestigator()
    result = investigator.investigate(
        InvestigationContext(
            repo_root=str(tmp_path),
            finding=make_finding("rack"),
        )
    )

    assert result.status == "not_observed"
    assert result.evidence == []

