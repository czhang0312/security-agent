from __future__ import annotations

from security_agent.advisories import load_advisory_database, match_advisories
from security_agent.bundler import parse_gemfile_lock
from security_agent.config import Config
from security_agent.investigation import (
    InvestigationContext,
    InvestigationError,
    InvestigationResult,
    MockInvestigator,
    build_investigator,
)
from security_agent.models import ScanResult, VulnerabilityFinding
from security_agent.repo import UnsupportedRepoError, detect_repo


def run_scan(repo_path: str, config: Config) -> ScanResult:
    repo = detect_repo(repo_path)
    if repo.kind != "rails":
        raise UnsupportedRepoError(
            "Expected a Ruby on Rails repository with Gemfile, Gemfile.lock, app/, and config/routes.rb."
        )

    graph = parse_gemfile_lock(f"{repo.root}/Gemfile.lock")
    advisory_db = load_advisory_database(config.advisory_path)

    findings: list[VulnerabilityFinding] = []
    for dependency in graph.dependencies:
        advisories = match_advisories(
            gem_name=dependency.name,
            version=dependency.version,
            advisory_db=advisory_db,
        )
        for advisory in advisories:
            findings.append(
                VulnerabilityFinding(
                    gem_name=dependency.name,
                    installed_version=dependency.version,
                    direct_dependency=dependency.direct,
                    advisory_id=advisory.id,
                    cve=advisory.cve,
                    severity=advisory.severity,
                    summary=advisory.summary,
                    fixed_versions=advisory.fixed_versions,
                    require_names=advisory.require_names,
                    namespaces=advisory.namespaces,
                    symbols=advisory.symbols,
                    advisory_notes=advisory.notes,
                )
            )

    rank_milestone_one_findings(findings)
    findings.sort(key=_finding_sort_key)
    investigate_top_finding(repo.root, findings, config)

    return ScanResult(
        repo_path=repo.root,
        repo_kind=repo.kind,
        dependency_count=len(graph.dependencies),
        findings=findings,
    )


def rank_milestone_one_findings(findings: list[VulnerabilityFinding]) -> None:
    severity_order = {"critical": "high", "high": "high", "medium": "medium"}
    for finding in findings:
        default_priority = severity_order.get(finding.severity.lower(), "low")
        if default_priority == "high" and not finding.direct_dependency:
            finding.priority = "medium"
        else:
            finding.priority = default_priority


def investigate_top_finding(repo_root: str, findings: list[VulnerabilityFinding], config: Config) -> None:
    if not findings:
        return

    selected = findings[0]
    context = InvestigationContext(repo_root=repo_root, finding=selected)
    provider_name = config.investigator_provider.lower()
    try:
        investigator = build_investigator(config)
        result = investigator.investigate(context)
        investigator_used = provider_name
    except InvestigationError as exc:
        fallback_result = MockInvestigator().investigate(context)
        fallback_result.assumptions.append(
            f"{provider_display_name(provider_name)} fallback activated: {exc}"
        )
        fallback_result.reasoning_summary = (
            f"{fallback_result.reasoning_summary} Used mock investigator fallback."
        )
        result = fallback_result
        investigator_used = "mock_fallback"
    apply_investigation_result(selected, result, investigator_used)


def apply_investigation_result(
    finding: VulnerabilityFinding,
    result: InvestigationResult,
    investigator_used: str,
) -> None:
    finding.investigated = True
    finding.investigator_used = investigator_used
    finding.reachability_status = result.status
    finding.confidence = result.confidence
    finding.reasoning_summary = result.reasoning_summary
    finding.assumptions = result.assumptions
    finding.evidence = result.evidence
    finding.commands_run = result.commands_run


def _finding_sort_key(finding: VulnerabilityFinding) -> tuple[int, int, str, str]:
    priority_order = {"high": 0, "medium": 1, "low": 2}
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return (
        priority_order.get(finding.priority, 99),
        severity_order.get(finding.severity.lower(), 99),
        finding.gem_name,
        finding.advisory_id,
    )


def provider_display_name(provider_name: str) -> str:
    return {
        "openai": "OpenAI",
        "gemini": "Gemini",
        "mock": "Mock",
    }.get(provider_name, provider_name)
