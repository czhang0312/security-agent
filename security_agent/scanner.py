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
from typing import Callable

ProgressReporter = Callable[[str], None]


def run_scan(
    repo_path: str,
    config: Config,
    progress_reporter: ProgressReporter | None = None,
) -> ScanResult:
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

    rank_findings_for_selection(findings)
    findings.sort(key=_finding_sort_key)
    investigate_findings(repo.root, findings, config, progress_reporter=progress_reporter)
    rank_findings(findings)
    findings.sort(key=_finding_sort_key)

    return ScanResult(
        repo_path=repo.root,
        repo_kind=repo.kind,
        dependency_count=len(graph.dependencies),
        findings=findings,
    )


def rank_findings_for_selection(findings: list[VulnerabilityFinding]) -> None:
    for finding in findings:
        severity = normalize_severity(finding.severity)
        default_priority = {"critical": "high", "high": "high", "medium": "medium"}.get(severity, "low")
        if default_priority == "high" and not finding.direct_dependency:
            finding.priority = "medium"
        else:
            finding.priority = default_priority


def rank_findings(findings: list[VulnerabilityFinding]) -> None:
    for finding in findings:
        finding.priority = calculate_priority(finding)


def investigate_findings(
    repo_root: str,
    findings: list[VulnerabilityFinding],
    config: Config,
    progress_reporter: ProgressReporter | None = None,
) -> None:
    if not findings:
        return

    budget = max(0, config.max_investigations)
    selected_findings = findings[:budget]
    total = len(selected_findings)
    provider_name = config.investigator_provider.lower()

    for index, selected in enumerate(selected_findings, start=1):
        if progress_reporter is not None:
            progress_reporter(
                f"Investigation {index}/{total}: {selected.advisory_id} ({selected.gem_name})"
            )
        context = InvestigationContext(repo_root=repo_root, finding=selected)
        try:
            investigator = build_investigator(config, progress_reporter=progress_reporter)
            result = investigator.investigate(context)
            investigator_used = provider_name
        except InvestigationError as exc:
            if progress_reporter is not None and provider_name == "openai":
                progress_reporter("OpenAI failed, falling back to mock")
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


def _finding_sort_key(finding: VulnerabilityFinding) -> tuple[int, int, int, int, int, str, str]:
    priority_order = {"high": 0, "medium": 1, "low": 2}
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    return (
        priority_order.get(finding.priority, 99),
        severity_order.get(normalize_severity(finding.severity), 99),
        0 if finding.investigated else 1,
        0 if finding.reachability_status == "reachable" else 1 if finding.reachability_status == "possibly_reachable" else 2,
        -int((finding.confidence or 0) * 100),
        finding.gem_name,
        finding.advisory_id,
    )


def provider_display_name(provider_name: str) -> str:
    return {
        "openai": "OpenAI",
        "gemini": "Gemini",
        "mock": "Mock",
    }.get(provider_name, provider_name)


def normalize_severity(severity: str) -> str:
    normalized = severity.strip().lower()
    return {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
    }.get(normalized, "unknown")


def calculate_priority(finding: VulnerabilityFinding) -> str:
    severity = normalize_severity(finding.severity)

    if finding.investigated:
        status = finding.reachability_status
        confidence = finding.confidence or 0.0

        if status == "reachable":
            if severity in {"critical", "high"}:
                return "high"
            if severity == "medium":
                return "medium" if confidence < 0.8 else "high"
            return "medium" if confidence >= 0.8 else "low"

        if status == "possibly_reachable":
            if severity in {"critical", "high"}:
                return "high" if confidence >= 0.6 else "medium"
            if severity == "medium":
                return "medium"
            return "low"

        if status == "not_observed":
            if severity == "critical" and finding.direct_dependency:
                return "medium"
            return "low"

    if severity in {"critical", "high"}:
        return "medium"
    if severity == "medium":
        return "medium" if finding.direct_dependency else "low"
    return "low"
