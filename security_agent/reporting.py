from __future__ import annotations

import json

from security_agent.models import ScanResult


def render_terminal(result: ScanResult) -> str:
    lines = [
        f"Repo: {result.repo_path}",
        f"Repo type: {result.repo_kind}",
        f"Dependencies scanned: {result.dependency_count}",
        f"Vulnerabilities found: {len(result.findings)}",
        "",
    ]

    if not result.findings:
        lines.append("No vulnerable gems matched the local advisory fixture.")
        return "\n".join(lines)

    for finding in result.findings:
        fixed_versions = ", ".join(finding.fixed_versions) if finding.fixed_versions else "unknown"
        directness = "direct" if finding.direct_dependency else "transitive"
        identifier = finding.cve or finding.advisory_id
        if finding.investigated:
            confidence = f"{finding.confidence:.2f}" if finding.confidence is not None else "n/a"
            reachability = finding.reachability_status
        else:
            confidence = "n/a"
            reachability = "not_investigated"
        lines.extend(
            [
                f"[{finding.priority.upper()}] {finding.gem_name} {finding.installed_version}",
                f"  Advisory: {identifier}",
                f"  Severity: {finding.severity} ({directness})",
                f"  Investigator: {finding.investigator_used or 'not_run'}",
                f"  Reachability: {reachability}",
                f"  Confidence: {confidence}",
                f"  Summary: {finding.summary}",
                f"  Fixed version: {fixed_versions}",
            ]
        )
        if finding.reasoning_summary:
            lines.append(f"  Investigation: {finding.reasoning_summary}")
        if finding.evidence:
            for item in finding.evidence[:2]:
                location = ""
                if item.path and item.line is not None:
                    location = f" ({item.path}:{item.line})"
                elif item.path:
                    location = f" ({item.path})"
                lines.append(f"  Evidence: {item.summary}{location}")
        lines.append("")

    return "\n".join(lines).rstrip()


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)
