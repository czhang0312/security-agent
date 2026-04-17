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
        lines.extend(
            [
                f"[{finding.priority.upper()}] {finding.gem_name} {finding.installed_version}",
                f"  Advisory: {identifier}",
                f"  Severity: {finding.severity} ({directness})",
                f"  Summary: {finding.summary}",
                f"  Fixed version: {fixed_versions}",
                "",
            ]
        )

    return "\n".join(lines).rstrip()


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)

