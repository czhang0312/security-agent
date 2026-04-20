from __future__ import annotations

import json

from security_agent.models import ScanResult
from security_agent.terminal_ui import priority_color, reachability_color, style


def render_terminal(result: ScanResult, color_enabled: bool = False) -> str:
    investigated_count = sum(1 for item in result.findings if item.investigated)
    lines = [
        style("security-agent", "bold", enabled=color_enabled),
        f"{style('Repo', 'dim', enabled=color_enabled)}: {result.repo_path}",
        f"{style('Type', 'dim', enabled=color_enabled)}: {result.repo_kind}",
        f"{style('Dependencies', 'dim', enabled=color_enabled)}: {result.dependency_count}",
        f"{style('Findings', 'dim', enabled=color_enabled)}: {len(result.findings)}",
        f"{style('Investigated', 'dim', enabled=color_enabled)}: {investigated_count}",
        "",
    ]

    if not result.findings:
        lines.append("No vulnerable gems matched the local advisory database.")
        return "\n".join(lines)

    high_count = sum(1 for item in result.findings if item.priority == "high")
    lines.append(
        f"{style('Summary', 'cyan', 'bold', enabled=color_enabled)}: "
        f"{investigated_count} investigated, {high_count} high-priority findings"
    )
    lines.append("")

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
        priority_badge = style(finding.priority.upper(), *priority_color(finding.priority), enabled=color_enabled)
        reachability_text = style(reachability, *reachability_color(reachability), enabled=color_enabled)
        title = f"[{priority_badge}] {style(finding.gem_name, 'bold', enabled=color_enabled)} {finding.installed_version}  {style(identifier, 'dim', enabled=color_enabled)}"
        lines.extend(
            [
                title,
                f"  {style('Severity', 'dim', enabled=color_enabled)}: {finding.severity} ({directness})  "
                f"{style('Reachability', 'dim', enabled=color_enabled)}: {reachability_text}  "
                f"{style('Confidence', 'dim', enabled=color_enabled)}: {confidence}",
                f"  {style('Fix', 'dim', enabled=color_enabled)}: {fixed_versions}  "
                f"{style('Investigator', 'dim', enabled=color_enabled)}: {finding.investigator_used or 'not_run'}",
                f"  {style('Summary', 'dim', enabled=color_enabled)}: {finding.summary}",
            ]
        )
        if finding.reasoning_summary:
            lines.append(f"  {style('Investigation', 'cyan', enabled=color_enabled)}: {finding.reasoning_summary}")
        if finding.evidence:
            for item in finding.evidence[:2]:
                location = ""
                if item.path and item.line is not None:
                    location = f" ({item.path}:{item.line})"
                elif item.path:
                    location = f" ({item.path})"
                lines.append(f"  {style('Evidence', 'magenta', enabled=color_enabled)}: {item.summary}{location}")
        lines.append("")

    return "\n".join(lines).rstrip()


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)
