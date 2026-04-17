from __future__ import annotations

from pathlib import Path

from security_agent.models import Dependency, DependencyGraph


def parse_gemfile_lock(lockfile_path: str | Path) -> DependencyGraph:
    path = Path(lockfile_path)
    lines = path.read_text().splitlines()

    specs: dict[str, str] = {}
    direct_dependencies: set[str] = set()

    section: str | None = None

    for raw_line in lines:
        if not raw_line.strip():
            continue

        if raw_line == "GEM":
            section = "gem"
            continue

        if raw_line == "DEPENDENCIES":
            section = "dependencies"
            continue

        if raw_line in {"PLATFORMS", "BUNDLED WITH", "RUBY VERSION", "PATH", "GIT"}:
            section = None
            continue

        if section == "gem":
            stripped = raw_line.lstrip()
            indent = len(raw_line) - len(stripped)
            if indent == 4 and "(" in stripped and stripped.endswith(")"):
                name, _, version_part = stripped.partition(" (")
                specs[name] = version_part[:-1]

        if section == "dependencies":
            stripped = raw_line.strip()
            if not stripped:
                continue
            dependency_name = stripped.split()[0]
            if dependency_name.endswith("!"):
                dependency_name = dependency_name[:-1]
            direct_dependencies.add(dependency_name)

    dependencies = [
        Dependency(name=name, version=version, direct=name in direct_dependencies)
        for name, version in sorted(specs.items())
    ]
    return DependencyGraph(dependencies=dependencies)

