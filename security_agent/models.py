from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(slots=True)
class RepoInfo:
    root: str
    kind: str


@dataclass(slots=True)
class Dependency:
    name: str
    version: str
    direct: bool


@dataclass(slots=True)
class DependencyGraph:
    dependencies: list[Dependency]


@dataclass(slots=True)
class Advisory:
    id: str
    gem_name: str
    severity: str
    summary: str
    affected_versions: list[str]
    fixed_versions: list[str]
    cve: str | None = None


@dataclass(slots=True)
class VulnerabilityFinding:
    gem_name: str
    installed_version: str
    direct_dependency: bool
    advisory_id: str
    severity: str
    summary: str
    fixed_versions: list[str]
    cve: str | None = None
    reachability_status: str = "not_investigated"
    confidence: float | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)
    priority: str = "unranked"


@dataclass(slots=True)
class ScanResult:
    repo_path: str
    repo_kind: str
    dependency_count: int
    findings: list[VulnerabilityFinding]
    scanned_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

