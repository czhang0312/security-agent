from __future__ import annotations

import json
from pathlib import Path

from security_agent.models import Advisory
from security_agent.versioning import version_satisfies_all


class AdvisoryDatabase:
    def __init__(self, advisories: list[Advisory]) -> None:
        self._by_gem: dict[str, list[Advisory]] = {}
        for advisory in advisories:
            self._by_gem.setdefault(advisory.gem_name, []).append(advisory)

    def for_gem(self, gem_name: str) -> list[Advisory]:
        return self._by_gem.get(gem_name, [])


def load_advisory_database(path: str | Path) -> AdvisoryDatabase:
    raw = json.loads(Path(path).read_text())
    advisories = [Advisory(**entry) for entry in raw]
    return AdvisoryDatabase(advisories=advisories)


def match_advisories(
    gem_name: str,
    version: str,
    advisory_db: AdvisoryDatabase,
) -> list[Advisory]:
    matches: list[Advisory] = []
    for advisory in advisory_db.for_gem(gem_name):
        if version_satisfies_all(version, advisory.affected_versions):
            matches.append(advisory)
    return matches

