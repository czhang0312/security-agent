from __future__ import annotations

import io
import json
from pathlib import Path
import tarfile
import tempfile
from typing import Callable
from urllib import error
from urllib import request

from security_agent.models import Advisory
from security_agent.versioning import version_satisfies_all

GITHUB_ADVISORY_ARCHIVE_URL = "https://codeload.github.com/github/advisory-database/tar.gz/refs/heads/main"


class AdvisoryDataUnavailableError(RuntimeError):
    pass


class AdvisoryDatabase:
    def __init__(self, advisories: list[Advisory]) -> None:
        self._by_gem: dict[str, list[Advisory]] = {}
        for advisory in advisories:
            self._by_gem.setdefault(advisory.gem_name, []).append(advisory)

    def for_gem(self, gem_name: str) -> list[Advisory]:
        return self._by_gem.get(gem_name, [])


def load_advisory_database(path: str | Path) -> AdvisoryDatabase:
    advisory_path = Path(path)
    if not advisory_path.exists():
        raise AdvisoryDataUnavailableError(
            f"Advisory cache not found at {advisory_path}. Run `security-agent advisories update` first."
        )
    raw = json.loads(advisory_path.read_text())
    advisories = [Advisory(**entry) for entry in raw]
    return AdvisoryDatabase(advisories=advisories)


def match_advisories(
    gem_name: str,
    version: str,
    advisory_db: AdvisoryDatabase,
) -> list[Advisory]:
    matches: list[Advisory] = []
    for advisory in advisory_db.for_gem(gem_name):
        if advisory_matches_version(version, advisory.affected_versions):
            matches.append(advisory)
    return matches


def advisory_matches_version(version: str, affected_versions: list[object]) -> bool:
    if not affected_versions:
        return False

    # example shape: ["< 2.0.0", ">= 1.5.0"]
    if all(isinstance(item, str) for item in affected_versions):
        return version_satisfies_all(version, [str(item) for item in affected_versions])

    # example shape: [["< 2.0.0", ">= 1.5.0"], ["< 3.0.0", ">= 2.5.0"]]
    for group in affected_versions:
        if isinstance(group, list) and all(isinstance(item, str) for item in group):
            if version_satisfies_all(version, group):
                return True
    return False


def update_advisory_cache(
    destination: str | Path,
    source_url: str = GITHUB_ADVISORY_ARCHIVE_URL,
    progress_reporter: Callable[[str], None] | None = None,
) -> int:
    report_progress(progress_reporter, f"Downloading advisory archive from {source_url}")
    try:
        with request.urlopen(source_url, timeout=60) as response:
            archive_bytes = response.read()
    except error.URLError as exc:
        raise AdvisoryDataUnavailableError(f"Failed to download advisory archive: {exc.reason}") from exc

    report_progress(progress_reporter, "Extracting advisory archive")
    try:
        advisories = parse_github_advisory_archive(archive_bytes, progress_reporter=progress_reporter)
    except (tarfile.TarError, json.JSONDecodeError) as exc:
        raise AdvisoryDataUnavailableError(f"Failed to parse advisory archive: {exc}") from exc
    if not advisories:
        raise AdvisoryDataUnavailableError("No RubyGems advisories were found in the downloaded archive.")

    destination_path = Path(destination).expanduser().resolve()
    destination_path.parent.mkdir(parents=True, exist_ok=True)

    report_progress(progress_reporter, f"Writing normalized advisory cache to {destination_path}")
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=destination_path.parent,
        suffix=".tmp",
        delete=False,
    ) as handle:
        json.dump([advisory_to_dict(item) for item in advisories], handle, indent=2)
        handle.write("\n")
        temp_path = Path(handle.name)

    temp_path.replace(destination_path)
    return len(advisories)


def parse_github_advisory_archive(
    archive_bytes: bytes,
    progress_reporter: Callable[[str], None] | None = None,
) -> list[Advisory]:
    advisories: list[Advisory] = []
    report_progress(progress_reporter, "Parsing RubyGems advisories from archive")
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile() or not member.name.endswith(".json"):
                continue
            if "/advisories/github-reviewed/" not in member.name:
                continue

            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            payload = json.loads(extracted.read().decode("utf-8"))
            advisories.extend(normalize_osv_record(payload))

    return advisories


def normalize_osv_record(record: dict) -> list[Advisory]:
    advisory_id = str(record.get("id", "")).strip()
    summary = str(record.get("summary", "")).strip()
    aliases = record.get("aliases", [])
    cve = next((alias for alias in aliases if isinstance(alias, str) and alias.startswith("CVE-")), None)
    severity = normalize_severity(record)
    notes = build_notes(record)

    advisories: list[Advisory] = []
    for affected in record.get("affected", []):
        if not isinstance(affected, dict):
            continue
        package = affected.get("package", {})
        if not isinstance(package, dict):
            continue
        if package.get("ecosystem") != "RubyGems":
            continue

        gem_name = str(package.get("name", "")).strip()
        if not gem_name:
            continue

        affected_constraints = normalize_affected_ranges(affected)
        if not affected_constraints:
            continue

        fixed_versions = normalize_fixed_versions(affected)
        advisories.append(
            Advisory(
                id=advisory_id,
                gem_name=gem_name,
                severity=severity,
                summary=summary,
                affected_versions=affected_constraints,
                fixed_versions=fixed_versions,
                cve=cve,
                notes=notes,
            )
        )
    return advisories


def normalize_affected_ranges(affected: dict) -> list[list[str]]:
    normalized: list[list[str]] = []
    for range_item in affected.get("ranges", []):
        if not isinstance(range_item, dict):
            continue
        if range_item.get("type") != "ECOSYSTEM":
            continue

        constraints: list[str] = []
        for event in range_item.get("events", []):
            if not isinstance(event, dict):
                continue
            introduced = event.get("introduced")
            fixed = event.get("fixed")
            last_affected = event.get("last_affected")

            if introduced not in {None, "0"}:
                constraints.append(f">= {introduced}")
            if fixed is not None:
                constraints.append(f"< {fixed}")
            elif last_affected is not None:
                constraints.append(f"<= {last_affected}")

        if constraints:
            normalized.append(constraints)

    return normalized


def normalize_fixed_versions(affected: dict) -> list[str]:
    fixed_versions: list[str] = []
    seen: set[str] = set()
    for range_item in affected.get("ranges", []):
        if not isinstance(range_item, dict):
            continue
        for event in range_item.get("events", []):
            if not isinstance(event, dict):
                continue
            fixed = event.get("fixed")
            if isinstance(fixed, str) and fixed not in seen:
                seen.add(fixed)
                fixed_versions.append(fixed)
    return fixed_versions


def normalize_severity(record: dict) -> str:
    database_specific = record.get("database_specific", {})
    if isinstance(database_specific, dict):
        severity = database_specific.get("severity")
        if isinstance(severity, str) and severity.strip():
            return severity.strip().lower()

    severity_items = record.get("severity", [])
    if isinstance(severity_items, list):
        for item in severity_items:
            if not isinstance(item, dict):
                continue
            if item.get("type") != "CVSS_V3":
                continue
            score = str(item.get("score", ""))
            if "CRITICAL" in score.upper():
                return "critical"
            if "HIGH" in score.upper():
                return "high"
            if "MEDIUM" in score.upper():
                return "medium"
            if "LOW" in score.upper():
                return "low"

    return "unknown"


def build_notes(record: dict) -> str | None:
    details = record.get("details")
    references = record.get("references", [])
    notes_parts: list[str] = []
    if isinstance(details, str) and details.strip():
        notes_parts.append(details.strip())
    if isinstance(references, list):
        urls = [item.get("url") for item in references if isinstance(item, dict) and item.get("url")]
        if urls:
            notes_parts.append("References: " + ", ".join(urls[:3]))
    return " ".join(notes_parts) if notes_parts else None


def advisory_to_dict(advisory: Advisory) -> dict:
    return {
        "id": advisory.id,
        "gem_name": advisory.gem_name,
        "severity": advisory.severity,
        "summary": advisory.summary,
        "affected_versions": advisory.affected_versions,
        "fixed_versions": advisory.fixed_versions,
        "cve": advisory.cve,
        "require_names": advisory.require_names,
        "namespaces": advisory.namespaces,
        "symbols": advisory.symbols,
        "notes": advisory.notes,
    }


def report_progress(progress_reporter: Callable[[str], None] | None, message: str) -> None:
    if progress_reporter is not None:
        progress_reporter(message)
