from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from security_agent.models import EvidenceItem, VulnerabilityFinding


@dataclass(slots=True)
class InvestigationContext:
    repo_root: str
    finding: VulnerabilityFinding


@dataclass(slots=True)
class CommandExecution:
    command: str
    exit_code: int
    stdout: str
    stderr: str


@dataclass(slots=True)
class InvestigationResult:
    status: str
    confidence: float
    reasoning_summary: str
    assumptions: list[str]
    evidence: list[EvidenceItem]
    commands_run: list[str]


class CommandExecutor(Protocol):
    def run(self, args: list[str], cwd: str) -> CommandExecution:
        pass


class Investigator(Protocol):
    def investigate(self, context: InvestigationContext) -> InvestigationResult:
        pass


class ShellCommandExecutor:
    ALLOWED_COMMANDS = {"rg", "ls", "find", "sed", "cat"}

    def run(self, args: list[str], cwd: str) -> CommandExecution:
        if not args:
            raise ValueError("Command cannot be empty.")

        command_name = args[0]
        if command_name not in self.ALLOWED_COMMANDS:
            raise ValueError(f"Unsupported investigation command: {command_name}")

        completed = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
        return CommandExecution(
            command=shlex.join(args),
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


class MockInvestigator:
    # uses simple heuristics based on file paths to determine reachability,
    # and includes command outputs as evidence

    def __init__(self, executor: CommandExecutor | None = None) -> None:
        self.executor = executor or ShellCommandExecutor()

    def investigate(self, context: InvestigationContext) -> InvestigationResult:
        repo_root = context.repo_root
        finding = context.finding
        commands_run: list[str] = []
        evidence: list[EvidenceItem] = []

        # search for the gem name in relevant rails directories + dependency files
        search_roots = self._existing_search_roots(repo_root)
        rg_args = ["rg", "-n", "--color", "never", finding.gem_name, *search_roots]
        search_result = self.executor.run(rg_args, cwd=repo_root)
        commands_run.append(search_result.command)

        matches = self._parse_rg_output(search_result.stdout, search_result.command)
        app_config_matches = [
            item
            for item in matches
            if item.path is not None
            and Path(item.path).parts
            and Path(item.path).parts[0] in {"app", "config", "lib"}
        ]
        weak_matches = [
            item
            for item in matches
            if item.path is not None
            and Path(item.path).parts
            and Path(item.path).parts[0] in {"Gemfile", "Gemfile.lock"}
        ]

        if app_config_matches:
            evidence.extend(app_config_matches[:2])
            snippet_evidence = self._read_snippet(repo_root, app_config_matches[0], commands_run)
            if snippet_evidence is not None:
                evidence.append(snippet_evidence)
            return InvestigationResult(
                status="reachable",
                confidence=0.86,
                reasoning_summary=(
                    f"Observed {finding.gem_name} referenced from application or configuration code."
                ),
                assumptions=[
                    "Direct code references are treated as a strong signal that the vulnerable gem is used."
                ],
                evidence=evidence,
                commands_run=commands_run,
            )

        if weak_matches:
            evidence.extend(weak_matches[:2])
            return InvestigationResult(
                status="possibly_reachable",
                confidence=0.42,
                reasoning_summary=(
                    f"Observed {finding.gem_name} only in dependency metadata, with no direct app/config references."
                ),
                assumptions=[
                    "The gem may still be reached indirectly through framework wiring that this mock investigator does not trace yet."
                ],
                evidence=evidence,
                commands_run=commands_run,
            )

        return InvestigationResult(
            status="not_observed",
            confidence=0.12,
            reasoning_summary=(
                f"No direct usage of {finding.gem_name} was observed in app, config, or lib paths."
            ),
            assumptions=[
                "Dynamic Rails loading may hide usage that cannot be detected by simple text search."
            ],
            evidence=[],
            commands_run=commands_run,
        )

    def _existing_search_roots(self, repo_root: str) -> list[str]:
        roots = []
        for name in ("app", "config", "lib", "Gemfile", "Gemfile.lock"):
            candidate = Path(repo_root) / name
            if candidate.exists():
                roots.append(name)
        return roots

    def _parse_rg_output(
        self,
        stdout: str,
        command: str,
    ) -> list[EvidenceItem]:
        items: list[EvidenceItem] = []
        for line in stdout.splitlines():
            path, line_number, snippet = line.split(":", 2)
            items.append(
                EvidenceItem(
                    kind="text_match",
                    summary=f"Matched search term in {path}:{line_number}",
                    path=str(Path(path)),
                    line=int(line_number),
                    command=command,
                    snippet=snippet.strip(),
                    relevance="mock_investigator_match",
                )
            )
        return items

    def _read_snippet(
        self,
        repo_root: str,
        evidence: EvidenceItem,
        commands_run: list[str],
    ) -> EvidenceItem | None:
        if evidence.path is None or evidence.line is None:
            return None

        start_line = max(1, evidence.line - 2)
        end_line = evidence.line + 2
        read_args = ["sed", "-n", f"{start_line},{end_line}p", evidence.path]
        read_result = self.executor.run(read_args, cwd=repo_root)
        commands_run.append(read_result.command)
        if read_result.exit_code != 0:
            return None

        return EvidenceItem(
            kind="file_snippet",
            summary=f"Read surrounding lines in {evidence.path}",
            path=evidence.path,
            line=evidence.line,
            command=read_result.command,
            snippet=read_result.stdout.strip(),
            relevance="mock_investigator_context",
        )
