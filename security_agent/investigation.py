from __future__ import annotations

import json
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib import error, parse, request

from security_agent.config import Config
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


class InvestigationError(RuntimeError):
    pass


class CommandExecutor(Protocol):
    def run(self, args: list[str], cwd: str) -> CommandExecution:
        pass


class Investigator(Protocol):
    def investigate(self, context: InvestigationContext) -> InvestigationResult:
        pass


class GeminiClient(Protocol):
    def generate(self, model: str, prompt: str) -> str:
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


class HttpGeminiClient:
    API_ROOT = "https://generativelanguage.googleapis.com/v1beta/models"

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    def generate(self, model: str, prompt: str) -> str:
        url = f"{self.API_ROOT}/{parse.quote(model)}:generateContent?key={parse.quote(self.api_key)}"
        payload = json.dumps(
            {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.1},
            }
        ).encode("utf-8")
        http_request = request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(http_request, timeout=30) as response:
                body = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")
            raise InvestigationError(f"Gemini API request failed: {exc.code} {details}") from exc
        except error.URLError as exc:
            raise InvestigationError(f"Gemini API request failed: {exc.reason}") from exc

        try:
            return body["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError) as exc:
            raise InvestigationError("Gemini response did not include text content.") from exc


class MockInvestigator:
    def __init__(self, executor: CommandExecutor | None = None) -> None:
        self.executor = executor or ShellCommandExecutor()

    def investigate(self, context: InvestigationContext) -> InvestigationResult:
        repo_root = context.repo_root
        finding = context.finding
        commands_run: list[str] = []
        evidence: list[EvidenceItem] = []

        search_terms = finding_search_terms(finding)
        matches = self._search_terms(repo_root, search_terms, commands_run)
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
                    f"Observed {finding.gem_name} or related APIs referenced from application or configuration code."
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
                f"No direct usage of {finding.gem_name} or its hinted APIs was observed in app, config, or lib paths."
            ),
            assumptions=[
                "Dynamic Rails loading may hide usage that cannot be detected by simple text search."
            ],
            evidence=[],
            commands_run=commands_run,
        )

    def _search_terms(
        self,
        repo_root: str,
        search_terms: list[str],
        commands_run: list[str],
    ) -> list[EvidenceItem]:
        matches: list[EvidenceItem] = []
        for term in search_terms:
            rg_args = ["rg", "-n", "--color", "never", "-F", term, *existing_search_roots(repo_root)]
            search_result = self.executor.run(rg_args, cwd=repo_root)
            commands_run.append(search_result.command)
            matches.extend(parse_rg_output(search_result.stdout, search_result.command))
        return dedupe_evidence(matches)

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


class GeminiInvestigator:
    def __init__(
        self,
        client: GeminiClient,
        model: str,
        max_steps: int = 6,
        max_tool_output_chars: int = 4000,
        executor: CommandExecutor | None = None,
    ) -> None:
        self.client = client
        self.model = model
        self.max_steps = max_steps
        self.max_tool_output_chars = max_tool_output_chars
        self.executor = executor or ShellCommandExecutor()

    def investigate(self, context: InvestigationContext) -> InvestigationResult:
        observations: list[dict[str, Any]] = []
        commands_run: list[str] = []

        for step_index in range(self.max_steps):
            prompt = self._build_prompt(context, observations, step_index + 1)
            response_text = self.client.generate(self.model, prompt)
            response = parse_agent_response(response_text)
            action = response.get("action")

            if action == "tool":
                tool_name = str(response.get("tool", "")).strip()
                args = response.get("args")
                if not isinstance(args, list):
                    raise InvestigationError("Gemini tool request must include an args list.")
                if not args:
                    raise InvestigationError("Gemini tool request cannot be empty.")
                if args[0] != tool_name:
                    raise InvestigationError("Gemini tool name must match args[0].")
                execution = self.executor.run([str(item) for item in args], cwd=context.repo_root)
                commands_run.append(execution.command)
                observations.append(
                    {
                        "command": execution.command,
                        "exit_code": execution.exit_code,
                        "stdout": execution.stdout[: self.max_tool_output_chars],
                        "stderr": execution.stderr[: self.max_tool_output_chars],
                    }
                )
                continue

            if action == "final":
                # early return on final decision, skipping remaining steps
                return self._finalize(response, commands_run)

            raise InvestigationError("Gemini response must request a tool or return a final decision.")

        # if we reach here, it means did not early return so failed to reach a final decision within the step limit
        return InvestigationResult(
            status="possibly_reachable",
            confidence=0.25,
            reasoning_summary="Gemini investigation did not complete within the configured step limit.",
            assumptions=[
                "The model exhausted the bounded investigation loop before returning a final decision."
            ],
            evidence=[],
            commands_run=commands_run,
        )

    def _build_prompt(
        self,
        context: InvestigationContext,
        observations: list[dict[str, Any]],
        step_number: int,
    ) -> str:
        finding = context.finding
        hints = {
            "require_names": finding.require_names,
            "namespaces": finding.namespaces,
            "symbols": finding.symbols,
            "notes": finding.advisory_notes,
        }
        return f"""
You are investigating whether a vulnerable Ruby gem appears reachable in a Rails repository.

Rules:
- Use only read-only repo exploration.
- Allowed commands: rg, ls, find, sed, cat.
- If you request a tool, return JSON only.
- If you return a final answer, return JSON only.
- Do not claim exploitability. Only assess usage reachability.
- Prefer "possibly_reachable" over overstated certainty.
- Cite only files and commands that actually appeared in the tool loop.

Finding:
{json.dumps({
    "gem_name": finding.gem_name,
    "installed_version": finding.installed_version,
    "severity": finding.severity,
    "summary": finding.summary,
    "direct_dependency": finding.direct_dependency,
    "fixed_versions": finding.fixed_versions,
    "hints": hints,
}, indent=2)}

Repo root: {context.repo_root}
Step: {step_number} of {self.max_steps}

Previous observations:
{json.dumps(observations, indent=2)}

Respond with one of:
1. Tool request:
{{
  "action": "tool",
  "tool": "rg",
  "args": ["rg", "-n", "--color", "never", "-F", "Nokogiri", "app", "config"]
}}

2. Final answer:
{{
  "action": "final",
  "status": "reachable" | "possibly_reachable" | "not_observed",
  "confidence": 0.0,
  "reasoning_summary": "short explanation",
  "assumptions": ["..."],
  "evidence": [
    {{
      "kind": "text_match",
      "summary": "Matched call in app/services/parser.rb:3",
      "path": "app/services/parser.rb",
      "line": 3,
      "snippet": "Nokogiri::XML.parse(payload)"
    }}
  ]
}}
""".strip()

    def _finalize(self, response: dict[str, Any], commands_run: list[str]) -> InvestigationResult:
        status = str(response.get("status", "")).strip()
        if status not in {"reachable", "possibly_reachable", "not_observed"}:
            raise InvestigationError("Gemini final response returned an invalid status.")

        try:
            confidence = float(response.get("confidence"))
        except (TypeError, ValueError) as exc:
            raise InvestigationError("Gemini final response returned an invalid confidence.") from exc

        evidence_payload = response.get("evidence", [])
        if not isinstance(evidence_payload, list):
            raise InvestigationError("Gemini final response returned invalid evidence.")

        evidence = [
            EvidenceItem(
                kind=str(item.get("kind", "reasoning_note")),
                summary=str(item.get("summary", "")),
                path=str(item["path"]) if item.get("path") is not None else None,
                line=int(item["line"]) if item.get("line") is not None else None,
                symbol=str(item["symbol"]) if item.get("symbol") is not None else None,
                snippet=str(item["snippet"]) if item.get("snippet") is not None else None,
                relevance="gemini_final_response",
            )
            for item in evidence_payload
            if isinstance(item, dict)
        ]

        assumptions = response.get("assumptions", [])
        if not isinstance(assumptions, list):
            raise InvestigationError("Gemini final response returned invalid assumptions.")

        reasoning_summary = str(response.get("reasoning_summary", "")).strip()
        if not reasoning_summary:
            raise InvestigationError("Gemini final response did not include a reasoning summary.")

        return InvestigationResult(
            status=status,
            confidence=confidence,
            reasoning_summary=reasoning_summary,
            assumptions=[str(item) for item in assumptions],
            evidence=evidence,
            commands_run=commands_run,
        )


def build_investigator(config: Config, client: GeminiClient | None = None) -> Investigator:
    provider = config.investigator_provider.lower()
    if provider == "gemini":
        if not config.gemini_api_key and client is None:
            raise InvestigationError("Gemini investigator selected but no API key is configured.")
        gemini_client = client or HttpGeminiClient(config.gemini_api_key or "")
        return GeminiInvestigator(
            client=gemini_client,
            model=config.gemini_model,
            max_steps=config.max_investigation_steps,
            max_tool_output_chars=config.max_tool_output_chars,
        )
    return MockInvestigator()


def existing_search_roots(repo_root: str) -> list[str]:
    roots = []
    for name in ("app", "config", "lib", "Gemfile", "Gemfile.lock"):
        candidate = Path(repo_root) / name
        if candidate.exists():
            roots.append(name)
    return roots


def parse_rg_output(stdout: str, command: str) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    for line in stdout.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        path, line_number, snippet = parts
        if not line_number.isdigit():
            continue
        items.append(
            EvidenceItem(
                kind="text_match",
                summary=f"Matched search term in {path}:{line_number}",
                path=str(Path(path)),
                line=int(line_number),
                command=command,
                snippet=snippet.strip(),
                relevance="repo_search_match",
            )
        )
    return items


def finding_search_terms(finding: VulnerabilityFinding) -> list[str]:
    terms = [
        finding.gem_name,
        *finding.require_names,
        *finding.namespaces,
        *finding.symbols,
    ]
    normalized: list[str] = []
    seen: set[str] = set()
    for term in terms:
        stripped = term.strip()
        if not stripped:
            continue
        if stripped not in seen:
            seen.add(stripped)
            normalized.append(stripped)
    return normalized or [finding.gem_name]


def dedupe_evidence(items: list[EvidenceItem]) -> list[EvidenceItem]:
    seen: set[tuple[str | None, int | None, str | None]] = set()
    deduped: list[EvidenceItem] = []
    for item in items:
        key = (item.path, item.line, item.snippet)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def parse_agent_response(response_text: str) -> dict[str, Any]:
    cleaned = response_text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise InvestigationError(f"Failed to parse Gemini response as JSON: {cleaned}") from exc

    if not isinstance(parsed, dict):
        raise InvestigationError("Gemini response must be a JSON object.")
    return parsed
