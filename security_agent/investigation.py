from __future__ import annotations

import json
import re
import shlex
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol
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


class PromptClient(Protocol):
    def generate(self, model: str, prompt: str) -> str:
        pass


ProgressReporter = Callable[[str], None]


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


class HttpOpenAIClient:
    API_URL = "https://api.openai.com/v1/responses"
    RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

    def __init__(
        self,
        api_key: str,
        max_retries: int = 3,
        base_delay_seconds: float = 1.0,
        progress_reporter: ProgressReporter | None = None,
        opener: Callable[..., Any] | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self.api_key = api_key
        self.max_retries = max(1, max_retries)
        self.base_delay_seconds = max(0.0, base_delay_seconds)
        self.progress_reporter = progress_reporter
        self.opener = opener or request.urlopen
        self.sleeper = sleeper or time.sleep

    def generate(self, model: str, prompt: str) -> str:
        payload = json.dumps(
            {
                "model": model,
                "input": prompt,
                "text": {"format": {"type": "json_object"}},
            }
        ).encode("utf-8")
        http_request = request.Request(
            self.API_URL,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )

        last_error: InvestigationError | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                with self.opener(http_request, timeout=30) as response:
                    body = json.loads(response.read().decode("utf-8"))
            except error.HTTPError as exc:
                details = read_http_error_details(exc)
                if exc.code in self.RETRYABLE_STATUS_CODES and attempt < self.max_retries:
                    self._report_retry(
                        f"OpenAI API returned {exc.code}",
                        attempt=attempt,
                        total_attempts=self.max_retries,
                    )
                    self._sleep_before_retry(attempt)
                    continue
                raise InvestigationError(f"OpenAI API request failed: {exc.code} {details}") from exc
            except (TimeoutError, socket.timeout) as exc:
                last_error = InvestigationError("OpenAI API request timed out.")
                if attempt < self.max_retries:
                    self._report_retry(
                        "OpenAI request timed out",
                        attempt=attempt,
                        total_attempts=self.max_retries,
                    )
                    self._sleep_before_retry(attempt)
                    continue
                raise last_error from exc
            except error.URLError as exc:
                last_error = InvestigationError(f"OpenAI API request failed: {exc.reason}")
                if attempt < self.max_retries:
                    self._report_retry(
                        f"OpenAI network error: {exc.reason}",
                        attempt=attempt,
                        total_attempts=self.max_retries,
                    )
                    self._sleep_before_retry(attempt)
                    continue
                raise last_error from exc

            output_text = extract_response_output_text(body)
            if output_text is None:
                raise InvestigationError("OpenAI response did not include text content.")
            return output_text

        raise last_error or InvestigationError("OpenAI API request failed after retries.")

    def _sleep_before_retry(self, attempt: int) -> None:
        delay = self.base_delay_seconds * (2 ** (attempt - 1))
        self.sleeper(delay)

    def _report_retry(self, reason: str, attempt: int, total_attempts: int) -> None:
        if self.progress_reporter is None:
            return
        delay = self.base_delay_seconds * (2 ** (attempt - 1))
        next_attempt = attempt + 1
        self.progress_reporter(
            f"{reason}, retrying in {delay:.1f}s (attempt {next_attempt}/{total_attempts})"
        )


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


class BaseLLMInvestigator:
    provider_name = "llm"

    def __init__(
        self,
        client: PromptClient,
        model: str,
        max_steps: int = 6,
        max_tool_output_chars: int = 4000,
        executor: CommandExecutor | None = None,
        progress_reporter: ProgressReporter | None = None,
    ) -> None:
        self.client = client
        self.model = model
        self.max_steps = max_steps
        self.max_tool_output_chars = max_tool_output_chars
        self.executor = executor or ShellCommandExecutor()
        self.progress_reporter = progress_reporter

    def investigate(self, context: InvestigationContext) -> InvestigationResult:
        observations: list[dict[str, Any]] = []
        commands_run: list[str] = []
        self.report_progress(
            f"{self.provider_name}: investigating {context.finding.gem_name} {context.finding.installed_version}"
        )

        for step_index in range(self.max_steps):
            step_number = step_index + 1
            self.report_progress(f"{self.provider_name} step {step_number}/{self.max_steps}: requesting model")
            prompt = self._build_prompt(context, observations, step_index + 1)
            response_text = self.client.generate(self.model, prompt)
            response = parse_agent_response(response_text)
            action = response.get("action")

            if action == "tool":
                execution = execute_tool_action(self.executor, response, context.repo_root)
                self.report_progress(
                    f"{self.provider_name} step {step_number}/{self.max_steps}: running {truncate_command(execution.command)}"
                )
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
                self.report_progress(
                    f"{self.provider_name} final: {str(response.get('status', 'unknown')).strip() or 'unknown'}"
                )
                return finalize_agent_response(response, commands_run)

            raise InvestigationError(
                f"{self.provider_name} response must request a tool or return a final decision."
            )

        return InvestigationResult(
            status="possibly_reachable",
            confidence=0.25,
            reasoning_summary=(
                f"{self.provider_name} investigation did not complete within the configured step limit."
            ),
            assumptions=[
                "The model exhausted the bounded investigation loop before returning a final decision."
            ],
            evidence=[],
            commands_run=commands_run,
        )

    def report_progress(self, message: str) -> None:
        if self.progress_reporter is not None and self.provider_name == "OpenAI":
            self.progress_reporter(message)

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


class GeminiInvestigator(BaseLLMInvestigator):
    provider_name = "Gemini"


class OpenAIInvestigator(BaseLLMInvestigator):
    provider_name = "OpenAI"


def build_investigator(
    config: Config,
    client: PromptClient | None = None,
    progress_reporter: ProgressReporter | None = None,
) -> Investigator:
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
            progress_reporter=progress_reporter,
        )
    if provider == "openai":
        if not config.openai_api_key and client is None:
            raise InvestigationError("OpenAI investigator selected but no API key is configured.")
        openai_client = client or HttpOpenAIClient(
            config.openai_api_key or "",
            max_retries=config.provider_max_retries,
            base_delay_seconds=config.provider_retry_base_delay_seconds,
            progress_reporter=progress_reporter,
        )
        return OpenAIInvestigator(
            client=openai_client,
            model=config.openai_model,
            max_steps=config.max_investigation_steps,
            max_tool_output_chars=config.max_tool_output_chars,
            progress_reporter=progress_reporter,
        )
    return MockInvestigator()


def read_http_error_details(exc: error.HTTPError) -> str:
    if exc.fp is None:
        return exc.reason or exc.msg
    return exc.read().decode("utf-8", errors="replace")


def make_stderr_progress_reporter() -> ProgressReporter:
    def report(message: str) -> None:
        print(message, file=sys.stderr, flush=True)

    return report


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
        raise InvestigationError(f"Failed to parse model response as JSON: {cleaned}") from exc

    if not isinstance(parsed, dict):
        raise InvestigationError("Model response must be a JSON object.")
    return parsed


def execute_tool_action(
    executor: CommandExecutor,
    response: dict[str, Any],
    repo_root: str,
) -> CommandExecution:
    tool_name = str(response.get("tool", "")).strip()
    args = response.get("args")
    if not isinstance(args, list):
        raise InvestigationError("Tool request must include an args list.")
    if not args:
        raise InvestigationError("Tool request cannot be empty.")
    if args[0] != tool_name:
        raise InvestigationError("Tool name must match args[0].")
    return executor.run([str(item) for item in args], cwd=repo_root)


def truncate_command(command: str, limit: int = 120) -> str:
    if len(command) <= limit:
        return command
    return f"{command[: limit - 3]}..."


def finalize_agent_response(
    response: dict[str, Any],
    commands_run: list[str],
) -> InvestigationResult:
    status = str(response.get("status", "")).strip()
    if status not in {"reachable", "possibly_reachable", "not_observed"}:
        raise InvestigationError("Final response returned an invalid status.")

    try:
        confidence = float(response.get("confidence"))
    except (TypeError, ValueError) as exc:
        raise InvestigationError("Final response returned an invalid confidence.") from exc

    evidence_payload = response.get("evidence", [])
    if not isinstance(evidence_payload, list):
        raise InvestigationError("Final response returned invalid evidence.")

    evidence = [
        EvidenceItem(
            kind=str(item.get("kind", "reasoning_note")),
            summary=str(item.get("summary", "")),
            path=str(item["path"]) if item.get("path") is not None else None,
            line=int(item["line"]) if item.get("line") is not None else None,
            symbol=str(item["symbol"]) if item.get("symbol") is not None else None,
            snippet=str(item["snippet"]) if item.get("snippet") is not None else None,
            relevance="llm_final_response",
        )
        for item in evidence_payload
        if isinstance(item, dict)
    ]

    assumptions = response.get("assumptions", [])
    if not isinstance(assumptions, list):
        raise InvestigationError("Final response returned invalid assumptions.")

    reasoning_summary = str(response.get("reasoning_summary", "")).strip()
    if not reasoning_summary:
        raise InvestigationError("Final response did not include a reasoning summary.")

    return InvestigationResult(
        status=status,
        confidence=confidence,
        reasoning_summary=reasoning_summary,
        assumptions=[str(item) for item in assumptions],
        evidence=evidence,
        commands_run=commands_run,
    )


def extract_response_output_text(body: dict[str, Any]) -> str | None:
    output = body.get("output")
    if isinstance(output, list):
        for item in output:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if isinstance(content, list):
                for part in content:
                    if not isinstance(part, dict):
                        continue
                    if part.get("type") in {"output_text", "text"} and isinstance(part.get("text"), str):
                        return part["text"]
    output_text = body.get("output_text")
    if isinstance(output_text, str):
        return output_text
    return None
