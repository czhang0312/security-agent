import json
import socket
from urllib import error

from security_agent.investigation import (
    CommandExecution,
    GeminiInvestigator,
    HttpOpenAIClient,
    InvestigationContext,
    InvestigationError,
    OpenAIInvestigator,
)
from security_agent.models import VulnerabilityFinding


class ScriptedClient:
    def __init__(self, responses: list[dict | str]) -> None:
        self.responses = responses
        self.prompts: list[str] = []

    def generate(self, model: str, prompt: str) -> str:
        self.prompts.append(prompt)
        response = self.responses.pop(0)
        if isinstance(response, str):
            return response
        return json.dumps(response)


class FakeExecutor:
    def __init__(self, outputs: dict[tuple[str, ...], CommandExecution]) -> None:
        self.outputs = outputs

    def run(self, args: list[str], cwd: str) -> CommandExecution:
        key = tuple(args)
        if key not in self.outputs:
            raise AssertionError(f"Unexpected command: {args}")
        return self.outputs[key]


def make_finding() -> VulnerabilityFinding:
    return VulnerabilityFinding(
        gem_name="nokogiri",
        installed_version="1.16.0",
        direct_dependency=True,
        advisory_id="SA-NOKOGIRI",
        severity="medium",
        summary="fixture",
        fixed_versions=["1.16.3"],
        require_names=["nokogiri"],
        namespaces=["Nokogiri"],
        symbols=["Nokogiri::XML.parse"],
    )


def test_gemini_investigator_executes_bounded_tool_loop() -> None:
    client = ScriptedClient(
        [
            {
                "action": "tool",
                "tool": "rg",
                "args": ["rg", "-n", "--color", "never", "-F", "Nokogiri", "app"],
            },
            {
                "action": "final",
                "status": "reachable",
                "confidence": 0.81,
                "reasoning_summary": "Observed Nokogiri usage in application code.",
                "assumptions": ["The matched method call belongs to the vulnerable path."],
                "evidence": [
                    {
                        "kind": "text_match",
                        "summary": "Matched Nokogiri call in parser",
                        "path": "app/services/parser.rb",
                        "line": 3,
                        "snippet": "Nokogiri::XML.parse(payload)",
                    }
                ],
            },
        ]
    )
    executor = FakeExecutor(
        {
            ("rg", "-n", "--color", "never", "-F", "Nokogiri", "app"): CommandExecution(
                command="rg -n --color never -F Nokogiri app",
                exit_code=0,
                stdout="app/services/parser.rb:3:Nokogiri::XML.parse(payload)\n",
                stderr="",
            )
        }
    )
    investigator = GeminiInvestigator(
        client=client,
        model="gemini-test",
        max_steps=4,
        max_tool_output_chars=500,
        executor=executor,
    )

    result = investigator.investigate(
        InvestigationContext(repo_root="/tmp/repo", finding=make_finding())
    )

    assert result.status == "reachable"
    assert result.commands_run == ["rg -n --color never -F Nokogiri app"]
    assert result.evidence[0].path == "app/services/parser.rb"
    assert len(client.prompts) == 2


def test_openai_investigator_executes_bounded_tool_loop() -> None:
    progress_messages: list[str] = []
    client = ScriptedClient(
        [
            {
                "action": "tool",
                "tool": "ls",
                "args": ["ls", "app"],
            },
            {
                "action": "final",
                "status": "reachable",
                "confidence": 0.74,
                "reasoning_summary": "Observed application entrypoints that invoke vulnerable code.",
                "assumptions": ["The observed Rails service is part of the request flow."],
                "evidence": [
                    {
                        "kind": "text_match",
                        "summary": "Matched parser service reference",
                        "path": "app/services/parser.rb",
                        "line": 1,
                        "snippet": "class Parser",
                    }
                ],
            },
        ]
    )
    executor = FakeExecutor(
        {
            ("ls", "app"): CommandExecution(
                command="ls app",
                exit_code=0,
                stdout="services\n",
                stderr="",
            )
        }
    )
    investigator = OpenAIInvestigator(
        client=client,
        model="gpt-test",
        max_steps=3,
        max_tool_output_chars=500,
        executor=executor,
        progress_reporter=progress_messages.append,
    )

    result = investigator.investigate(
        InvestigationContext(repo_root="/tmp/repo", finding=make_finding())
    )

    assert result.status == "reachable"
    assert result.commands_run == ["ls app"]
    assert result.evidence[0].path == "app/services/parser.rb"
    assert len(client.prompts) == 2
    assert progress_messages == [
        "OpenAI: investigating nokogiri 1.16.0",
        "OpenAI step 1/3: requesting model",
        "OpenAI step 1/3: running ls app",
        "OpenAI step 2/3: requesting model",
        "OpenAI final: reachable",
    ]


def test_llm_investigator_returns_incomplete_result_on_step_limit() -> None:
    progress_messages: list[str] = []
    client = ScriptedClient(
        [
            {
                "action": "tool",
                "tool": "ls",
                "args": ["ls", "app"],
            }
        ]
    )
    executor = FakeExecutor(
        {
            ("ls", "app"): CommandExecution(
                command="ls app",
                exit_code=0,
                stdout="services\n",
                stderr="",
            )
        }
    )
    investigator = OpenAIInvestigator(
        client=client,
        model="gpt-test",
        max_steps=1,
        max_tool_output_chars=500,
        executor=executor,
        progress_reporter=progress_messages.append,
    )

    result = investigator.investigate(
        InvestigationContext(repo_root="/tmp/repo", finding=make_finding())
    )

    assert result.status == "possibly_reachable"
    assert "did not complete" in result.reasoning_summary
    assert progress_messages == [
        "OpenAI: investigating nokogiri 1.16.0",
        "OpenAI step 1/1: requesting model",
        "OpenAI step 1/1: running ls app",
    ]


def test_llm_investigator_rejects_invalid_response() -> None:
    client = ScriptedClient(["not-json"])
    investigator = OpenAIInvestigator(client=client, model="gpt-test")

    try:
        investigator.investigate(InvestigationContext(repo_root="/tmp/repo", finding=make_finding()))
    except InvestigationError as exc:
        assert "parse" in str(exc).lower()
    else:
        raise AssertionError("Expected InvestigationError for invalid provider response")


class FakeHttpResponse:
    def __init__(self, body: dict) -> None:
        self._body = json.dumps(body).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


def test_http_openai_client_retries_timeout_then_succeeds() -> None:
    progress_messages: list[str] = []
    sleep_calls: list[float] = []
    attempts = {"count": 0}

    def opener(http_request, timeout=30):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise TimeoutError("timed out")
        return FakeHttpResponse(
            {
                "output": [
                    {"type": "message", "content": [{"type": "output_text", "text": "{\"ok\": true}"}]}
                ]
            }
        )

    client = HttpOpenAIClient(
        "test-key",
        max_retries=3,
        base_delay_seconds=1.0,
        progress_reporter=progress_messages.append,
        opener=opener,
        sleeper=sleep_calls.append,
    )

    result = client.generate("gpt-test", "hello")

    assert result == "{\"ok\": true}"
    assert attempts["count"] == 2
    assert sleep_calls == [1.0]
    assert progress_messages == ["OpenAI request timed out, retrying in 1.0s (attempt 2/3)"]


def test_http_openai_client_retries_503_then_succeeds() -> None:
    progress_messages: list[str] = []
    sleep_calls: list[float] = []
    attempts = {"count": 0}

    def opener(http_request, timeout=30):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise error.HTTPError(
                url="https://api.openai.com/v1/responses",
                code=503,
                msg="unavailable",
                hdrs=None,
                fp=None,
            )
        return FakeHttpResponse(
            {
                "output": [
                    {"type": "message", "content": [{"type": "output_text", "text": "{\"ok\": true}"}]}
                ]
            }
        )

    client = HttpOpenAIClient(
        "test-key",
        max_retries=3,
        base_delay_seconds=1.0,
        progress_reporter=progress_messages.append,
        opener=opener,
        sleeper=sleep_calls.append,
    )

    result = client.generate("gpt-test", "hello")

    assert result == "{\"ok\": true}"
    assert attempts["count"] == 2
    assert sleep_calls == [1.0]
    assert progress_messages == ["OpenAI API returned 503, retrying in 1.0s (attempt 2/3)"]


def test_http_openai_client_fails_fast_on_401() -> None:
    attempts = {"count": 0}

    def opener(http_request, timeout=30):
        attempts["count"] += 1
        raise error.HTTPError(
            url="https://api.openai.com/v1/responses",
            code=401,
            msg="unauthorized",
            hdrs=None,
            fp=None,
        )

    client = HttpOpenAIClient("test-key", max_retries=3, opener=opener, sleeper=lambda seconds: None)

    try:
        client.generate("gpt-test", "hello")
    except InvestigationError as exc:
        assert "401" in str(exc)
    else:
        raise AssertionError("Expected InvestigationError")

    assert attempts["count"] == 1


def test_http_openai_client_raises_after_retry_exhaustion() -> None:
    sleep_calls: list[float] = []

    def opener(http_request, timeout=30):
        raise socket.timeout("timed out")

    client = HttpOpenAIClient(
        "test-key",
        max_retries=3,
        base_delay_seconds=0.5,
        opener=opener,
        sleeper=sleep_calls.append,
    )

    try:
        client.generate("gpt-test", "hello")
    except InvestigationError as exc:
        assert "timed out" in str(exc).lower()
    else:
        raise AssertionError("Expected InvestigationError")

    assert sleep_calls == [0.5, 1.0]
