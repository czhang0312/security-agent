from security_agent.config import load_config


def test_load_config_defaults_to_mock(monkeypatch) -> None:
    monkeypatch.delenv("SECURITY_AGENT_INVESTIGATOR_PROVIDER", raising=False)
    monkeypatch.delenv("SECURITY_AGENT_GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("SECURITY_AGENT_OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    config = load_config()

    assert config.investigator_provider == "mock"
    assert config.gemini_api_key is None
    assert config.openai_api_key is None
    assert config.max_investigation_steps == 6


def test_load_config_uses_override_and_env(monkeypatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "env-key")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-key")
    monkeypatch.setenv("SECURITY_AGENT_MAX_INVESTIGATION_STEPS", "9")
    monkeypatch.setenv("SECURITY_AGENT_MAX_TOOL_OUTPUT_CHARS", "1234")

    config = load_config(investigator_provider="gemini")

    assert config.investigator_provider == "gemini"
    assert config.gemini_api_key == "env-key"
    assert config.openai_api_key == "openai-key"
    assert config.max_investigation_steps == 9
    assert config.max_tool_output_chars == 1234


def test_load_config_supports_openai_override(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "openai-key")
    monkeypatch.setenv("SECURITY_AGENT_OPENAI_MODEL", "gpt-5")

    config = load_config(investigator_provider="openai")

    assert config.investigator_provider == "openai"
    assert config.openai_api_key == "openai-key"
    assert config.openai_model == "gpt-5"
