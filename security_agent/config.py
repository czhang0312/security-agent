from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(slots=True)
class Config:
    advisory_path: Path
    investigator_provider: str = "mock"
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-2.5-flash"
    openai_api_key: str | None = None
    openai_model: str = "gpt-5-mini"
    max_investigation_steps: int = 6
    max_tool_output_chars: int = 4000
    max_investigations: int = 3
    provider_max_retries: int = 3
    provider_retry_base_delay_seconds: float = 1.0


def default_advisory_cache_path() -> Path:
    xdg_cache_home = os.getenv("XDG_CACHE_HOME")
    if xdg_cache_home:
        cache_root = Path(xdg_cache_home).expanduser()
    else:
        cache_root = Path.home() / ".cache"
    return cache_root / "security-agent" / "advisories.json"


def load_config(
    config_path: str | None = None,
    investigator_provider: str | None = None,
) -> Config:
    provider = (
        investigator_provider
        or os.getenv("SECURITY_AGENT_INVESTIGATOR_PROVIDER", "mock").strip().lower()
        or "mock"
    )
    gemini_api_key = (
        os.getenv("SECURITY_AGENT_GEMINI_API_KEY")
        or os.getenv("GEMINI_API_KEY")
        or None
    )
    gemini_model = os.getenv("SECURITY_AGENT_GEMINI_MODEL", "gemini-2.5-flash")
    openai_api_key = (
        os.getenv("SECURITY_AGENT_OPENAI_API_KEY")
        or os.getenv("OPENAI_API_KEY")
        or None
    )
    openai_model = os.getenv("SECURITY_AGENT_OPENAI_MODEL", "gpt-5-mini")
    max_steps = _int_from_env("SECURITY_AGENT_MAX_INVESTIGATION_STEPS", 6)
    max_chars = _int_from_env("SECURITY_AGENT_MAX_TOOL_OUTPUT_CHARS", 4000)
    max_investigations = _int_from_env("SECURITY_AGENT_MAX_INVESTIGATIONS", 3)
    provider_max_retries = _int_from_env("SECURITY_AGENT_PROVIDER_MAX_RETRIES", 3)
    provider_retry_base_delay_seconds = _float_from_env("SECURITY_AGENT_PROVIDER_RETRY_BASE_DELAY_SECONDS", 1.0)

    if config_path is not None:
        return Config(
            advisory_path=Path(config_path).expanduser().resolve(),
            investigator_provider=provider,
            gemini_api_key=gemini_api_key,
            gemini_model=gemini_model,
            openai_api_key=openai_api_key,
            openai_model=openai_model,
            max_investigation_steps=max_steps,
            max_tool_output_chars=max_chars,
            max_investigations=max_investigations,
            provider_max_retries=provider_max_retries,
            provider_retry_base_delay_seconds=provider_retry_base_delay_seconds,
        )

    default_path = default_advisory_cache_path()
    return Config(
        advisory_path=default_path,
        investigator_provider=provider,
        gemini_api_key=gemini_api_key,
        gemini_model=gemini_model,
        openai_api_key=openai_api_key,
        openai_model=openai_model,
        max_investigation_steps=max_steps,
        max_tool_output_chars=max_chars,
        max_investigations=max_investigations,
        provider_max_retries=provider_max_retries,
        provider_retry_base_delay_seconds=provider_retry_base_delay_seconds,
    )


def _int_from_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _float_from_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default
