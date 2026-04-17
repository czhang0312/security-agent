from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class Config:
    advisory_path: Path


def load_config(config_path: str | None = None) -> Config:
    if config_path is not None:
        return Config(advisory_path=Path(config_path).expanduser().resolve())

    default_path = Path(__file__).resolve().parent / "data" / "advisories.json"
    return Config(advisory_path=default_path)

