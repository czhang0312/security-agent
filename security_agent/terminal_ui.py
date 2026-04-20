from __future__ import annotations

from typing import TextIO

RESET = "\033[0m"
STYLES = {
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
}


def resolve_color_enabled(color_mode: str, stream: TextIO | None = None) -> bool:
    normalized = color_mode.strip().lower()
    if normalized == "always":
        return True
    if normalized == "never":
        return False
    # For auto mode, enable color only if outputing to terminal (not being piped to a file or another process)
    return bool(stream is not None and hasattr(stream, "isatty") and stream.isatty())


def style(text: str, *names: str, enabled: bool) -> str:
    if not enabled or not names:
        return text
    prefix = "".join(STYLES[name] for name in names if name in STYLES)
    return f"{prefix}{text}{RESET}" if prefix else text


def priority_color(priority: str) -> tuple[str, ...]:
    return {
        "high": ("red", "bold"),
        "medium": ("yellow", "bold"),
        "low": ("blue", "bold"),
    }.get(priority.lower(), ("bold",))


def reachability_color(status: str) -> tuple[str, ...]:
    return {
        "reachable": ("red", "bold"),
        "possibly_reachable": ("yellow", "bold"),
        "not_observed": ("green",),
        "not_investigated": ("dim",),
    }.get(status.lower(), ("dim",))
