from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from security_agent.config import load_config
from security_agent.reporting import render_json, render_terminal
from security_agent.repo import UnsupportedRepoError
from security_agent.scanner import run_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="security-agent")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a Rails repository for vulnerable gems.")
    scan_parser.add_argument("repo_path", nargs="?", default=".")
    scan_parser.add_argument("--json", action="store_true", dest="json_output")
    scan_parser.add_argument("--output", type=Path)
    scan_parser.add_argument(
        "--investigator",
        choices=("mock", "gemini", "openai"),
        help="Override the investigator provider for this run.",
    )
    scan_parser.add_argument(
        "--config",
        dest="config_path",
        help="Path to a local advisory fixture JSON file.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.error("Unsupported command")

    config = load_config(args.config_path, investigator_provider=args.investigator)

    try:
        result = run_scan(repo_path=args.repo_path, config=config)
    except UnsupportedRepoError as exc:
        parser.exit(status=2, message=f"error: {exc}\n")

    rendered = render_json(result) if args.json_output else render_terminal(result)

    if args.output:
        args.output.write_text(rendered + ("\n" if not rendered.endswith("\n") else ""))
    else:
        print(rendered)

    return 1 if result.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
