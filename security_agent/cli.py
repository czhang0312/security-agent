from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from security_agent.advisories import (
    AdvisoryDataUnavailableError,
    GITHUB_ADVISORY_ARCHIVE_URL,
    update_advisory_cache,
)
from security_agent.config import load_config
from security_agent.investigation import make_stderr_progress_reporter
from security_agent.reporting import render_json, render_terminal
from security_agent.repo import UnsupportedRepoError
from security_agent.scanner import run_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="security-agent")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a Rails repository for vulnerable gems. Run `security-agent advisories update` first.",
    )
    scan_parser.add_argument("repo_path", nargs="?", default=".")
    scan_parser.add_argument("--json", action="store_true", dest="json_output")
    scan_parser.add_argument("--output", type=Path)
    scan_parser.add_argument(
        "--investigator",
        choices=("mock", "gemini", "openai"),
        help="Override the investigator provider for this run. `openai` is the recommended real provider for the MVP.",
    )
    scan_parser.add_argument(
        "--config",
        dest="config_path",
        help="Path to an advisory cache JSON file. Defaults to the local cache created by `security-agent advisories update`.",
    )
    scan_parser.add_argument(
        "--max-investigations",
        type=int,
        help="Override how many matched advisories are investigated during this scan.",
    )

    advisories_parser = subparsers.add_parser(
        "advisories",
        help="Manage the local advisory data cache.",
    )
    advisories_subparsers = advisories_parser.add_subparsers(dest="advisories_command", required=True)
    update_parser = advisories_subparsers.add_parser(
        "update",
        help="Download advisory data and rebuild the local advisory cache used by `scan`.",
    )
    update_parser.add_argument(
        "--output",
        type=Path,
        help="Override the destination advisory cache path.",
    )
    update_parser.add_argument(
        "--source-url",
        help="Override the advisory archive URL used for updates.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    progress_reporter = make_stderr_progress_reporter()

    if args.command == "scan":
        config = load_config(args.config_path, investigator_provider=args.investigator)
        if args.max_investigations is not None:
            config.max_investigations = max(0, args.max_investigations)

        try:
            result = run_scan(repo_path=args.repo_path, config=config, progress_reporter=progress_reporter)
        except UnsupportedRepoError as exc:
            parser.exit(status=2, message=f"error: {exc}\n")
        except AdvisoryDataUnavailableError as exc:
            parser.exit(status=2, message=f"error: {exc}\n")

        rendered = render_json(result) if args.json_output else render_terminal(result)

        if args.output:
            args.output.write_text(rendered + ("\n" if not rendered.endswith("\n") else ""))
        else:
            print(rendered)

        return 1 if result.findings else 0

    if args.command == "advisories" and args.advisories_command == "update":
        config = load_config()
        destination = args.output or config.advisory_path
        try:
            advisory_count = update_advisory_cache(
                destination=destination,
                source_url=args.source_url or GITHUB_ADVISORY_ARCHIVE_URL,
                progress_reporter=progress_reporter,
            )
        except AdvisoryDataUnavailableError as exc:
            parser.exit(status=2, message=f"error: {exc}\n")
        print(f"Updated advisory cache with {advisory_count} advisories at {destination}")
        return 0

    parser.error("Unsupported command")


if __name__ == "__main__":
    raise SystemExit(main())
