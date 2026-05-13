"""CLI entrypoint."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from scanguard.cli import app, run_scan

FORWARDED_SUBCOMMANDS = {"report", "projects", "findings", "init", "autopilot"}
COMPLETION_FLAGS = {"--install-completion", "--show-completion"}
DEFAULT_OBJECTIVE = "Run a safe reconnaissance workflow, collect findings, and generate reports."
DEFAULT_REPORT_FORMATS = ["markdown", "html", "json"]


def build_scan_parser() -> argparse.ArgumentParser:
    """Build the lightweight direct scan parser."""
    parser = argparse.ArgumentParser(
        prog="scanguard",
        description="AI-assisted reconnaissance for authorized testing on Kali Linux.",
        epilog="Other commands: scanguard report --project PROJECT_ID --format markdown|html|json | scanguard projects | scanguard findings --project PROJECT_ID",
    )
    parser.add_argument("target_value", nargs="?", help="Authorized target to scan.")
    parser.add_argument("--target", dest="target_option", help="Authorized target to scan.")
    parser.add_argument(
        "--scope",
        type=Path,
        default=None,
        help="Path to the in-scope targets file. Defaults to ./scope.txt if present.",
    )
    parser.add_argument(
        "--objective",
        default=DEFAULT_OBJECTIVE,
        help="Operator intent provided to the AI planner.",
    )
    parser.add_argument(
        "--auto-safe",
        dest="auto_safe",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Allow active_safe tools to run automatically.",
    )
    parser.add_argument(
        "--allow-careful",
        action="store_true",
        help="Explicitly allow active_careful tools in the autonomous workflow.",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=8,
        help="Maximum number of AI-planned steps to run.",
    )
    parser.add_argument(
        "--report-format",
        action="append",
        default=None,
        help="Report format to generate at the end. Repeat to select multiple formats.",
    )
    return parser


def should_forward_to_typer(argv: Sequence[str]) -> bool:
    """Return True when the request should go to the Typer subcommand app."""
    if not argv:
        return False
    if argv[0] in FORWARDED_SUBCOMMANDS:
        return True
    return any(flag in argv for flag in COMPLETION_FLAGS)


def run_direct_scan_cli(argv: Sequence[str]) -> None:
    """Parse and run the single-command scan workflow."""
    parser = build_scan_parser()
    namespace = parser.parse_args(list(argv))
    target = namespace.target_option or namespace.target_value
    if not target:
        parser.error("the following arguments are required: --target")
    if namespace.max_steps < 1 or namespace.max_steps > 20:
        parser.error("--max-steps must be between 1 and 20")

    report_formats = namespace.report_format or list(DEFAULT_REPORT_FORMATS)
    run_scan(
        target=target,
        scope=namespace.scope,
        objective=namespace.objective,
        auto_safe=namespace.auto_safe,
        allow_careful=namespace.allow_careful,
        max_steps=namespace.max_steps,
        report_format=report_formats,
    )


def main() -> None:
    argv = sys.argv[1:]
    if should_forward_to_typer(argv):
        app()
        return
    if not argv:
        build_scan_parser().print_help()
        return
    run_direct_scan_cli(argv)
