"""CLI entrypoint."""

from __future__ import annotations

import sys

from scanguard.cli import app, scan_app, should_route_to_scan_app


def main() -> None:
    argv = sys.argv[1:]
    if should_route_to_scan_app(argv):
        scan_app(args=argv, prog_name="scanguard")
        return
    app()

