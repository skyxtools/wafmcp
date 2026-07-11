"""Command-line entry point for the MCP server and maintenance commands."""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence

from . import __version__


UPDATE_URL = (
    "https://github.com/skyxtools/wafmcp/archive/refs/heads/main.zip"
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wafmcp",
        description="Run or update the wafmcp MCP server.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("serve", help="run the MCP server over stdio (default)")
    commands.add_parser(
        "update",
        help="download and reinstall the latest main branch without a git clone",
    )
    return parser


def update() -> int:
    """Reinstall the package from the canonical GitHub source archive."""
    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--upgrade",
        "--force-reinstall",
        UPDATE_URL,
    ]
    print(f"Updating wafmcp from {UPDATE_URL}", file=sys.stderr)
    try:
        result = subprocess.run(command, check=False)
    except OSError as exc:
        print(f"Unable to start pip: {exc}", file=sys.stderr)
        return 1

    if result.returncode == 0:
        print(
            "Update complete. Restart your MCP client to load the new version.",
            file=sys.stderr,
        )
    else:
        print(f"Update failed (pip exit code {result.returncode}).", file=sys.stderr)
    return result.returncode


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "update":
        return update()

    # Keep the historical behavior: `wafmcp`, `wafmcp serve`, and
    # `python -m wafmcp` all start the stdio server.
    from .server import main as server_main

    server_main()
    return 0

