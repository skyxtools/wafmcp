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
        description="Run, update, or prepare the wafmcp MCP server.",
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
        help="upgrade to the latest main branch without a git clone",
    )
    install_browser = commands.add_parser(
        "install-browser",
        help="install the Chromium runtime used by browser-based tools",
    )
    install_browser.add_argument(
        "--with-deps",
        action="store_true",
        help="also ask Playwright to install OS packages; may require sudo/root",
    )
    return parser


def install_browser(*, with_deps: bool = False) -> int:
    """Install the Chromium runtime using the current wafmcp environment."""
    command = [
        sys.executable,
        "-m",
        "playwright",
        "install",
    ]
    if with_deps:
        command.append("--with-deps")
    command.append("chromium")

    print("Installing Chromium browser runtime for wafmcp...", file=sys.stderr)
    try:
        result = subprocess.run(command, check=False)
    except OSError as exc:
        print(f"Unable to start Playwright installer: {exc}", file=sys.stderr)
        return 1

    if result.returncode == 0:
        print("Browser runtime ready.", file=sys.stderr)
    else:
        print(
            f"Browser runtime install failed (playwright exit code {result.returncode}).",
            file=sys.stderr,
        )
    return result.returncode


def update() -> int:
    """Upgrade the package from the canonical GitHub source archive."""
    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--upgrade",
        "--upgrade-strategy",
        "only-if-needed",
        UPDATE_URL,
    ]
    print(f"Updating wafmcp from {UPDATE_URL}", file=sys.stderr)
    try:
        result = subprocess.run(command, check=False)
    except OSError as exc:
        print(f"Unable to start pip: {exc}", file=sys.stderr)
        return 1

    if result.returncode != 0:
        print(f"Update failed (pip exit code {result.returncode}).", file=sys.stderr)
        return result.returncode

    browser_code = install_browser()
    if browser_code == 0:
        print(
            "Update complete. Restart your MCP client to load the new version.",
            file=sys.stderr,
        )
    else:
        print(
            "Package update completed, but Chromium setup failed. "
            "Run `wafmcp install-browser` after fixing the Playwright error above.",
            file=sys.stderr,
        )
    return browser_code


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "update":
        return update()
    if args.command == "install-browser":
        return install_browser(with_deps=args.with_deps)

    # Keep the historical behavior: `wafmcp`, `wafmcp serve`, and
    # `python -m wafmcp` all start the stdio server.
    from .server import main as server_main

    server_main()
    return 0

