from __future__ import annotations

import subprocess
import sys

import pytest

from wafmcp import __version__, cli


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])

    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"wafmcp {__version__}"


def test_update_uses_only_if_needed_upgrade(monkeypatch, capsys) -> None:
    seen: list[dict[str, object]] = []

    def fake_run(command, check):
        seen.append({"command": command, "check": check})
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    assert cli.main(["update"]) == 0
    assert seen == [
        {
            "command": [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--upgrade",
                "--upgrade-strategy",
                "only-if-needed",
                cli.UPDATE_URL,
            ],
            "check": False,
        },
        {
            "command": [
                sys.executable,
                "-m",
                "playwright",
                "install",
                "chromium",
            ],
            "check": False,
        },
    ]
    stderr = capsys.readouterr().err
    assert "Browser runtime ready" in stderr
    assert "Restart your MCP client" in stderr


def test_update_propagates_pip_failure(monkeypatch, capsys) -> None:
    seen: list[list[str]] = []

    def fake_run(command, check):
        seen.append(command)
        return subprocess.CompletedProcess(command, 7)

    monkeypatch.setattr(
        cli.subprocess,
        "run",
        fake_run,
    )

    assert cli.main(["update"]) == 7
    assert len(seen) == 1
    assert "pip exit code 7" in capsys.readouterr().err


def test_install_browser_uses_current_environment(monkeypatch, capsys) -> None:
    seen: dict[str, object] = {}

    def fake_run(command, check):
        seen["command"] = command
        seen["check"] = check
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    assert cli.main(["install-browser"]) == 0
    assert seen == {
        "command": [
            sys.executable,
            "-m",
            "playwright",
            "install",
            "chromium",
        ],
        "check": False,
    }
    assert "Browser runtime ready" in capsys.readouterr().err


def test_install_browser_with_deps(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def fake_run(command, check):
        seen["command"] = command
        seen["check"] = check
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    assert cli.main(["install-browser", "--with-deps"]) == 0
    assert seen["command"] == [
        sys.executable,
        "-m",
        "playwright",
        "install",
        "--with-deps",
        "chromium",
    ]


def test_default_and_serve_start_server(monkeypatch) -> None:
    calls: list[bool] = []
    monkeypatch.setattr("wafmcp.server.main", lambda: calls.append(True))

    assert cli.main([]) == 0
    assert cli.main(["serve"]) == 0
    assert calls == [True, True]
