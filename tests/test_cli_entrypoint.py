from pathlib import Path
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from scanguard.cli import app, resolve_scope_file

runner = CliRunner()


def test_root_command_allows_missing_scope_option(monkeypatch: Any, tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("example.com\n", encoding="utf-8")
    captured: dict[str, Any] = {}

    def fake_run_autopilot(
        *,
        target: str,
        scope: Path | None,
        objective: str,
        auto_safe: bool,
        allow_careful: bool,
        max_steps: int,
        report_format: list[str],
    ) -> None:
        captured.update(
            {
                "target": target,
                "scope": scope,
                "objective": objective,
                "auto_safe": auto_safe,
                "allow_careful": allow_careful,
                "max_steps": max_steps,
                "report_format": report_format,
            }
        )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("scanguard.cli._run_autopilot", fake_run_autopilot)

    result = runner.invoke(app, ["--target", "example.com"])

    assert result.exit_code == 0
    assert captured["target"] == "example.com"
    assert captured["scope"] is None


def test_resolve_scope_file_uses_default_file(monkeypatch: Any, tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("example.com\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)

    assert resolve_scope_file(None) == tmp_path / "scope.txt"


def test_resolve_scope_file_requires_path_if_default_is_missing(monkeypatch: Any, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)

    with pytest.raises(typer.BadParameter, match="No scope file provided"):
        resolve_scope_file(None)
