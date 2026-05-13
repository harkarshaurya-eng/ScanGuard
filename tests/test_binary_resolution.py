from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from scanguard.mcp.schemas import ToolExecutionInput
from scanguard.tools.base import resolve_binary_candidate
from scanguard.tools.web_tools import _httpx_command


def test_httpx_resolution_rejects_non_projectdiscovery_binary(monkeypatch: Any) -> None:
    resolve_binary_candidate.cache_clear()
    monkeypatch.delenv("SCANGUARD_HTTPX_BINARY", raising=False)
    monkeypatch.setattr("shutil.which", lambda binary: "/tmp/httpx" if binary == "httpx" else None)

    class Completed:
        stdout = "Usage: httpx [OPTIONS] URL"
        stderr = ""

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: Completed())

    with pytest.raises(FileNotFoundError, match="ProjectDiscovery"):
        resolve_binary_candidate("httpx", validator_name="projectdiscovery_httpx")


def test_httpx_command_uses_override_binary(monkeypatch: Any, tmp_path: Path) -> None:
    resolve_binary_candidate.cache_clear()
    override_path = tmp_path / "httpx-pd"
    monkeypatch.setenv("SCANGUARD_HTTPX_BINARY", str(override_path))
    monkeypatch.setattr("shutil.which", lambda binary: str(override_path))

    class Completed:
        stdout = "httpx -json -tech-detect -status-code"
        stderr = ""

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: Completed())

    command = _httpx_command(
        ToolExecutionInput(
            target="example.com",
            project_id="project-1",
        )
    )

    assert command[0] == str(override_path)
    assert command[1:] == [
        "-u",
        "https://example.com",
        "-json",
        "-title",
        "-tech-detect",
        "-web-server",
        "-status-code",
        "-follow-host-redirects",
    ]
