"""Secure subprocess helpers."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from recon_ai.constants import BANNED_GENERIC_FLAGS, BANNED_NMAP_FLAGS
from recon_ai.utils.time import utc_iso


@dataclass(slots=True)
class CommandResult:
    args: list[str]
    exit_code: int
    stdout: str
    stderr: str
    started_at: str
    finished_at: str


def ensure_binary(binary: str) -> str:
    resolved = shutil.which(binary)
    if not resolved:
        raise FileNotFoundError(f"Required binary not found in PATH: {binary}")
    return resolved


def validate_command_args(args: list[str]) -> None:
    if not args:
        raise ValueError("Command argument list cannot be empty.")
    for item in args:
        if "\x00" in item:
            raise ValueError("Null bytes are not allowed in command arguments.")
        if item in BANNED_GENERIC_FLAGS:
            raise ValueError(f"Blocked unsafe flag: {item}")
    if Path(args[0]).name == "nmap":
        for item in args[1:]:
            if item in BANNED_NMAP_FLAGS:
                raise ValueError(f"Blocked nmap flag: {item}")
            if item.startswith("--script") and "safe" not in item:
                raise ValueError("Nmap NSE scripts are blocked unless explicitly whitelisted.")


def safe_run_command(
    args: list[str],
    timeout: int,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> CommandResult:
    """Run a command safely without a shell."""
    validate_command_args(args)
    binary = ensure_binary(args[0])
    prepared_args = [binary, *args[1:]]
    started_at = utc_iso()
    completed = subprocess.run(
        prepared_args,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(cwd) if cwd else None,
        env=dict(os.environ | dict(env or {})),
        check=False,
        shell=False,
    )
    return CommandResult(
        args=prepared_args,
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        started_at=started_at,
        finished_at=utc_iso(),
    )

