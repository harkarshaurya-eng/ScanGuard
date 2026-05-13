"""Shared tool helper functions."""

from __future__ import annotations

import os
import shutil
import subprocess
from functools import lru_cache
from urllib.parse import urlparse

from scanguard.mcp.schemas import ToolExecutionInput


def as_url(target: str) -> str:
    """Ensure a target is represented as an HTTP URL."""
    parsed = urlparse(target)
    if parsed.scheme and parsed.netloc:
        return target
    if parsed.scheme and parsed.path and not parsed.netloc:
        return f"https://{parsed.path}"
    return f"https://{target}"


def no_extra_args(input_data: ToolExecutionInput) -> None:
    """Reject arbitrary extra arguments for fixed wrappers."""
    if input_data.extra_args:
        raise ValueError("This tool wrapper does not accept arbitrary extra arguments.")


def _probe_binary(binary: str, help_args: tuple[str, ...]) -> str:
    """Return combined help output for a binary probe."""
    completed = subprocess.run(
        [binary, *help_args],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        shell=False,
    )
    return f"{completed.stdout}\n{completed.stderr}".strip()


def _looks_like_projectdiscovery_httpx(binary: str) -> bool:
    """Detect the ProjectDiscovery httpx CLI instead of Python's httpx helper."""
    help_output = _probe_binary(binary, ("-h",)).lower()
    required_markers = ("-json", "-tech-detect", "-status-code")
    return all(marker in help_output for marker in required_markers)


@lru_cache(maxsize=16)
def resolve_binary_candidate(
    *candidates: str,
    env_var: str | None = None,
    validator_name: str | None = None,
) -> str:
    """Resolve a binary candidate, optionally validating the chosen executable."""
    validator_map = {
        "projectdiscovery_httpx": _looks_like_projectdiscovery_httpx,
    }
    validator = validator_map.get(validator_name)

    ordered_candidates: list[str] = []
    if env_var:
        override = os.environ.get(env_var, "").strip()
        if override:
            ordered_candidates.append(override)
    ordered_candidates.extend(candidates)

    rejected: list[str] = []
    for candidate in ordered_candidates:
        resolved = shutil.which(candidate)
        if not resolved:
            continue
        if validator and not validator(resolved):
            rejected.append(resolved)
            continue
        return resolved

    if rejected and validator_name == "projectdiscovery_httpx":
        rejected_values = ", ".join(rejected)
        raise FileNotFoundError(
            "Found httpx on PATH, but it is not the ProjectDiscovery scanner CLI. "
            f"Rejected: {rejected_values}. Install ProjectDiscovery httpx or set "
            "SCANGUARD_HTTPX_BINARY to the correct executable."
        )

    candidate_list = ", ".join(candidates)
    raise FileNotFoundError(f"Required binary not found in PATH: {candidate_list}")


