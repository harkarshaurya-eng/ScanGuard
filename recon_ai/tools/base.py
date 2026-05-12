"""Shared tool helper functions."""

from __future__ import annotations

from urllib.parse import urlparse

from recon_ai.mcp.schemas import ToolExecutionInput


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

