"""Logging setup."""

from __future__ import annotations

import sys
from pathlib import Path

from loguru import logger

from scanguard.constants import DEFAULT_LOG_LEVEL, LOG_DIR


def configure_logging(level: str = DEFAULT_LOG_LEVEL, log_file: Path | None = None) -> None:
    """Configure console and file logging."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    sink_path = log_file or (LOG_DIR / "scanguard.log")
    logger.remove()
    console_level = "DEBUG" if level.upper() == "DEBUG" else "ERROR"
    logger.add(sys.stderr, level=console_level, colorize=True)
    logger.add(
        sink_path,
        level=level,
        rotation="10 MB",
        retention=5,
        backtrace=False,
        diagnose=False,
    )


