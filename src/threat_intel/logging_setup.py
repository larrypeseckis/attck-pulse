"""Logging configuration.

Goal: every script gets consistent, grep-friendly logs to both stdout and disk.
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler

from threat_intel.config import settings

_CONFIGURED = False


def configure_logging() -> None:
    """Configure root logger. Idempotent.

    Call once at process startup. Subsequent calls are no-ops.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return

    settings.log_dir.mkdir(parents=True, exist_ok=True)

    fmt = (
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    formatter = logging.Formatter(fmt, datefmt="%Y-%m-%dT%H:%M:%S%z")

    root = logging.getLogger()
    root.setLevel(settings.log_level.upper())

    # Clear any default handlers (avoids dupes in notebooks)
    root.handlers.clear()

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    root.addHandler(stdout_handler)

    file_handler = RotatingFileHandler(
        settings.log_dir / "threat_intel.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    # Quiet noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Get a configured logger. Calls configure_logging() if needed."""
    if not _CONFIGURED:
        configure_logging()
    return logging.getLogger(name)
