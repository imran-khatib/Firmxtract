"""
FirmXtract structured logger.

Provides a Rich-enhanced logger with file + console handlers.
All modules should use: from firmxtract.utils.logger import get_logger
"""

from __future__ import annotations


import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

# Module-level console (used by logger and also available for direct use)
console = Console(stderr=True)

_LOG_FORMAT = "%(message)s"
_DATE_FORMAT = "%H:%M:%S"

_initialized = False


def setup_logging(
    level: int = logging.INFO,
    log_file: Path | None = None,
    verbose: bool = False,
) -> None:
    """
    Initialize the root logger for FirmXtract.

    Should be called once at startup by the CLI entry point.
    Subsequent calls are safe (idempotent after first init).

    Args:
        level: Logging level (e.g. logging.DEBUG). verbose=True forces DEBUG.
        log_file: Optional path to write log file (in addition to console).
        verbose: If True, overrides level to DEBUG.
    """
    global _initialized
    if _initialized:
        return

    if verbose:
        level = logging.DEBUG

    handlers: list[logging.Handler] = [
        RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
            tracebacks_show_locals=False,
        )
    ]

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        file_handler.setLevel(logging.DEBUG)  # Always verbose to file
        handlers.append(file_handler)

    logging.basicConfig(
        level=level,
        format=_LOG_FORMAT,
        datefmt=_DATE_FORMAT,
        handlers=handlers,
    )

    _initialized = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger under the 'firmxtract' namespace.

    Args:
        name: Module name, typically __name__ of the calling module.

    Returns:
        A Logger instance scoped to firmxtract.<name>.

    Example:
        log = get_logger(__name__)
        log.info("UART detected on /dev/ttyUSB0")
    """
    # Normalize: strip leading "firmxtract." if already present
    clean = name.removeprefix("firmxtract.").removeprefix("src.")
    return logging.getLogger(f"firmxtract.{clean}")
