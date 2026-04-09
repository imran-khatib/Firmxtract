"""
FirmXtract structured logger.

Provides:
  - Rich-enhanced console logging (human readable)
  - JSON log file (machine readable, for SIEM/automation)
  - Plain text log file (fallback/archive)

All modules should use: from firmxtract.utils.logger import get_logger

JSON log format per line:
  {"ts": "2026-04-06T13:00:00", "level": "INFO", "logger": "firmxtract.hardware.spi",
   "msg": "Chip detected: W25Q64.V", "session_id": "20260406_130000"}
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

console = Console(stderr=True)

_LOG_FORMAT = "%(message)s"
_DATE_FORMAT = "%H:%M:%S"
_initialized = False

# Session ID injected here so all log lines carry it
_current_session_id: str = ""


def set_session_id(session_id: str) -> None:
    """Call this after session creation so JSON logs carry the session ID."""
    global _current_session_id
    _current_session_id = session_id


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------


class JsonLogFormatter(logging.Formatter):
    """
    Formats log records as newline-delimited JSON.

    Each line is a valid JSON object:
        {"ts": "...", "level": "INFO", "logger": "...", "msg": "...", "session": "..."}

    Strip Rich markup before writing to JSON (keeps logs clean).
    """

    # Regex to strip Rich markup tags like [bold], [green], [/green] etc.
    import re
    _RICH_TAG = re.compile(r"\[/?[a-zA-Z0-9_ ]+\]")

    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()
        # Strip Rich markup
        msg = self._RICH_TAG.sub("", msg)

        entry = {
            "ts":      datetime.fromtimestamp(record.created).isoformat(timespec="seconds"),
            "level":   record.levelname,
            "logger":  record.name,
            "msg":     msg,
            "session": _current_session_id,
        }

        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(entry, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------


def setup_logging(
    level: int = logging.INFO,
    log_file: Path | None = None,
    verbose: bool = False,
    json_log_file: Path | None = None,
) -> None:
    """
    Initialize the root logger for FirmXtract.

    Handlers:
      1. Console (Rich — human readable, colorized)
      2. Plain text log file (optional)
      3. JSON log file (optional — machine readable)

    Args:
        level:         Logging level for console. verbose overrides to DEBUG.
        log_file:      Path for plain text log file.
        verbose:       Force DEBUG level.
        json_log_file: Path for JSON structured log file.
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

    # Plain text file handler
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        txt_handler = logging.FileHandler(log_file, encoding="utf-8")
        txt_handler.setFormatter(logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        txt_handler.setLevel(logging.DEBUG)
        handlers.append(txt_handler)

    # JSON file handler
    if json_log_file is not None:
        json_log_file.parent.mkdir(parents=True, exist_ok=True)
        json_handler = logging.FileHandler(json_log_file, encoding="utf-8")
        json_handler.setFormatter(JsonLogFormatter())
        json_handler.setLevel(logging.DEBUG)
        handlers.append(json_handler)

    logging.basicConfig(
        level=level,
        format=_LOG_FORMAT,
        datefmt=_DATE_FORMAT,
        handlers=handlers,
    )

    _initialized = True


def setup_session_logging(session_output_dir: Path, level: int = logging.INFO) -> None:
    """
    Configure logging to write to a session directory.

    Creates two log files inside session_output_dir:
      - firmxtract.log       (human-readable plain text)
      - firmxtract.log.json  (machine-readable JSON, one entry per line)

    Call this right after create_session() to capture all session logs.

    Args:
        session_output_dir: The session output directory path.
        level:              Console log level.
    """
    global _initialized
    _initialized = False  # allow re-init with session paths

    setup_logging(
        level=level,
        log_file=session_output_dir / "firmxtract.log",
        json_log_file=session_output_dir / "firmxtract.log.json",
    )


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger under the firmxtract namespace.

    Args:
        name: Module name — pass __name__ from the calling module.

    Returns:
        Logger scoped to firmxtract.<name>.

    Example:
        log = get_logger(__name__)
        log.info("UART detected")
    """
    clean = name.removeprefix("firmxtract.").removeprefix("src.")
    return logging.getLogger(f"firmxtract.{clean}")
