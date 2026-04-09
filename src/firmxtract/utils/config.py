"""
FirmXtract configuration loader.

Loads settings from (in priority order):
  1. Environment variables (FIRMXTRACT_*)
  2. User config file (~/.firmxtract/config.toml)
  3. Built-in defaults

Usage:
    from firmxtract.utils.config import get_config
    cfg = get_config()
    print(cfg.uart.default_baudrate)
"""

from __future__ import annotations


import os
import sys

try:
    import tomllib  # stdlib in Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # pip install tomli  (Python 3.10 fallback)
    except ImportError:
        tomllib = None  # type: ignore[assignment]
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from firmxtract.utils.logger import get_logger

log = get_logger(__name__)

# Default config file location
DEFAULT_CONFIG_DIR = Path.home() / ".firmxtract"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.toml"


# ---------------------------------------------------------------------------
# Config dataclasses
# ---------------------------------------------------------------------------


@dataclass
class UARTConfig:
    """UART hardware interface settings."""

    baudrates: list[int] = field(
        default_factory=lambda: [9600, 38400, 57600, 115200, 230400, 921600]
    )
    default_baudrate: int = 115200
    read_timeout: float = 2.0       # seconds per read() call
    detection_timeout: float = 5.0  # seconds for initial prompt detection
    bytesize: int = 8
    parity: str = "N"
    stopbits: int = 1
    detection_sample_bytes: int = 256   # bytes to sample during baud sweep

    # Shell extraction settings
    shell_prompt_timeout: float = 30.0  # seconds to wait for shell after boot
    cmd_response_timeout: float = 10.0  # seconds to wait for a command reply
    dd_chunk_lines: int = 0             # 0 = single dd call; >0 = chunked (Phase 2)
    base64_line_bytes: int = 57         # bytes per base64 line (57 → 76 chars)
    extraction_timeout: float = 300.0   # max seconds for full firmware transfer


@dataclass
class SPIConfig:
    """SPI flash / flashrom settings."""

    flashrom_path: str = "flashrom"
    default_programmer: str = "ch341a_spi"
    verify_after_dump: bool = True
    dump_retries: int = 3
    chip_id_timeout: float = 30.0


@dataclass
class BinwalkConfig:
    """binwalk analysis settings."""

    binwalk_path: str = "binwalk"
    extract: bool = True
    matryoshka: bool = True  # recursive extraction
    signature_scan: bool = True
    entropy_scan: bool = False  # expensive — opt-in


@dataclass
class OutputConfig:
    """Output and session settings."""

    base_dir: Path = field(default_factory=lambda: Path.home() / ".firmxtract" / "sessions")
    permissions: int = 0o700


@dataclass
class FirmXtractConfig:
    """Root configuration object."""

    uart: UARTConfig = field(default_factory=UARTConfig)
    spi: SPIConfig = field(default_factory=SPIConfig)
    binwalk: BinwalkConfig = field(default_factory=BinwalkConfig)
    output: OutputConfig = field(default_factory=OutputConfig)


# ---------------------------------------------------------------------------
# TOML loader
# ---------------------------------------------------------------------------


def _load_toml(path: Path) -> dict[str, Any]:
    """Load a TOML file, returning empty dict if not found or invalid."""
    if not path.exists():
        return {}
    if tomllib is None:
        log.debug("tomllib/tomli not available — skipping config file (using defaults).")
        return {}
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except Exception as exc:
        log.warning(f"Could not parse config file {path}: {exc}. Using defaults.")
        return {}


def _apply_env_overrides(cfg: FirmXtractConfig) -> None:
    """
    Apply environment variable overrides.

    Supported variables (all optional):
        FIRMXTRACT_OUTPUT_DIR     → output.base_dir
        FIRMXTRACT_FLASHROM_PATH  → spi.flashrom_path
        FIRMXTRACT_BINWALK_PATH   → binwalk.binwalk_path
        FIRMXTRACT_UART_BAUD      → uart.default_baudrate
        FIRMXTRACT_SPI_PROGRAMMER → spi.default_programmer
    """
    if val := os.environ.get("FIRMXTRACT_OUTPUT_DIR"):
        cfg.output.base_dir = Path(val)

    if val := os.environ.get("FIRMXTRACT_FLASHROM_PATH"):
        cfg.spi.flashrom_path = val

    if val := os.environ.get("FIRMXTRACT_BINWALK_PATH"):
        cfg.binwalk.binwalk_path = val

    if val := os.environ.get("FIRMXTRACT_UART_BAUD"):
        try:
            cfg.uart.default_baudrate = int(val)
        except ValueError:
            log.warning(f"Invalid FIRMXTRACT_UART_BAUD value: {val!r}. Ignored.")

    if val := os.environ.get("FIRMXTRACT_SPI_PROGRAMMER"):
        cfg.spi.default_programmer = val


def _apply_toml_section(cfg: FirmXtractConfig, data: dict[str, Any]) -> None:
    """Overlay TOML values onto the config dataclass (best-effort)."""
    for section_name, section_data in data.items():
        if not isinstance(section_data, dict):
            continue
        sub = getattr(cfg, section_name, None)
        if sub is None:
            log.debug(f"Unknown config section [{section_name}] — skipped.")
            continue
        for key, value in section_data.items():
            if hasattr(sub, key):
                # Path coercion for known Path fields
                if key in ("base_dir",):
                    value = Path(value)
                setattr(sub, key, value)
            else:
                log.debug(f"Unknown config key [{section_name}].{key} — skipped.")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_cached_config: FirmXtractConfig | None = None


def get_config(config_file: Path | None = None, *, reload: bool = False) -> FirmXtractConfig:
    """
    Return the global FirmXtractConfig instance.

    Loads once and caches. Pass reload=True to force re-read.

    Args:
        config_file: Override path to TOML config. Defaults to ~/.firmxtract/config.toml.
        reload: Force reload from disk (bypass cache).

    Returns:
        FirmXtractConfig populated from defaults → TOML → env vars.
    """
    global _cached_config
    if _cached_config is not None and not reload:
        return _cached_config

    cfg = FirmXtractConfig()

    path = config_file or DEFAULT_CONFIG_FILE
    toml_data = _load_toml(path)
    if toml_data:
        log.debug(f"Loaded config from {path}")
        _apply_toml_section(cfg, toml_data)

    _apply_env_overrides(cfg)

    _cached_config = cfg
    return cfg
