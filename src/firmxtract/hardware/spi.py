"""
FirmXtract SPI Flash Module.

Handles firmware extraction from SPI NOR/NAND flash chips via flashrom.

Responsibilities:
  - Detect connected SPI programmer (ch341a, ft2232h, buspirate, serprog, etc.)
  - Identify flash chip (safe read-only probe)
  - Dump full flash contents to file
  - Verify dump integrity (read-verify + SHA256)
  - Retry on partial/failed reads

Hardware safety:
  - All flashrom calls are read-only (no --write, --erase flags) in Phase 1.
  - Chip ID is always verified before initiating a full dump.
  - Voltage warnings are logged for unknown programmers.

flashrom docs: https://www.flashrom.org/Flashrom
"""

from __future__ import annotations


import hashlib
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING

from firmxtract.core.session import DetectedInterface, ExtractionResult
from firmxtract.utils.config import SPIConfig
from firmxtract.utils.logger import get_logger

if TYPE_CHECKING:
    from firmxtract.core.session import Session

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Known USB SPI programmers (flashrom -p <programmer>)
# These are probed in order during detection.
# ---------------------------------------------------------------------------

KNOWN_PROGRAMMERS: list[str] = [
    "ch341a_spi",           # CH341A USB adapter (very common, cheap)
    "ft2232_spi",           # FTDI FT2232H (higher quality)
    "buspirate_spi",        # Bus Pirate
    "serprog",              # Generic serial programmer protocol
    "dediprog",             # Dediprog SF100/SF600
    "usbblaster_spi",       # Altera USB-Blaster (repurposed)
]

# flashrom exit codes
_FLASHROM_OK = 0
_FLASHROM_NO_CHIP = 3


# ---------------------------------------------------------------------------
# Programmer probing (called by HAL's SPIDetector)
# ---------------------------------------------------------------------------


def probe_spi_programmer(config: SPIConfig) -> list[DetectedInterface]:
    """
    Probe for connected SPI programmers using flashrom's --flash-name.

    Tries known programmer types and returns the first one that responds
    with a detected chip. This is a read-only, safe operation.

    Args:
        config: SPIConfig with flashrom path and default programmer.

    Returns:
        List of DetectedInterface (typically 0 or 1 for SPI).
    """
    flashrom = shutil.which(config.flashrom_path)
    if flashrom is None:
        log.warning(f"flashrom binary not found: {config.flashrom_path}")
        return []

    # Try default programmer first, then fall through others
    candidates = [config.default_programmer] + [
        p for p in KNOWN_PROGRAMMERS if p != config.default_programmer
    ]

    for programmer in candidates:
        log.debug(f"Probing SPI programmer: {programmer}...")
        chip_id, chip_name = _get_chip_id(flashrom, programmer, config.chip_id_timeout)

        if chip_id:
            log.info(
                f"[green]SPI flash detected[/green] via {programmer}: "
                f"{chip_name or chip_id}"
            )
            return [
                DetectedInterface(
                    interface_type="spi",
                    port_or_device=programmer,
                    metadata={
                        "chip_id": chip_id,
                        "chip_name": chip_name,
                        "flashrom_path": flashrom,
                    },
                )
            ]

    log.info("No SPI flash chip detected via any known programmer.")
    return []


def _get_chip_id(
    flashrom_path: str,
    programmer: str,
    timeout: float,
) -> tuple[str | None, str | None]:
    """
    Run flashrom --flash-name to identify the chip without dumping.

    Args:
        flashrom_path: Absolute path to flashrom binary.
        programmer: Programmer string (e.g. "ch341a_spi").
        timeout: Subprocess timeout in seconds.

    Returns:
        Tuple of (chip_id_string, chip_name_string) or (None, None) on failure.
    """
    cmd = [flashrom_path, "-p", programmer, "--flash-name"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        log.debug(f"  flashrom --flash-name timed out for {programmer}")
        return None, None
    except FileNotFoundError:
        log.debug(f"  flashrom binary not found: {flashrom_path}")
        return None, None

    log.debug(f"  flashrom stdout: {result.stdout.strip()!r}")
    log.debug(f"  flashrom stderr: {result.stderr.strip()!r}")

    if result.returncode == _FLASHROM_OK:
        # Output format: "vendor=\"Winbond\" name=\"W25Q64.V\""
        chip_id = _parse_chip_id(result.stdout)
        chip_name = _parse_chip_name(result.stdout)
        return chip_id or "detected", chip_name

    return None, None


def _parse_chip_id(output: str) -> str | None:
    """Extract chip ID from flashrom output."""
    for line in output.splitlines():
        if "vendor=" in line.lower() or "name=" in line.lower():
            return line.strip()
    return None


def _parse_chip_name(output: str) -> str | None:
    """Extract human-readable chip name from flashrom output."""
    import re
    match = re.search(r'name="([^"]+)"', output)
    return match.group(1) if match else None


# ---------------------------------------------------------------------------
# Full flash dump
# ---------------------------------------------------------------------------


def _run_flashrom_read(
    flashrom_path: str,
    programmer: str,
    output_file: Path,
    timeout: float = 300.0,
) -> tuple[bool, str]:
    """
    Execute flashrom -r (read) to dump full flash contents.

    Args:
        flashrom_path: Path to flashrom binary.
        programmer: Programmer identifier string.
        output_file: Destination file for the firmware dump.
        timeout: Maximum time to allow for the dump operation.

    Returns:
        Tuple of (success: bool, stderr_or_error: str).
    """
    cmd = [
        flashrom_path,
        "-p", programmer,
        "-r", str(output_file),
    ]
    log.debug(f"Running: {shlex.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"flashrom read timed out after {timeout}s"
    except FileNotFoundError as exc:
        return False, str(exc)

    if result.returncode != _FLASHROM_OK:
        stderr = result.stderr.strip()
        log.debug(f"flashrom -r failed (rc={result.returncode}): {stderr}")
        return False, stderr

    return True, result.stderr.strip()


# ---------------------------------------------------------------------------
# SPIHandler — called by Orchestrator
# ---------------------------------------------------------------------------


class SPIHandler:
    """
    Handles SPI flash firmware extraction.

    Uses flashrom as the backend. All operations are read-only in Phase 1.
    Implements retry logic and post-dump checksum verification.
    """

    def __init__(self, session: "Session") -> None:
        self.session = session
        self.config = session.config.spi

    def extract(self, interface: DetectedInterface) -> ExtractionResult:
        """
        Dump SPI flash contents to a file.

        Retries up to config.dump_retries times on failure.
        Verifies the dump with a second read if config.verify_after_dump is True.

        Args:
            interface: A DetectedInterface of type 'spi'.

        Returns:
            ExtractionResult with firmware path and checksum on success.
        """
        programmer = interface.port_or_device
        flashrom_path = interface.metadata.get("flashrom_path") or self.config.flashrom_path
        chip_name = interface.metadata.get("chip_name", "unknown")

        dump_path = self.session.output_dir / "firmware.bin"

        log.info(
            f"Dumping SPI flash ({chip_name}) via {programmer}..."
        )
        log.warning(
            "[yellow]⚡ Hardware connected — ensure correct voltage levels "
            "before proceeding. Read-only operation.[/yellow]"
        )

        last_error = "no attempts made"
        for attempt in range(1, self.config.dump_retries + 1):
            if attempt > 1:
                log.info(f"Retry {attempt}/{self.config.dump_retries}...")
                time.sleep(1.0)

            # Remove stale output from previous attempt
            if dump_path.exists():
                dump_path.unlink()

            success, stderr = _run_flashrom_read(
                flashrom_path=flashrom_path,
                programmer=programmer,
                output_file=dump_path,
                timeout=300.0,
            )

            if success and dump_path.exists() and dump_path.stat().st_size > 0:
                log.info(f"Flash dump complete ({dump_path.stat().st_size:,} bytes).")

                if self.config.verify_after_dump:
                    verified = self._verify_dump(
                        flashrom_path, programmer, dump_path
                    )
                    if not verified:
                        log.warning("Dump verification failed — attempting retry.")
                        last_error = "verify read mismatch"
                        continue

                checksum = self._sha256(dump_path)
                log.info(f"SHA256: {checksum}")
                self.session.add_note(
                    f"SPI dump: {dump_path.stat().st_size:,} bytes, SHA256={checksum}"
                )

                return ExtractionResult(
                    success=True,
                    method="spi",
                    firmware_path=dump_path,
                    size_bytes=dump_path.stat().st_size,
                    checksum_sha256=checksum,
                )

            last_error = stderr or "zero-length output file"
            log.warning(f"Attempt {attempt} failed: {last_error}")

        return ExtractionResult(
            success=False,
            method="spi",
            error_message=f"flashrom read failed after {self.config.dump_retries} attempts. "
                          f"Last error: {last_error}",
        )

    def _verify_dump(
        self,
        flashrom_path: str,
        programmer: str,
        original: Path,
    ) -> bool:
        """
        Verify dump by reading flash a second time and comparing SHA256.

        Args:
            flashrom_path: Path to flashrom.
            programmer: Programmer identifier.
            original: Path of the first dump for comparison.

        Returns:
            True if second read matches first.
        """
        verify_path = self.session.output_dir / "firmware_verify.bin"
        log.debug("Running verification read...")

        success, _ = _run_flashrom_read(flashrom_path, programmer, verify_path)
        if not success or not verify_path.exists():
            log.warning("Verification read failed.")
            return False

        hash1 = self._sha256(original)
        hash2 = self._sha256(verify_path)

        # Remove verify file to save space
        verify_path.unlink(missing_ok=True)

        if hash1 == hash2:
            log.debug("Verification: checksums match ✓")
            return True

        log.warning(f"Verification mismatch!\n  Read 1: {hash1}\n  Read 2: {hash2}")
        return False

    @staticmethod
    def _sha256(path: Path) -> str:
        """Compute SHA256 of a file. Returns hex digest string."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
