"""
FirmXtract binwalk integration.

Wraps binwalk as a subprocess, parses its output into structured results,
and manages the extraction directory lifecycle.

binwalk docs: https://github.com/ReFirmLabs/binwalk
"""

from __future__ import annotations


import json
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any

from firmxtract.core.session import AnalysisResult
from firmxtract.utils.logger import get_logger

if TYPE_CHECKING:
    from firmxtract.core.session import Session

log = get_logger(__name__)


class BinwalkWrapper:
    """
    Wraps binwalk for firmware signature scanning and extraction.

    Phase 1 capabilities:
      - Signature scan (-B)
      - Recursive extraction (-eM)
      - JSON output parsing (--log + -J)

    Phase 2 additions:
      - Entropy analysis (-E)
      - Diff mode for comparing firmware versions
    """

    def __init__(self, session: "Session") -> None:
        self.session = session
        self.config = session.config.binwalk

    def analyze(self, firmware_path: Path) -> AnalysisResult:
        """
        Run binwalk signature scan and optional extraction on firmware.

        Args:
            firmware_path: Path to the firmware binary (or capture log).

        Returns:
            AnalysisResult with parsed signatures and extraction directory.
        """
        binwalk = shutil.which(self.config.binwalk_path)
        if binwalk is None:
            msg = (
                f"binwalk not found at '{self.config.binwalk_path}'. "
                "Install with: pip install binwalk  or  apt install binwalk"
            )
            log.warning(msg)
            return AnalysisResult(
                tool="binwalk",
                success=False,
                error_message=msg,
            )

        if not firmware_path.exists():
            msg = f"Firmware file not found: {firmware_path}"
            log.error(msg)
            return AnalysisResult(tool="binwalk", success=False, error_message=msg)

        log.info(f"Running binwalk on {firmware_path.name} ({firmware_path.stat().st_size:,} bytes)...")

        # Step 1: Signature scan with JSON output
        findings = self._run_signature_scan(binwalk, firmware_path)

        # Step 2: Extraction (if enabled and signatures found)
        extracted_dir: Path | None = None
        if self.config.extract and findings:
            extracted_dir = self._run_extraction(binwalk, firmware_path)

        return AnalysisResult(
            tool="binwalk",
            success=True,
            findings=findings,
            extracted_dir=extracted_dir,
        )

    # ------------------------------------------------------------------
    # Internal: signature scan
    # ------------------------------------------------------------------

    def _run_signature_scan(
        self,
        binwalk: str,
        firmware_path: Path,
    ) -> list[dict[str, Any]]:
        """
        Run binwalk -B (signature scan) and parse output.

        Uses --log to capture machine-readable output alongside stdout.

        Args:
            binwalk: Absolute path to binwalk binary.
            firmware_path: Target firmware file.

        Returns:
            List of signature dicts: {offset, hex_offset, description, name}.
        """
        log_file = self.session.output_dir / "binwalk_scan.log"

        cmd = [
            binwalk,
            "--signature",
            "--log", str(log_file),
            str(firmware_path),
        ]

        log.debug(f"Signature scan: {shlex.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            log.warning("binwalk signature scan timed out.")
            return []
        except Exception as exc:
            log.warning(f"binwalk scan error: {exc}")
            return []

        if result.returncode != 0:
            log.warning(
                f"binwalk exited with code {result.returncode}: "
                f"{result.stderr.strip()[:200]}"
            )

        # Try to parse the log output
        findings = self._parse_binwalk_log(log_file)
        if not findings:
            # Fall back to stdout parsing
            findings = self._parse_binwalk_stdout(result.stdout)

        log.info(f"binwalk found {len(findings)} signature(s).")
        for f in findings[:10]:  # Show first 10
            log.info(
                f"  0x{f.get('offset', 0):08X}  {f.get('description', '?')[:80]}"
            )
        if len(findings) > 10:
            log.info(f"  ... and {len(findings) - 10} more (see {log_file})")

        return findings

    def _parse_binwalk_log(self, log_file: Path) -> list[dict[str, Any]]:
        """
        Parse binwalk's CSV log output.

        binwalk --log writes lines like:
          DECIMAL,HEX,DESCRIPTION
          0,0x0,DLOB firmware header...

        Args:
            log_file: Path to the binwalk log file.

        Returns:
            List of parsed finding dicts.
        """
        if not log_file.exists():
            return []

        findings: list[dict[str, Any]] = []
        try:
            with open(log_file, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("DECIMAL"):
                        continue
                    parts = line.split(",", 2)
                    if len(parts) >= 3:
                        try:
                            offset = int(parts[0])
                            findings.append({
                                "offset": offset,
                                "hex_offset": parts[1].strip(),
                                "description": parts[2].strip(),
                            })
                        except ValueError:
                            continue
        except OSError as exc:
            log.debug(f"Could not read binwalk log: {exc}")

        return findings

    def _parse_binwalk_stdout(self, stdout: str) -> list[dict[str, Any]]:
        """
        Fallback: parse binwalk's human-readable stdout.

        Standard output format:
          DECIMAL       HEXADECIMAL     DESCRIPTION
          -------       -----------     -----------
          0             0x0             DLOB firmware header...

        Args:
            stdout: Raw stdout from binwalk.

        Returns:
            List of finding dicts (less precise than log parsing).
        """
        findings: list[dict[str, Any]] = []
        in_results = False

        for line in stdout.splitlines():
            stripped = line.strip()

            if stripped.startswith("DECIMAL"):
                in_results = True
                continue
            if stripped.startswith("---"):
                continue
            if not in_results or not stripped:
                continue

            parts = stripped.split(None, 2)
            if len(parts) >= 3:
                try:
                    offset = int(parts[0])
                    findings.append({
                        "offset": offset,
                        "hex_offset": parts[1],
                        "description": parts[2],
                    })
                except ValueError:
                    continue

        return findings

    # ------------------------------------------------------------------
    # Internal: extraction
    # ------------------------------------------------------------------

    def _run_extraction(
        self,
        binwalk: str,
        firmware_path: Path,
    ) -> Path | None:
        """
        Run binwalk -eM (extract + matryoshka) on the firmware.

        binwalk extracts into a directory named _{firmware_name}.extracted/
        adjacent to the firmware file. We move it into the session output dir.

        Args:
            binwalk: Absolute path to binwalk binary.
            firmware_path: Target firmware file.

        Returns:
            Path to the extraction directory, or None on failure.
        """
        cmd = [binwalk, "--extract"]
        if self.config.matryoshka:
            cmd.append("--matryoshka")
        cmd.append(str(firmware_path))

        log.info("Running binwalk extraction...")
        log.debug(f"Extraction cmd: {shlex.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(self.session.output_dir),  # Extract into session dir
            )
        except subprocess.TimeoutExpired:
            log.warning("binwalk extraction timed out.")
            return None
        except Exception as exc:
            log.warning(f"binwalk extraction error: {exc}")
            return None

        if result.returncode != 0:
            log.warning(
                f"binwalk extraction exit code {result.returncode}: "
                f"{result.stderr.strip()[:200]}"
            )

        # Find the extraction directory (binwalk names it _{filename}.extracted)
        extracted_dir_name = f"_{firmware_path.name}.extracted"
        extracted_dir = self.session.output_dir / extracted_dir_name

        # Also check if binwalk made it in the firmware's parent dir
        alt_dir = firmware_path.parent / extracted_dir_name
        if not extracted_dir.exists() and alt_dir.exists():
            shutil.move(str(alt_dir), str(extracted_dir))

        if extracted_dir.exists():
            file_count = sum(1 for _ in extracted_dir.rglob("*") if _.is_file())
            log.info(
                f"[green]Extraction complete[/green] → {extracted_dir} "
                f"({file_count} files)"
            )
            return extracted_dir

        log.warning(
            "binwalk extraction ran but output directory not found. "
            "Check if extraction rules are installed."
        )
        return None
