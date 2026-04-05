"""
FirmXtract Session — run context and state bag.

A Session is created once per `firmxtract extract` invocation and passed
through the entire pipeline. It tracks:
  - Output paths for this run
  - Detected hardware interfaces
  - Extracted firmware location
  - Analysis results
  - Timing information

Modules read from and write to the session but the orchestrator owns it.
"""

from __future__ import annotations


import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from firmxtract.utils.config import FirmXtractConfig, get_config
from firmxtract.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class DetectedInterface:
    """Describes a discovered hardware interface."""

    interface_type: str          # "uart" | "spi" | "jtag"
    port_or_device: str          # e.g. "/dev/ttyUSB0" or "ch341a_spi"
    metadata: dict[str, Any] = field(default_factory=dict)  # baud rate, chip id, etc.


@dataclass
class ExtractionResult:
    """Result of a firmware extraction attempt."""

    success: bool
    method: str                  # "uart" | "spi"
    firmware_path: Path | None = None
    size_bytes: int = 0
    checksum_sha256: str = ""
    error_message: str = ""


@dataclass
class AnalysisResult:
    """Result of post-extraction analysis (binwalk, secrets, etc.)."""

    tool: str                    # "binwalk" | "secrets"
    success: bool
    findings: list[dict[str, Any]] = field(default_factory=list)
    extracted_dir: Path | None = None
    error_message: str = ""


@dataclass
class Session:
    """
    Central state object for a single FirmXtract run.

    Created by the Orchestrator at session start. All pipeline stages
    receive a reference to the same Session instance and update it in place.
    """

    session_id: str
    started_at: datetime
    output_dir: Path

    # Config snapshot for this run
    config: FirmXtractConfig = field(default_factory=get_config)

    # Pipeline state (populated as the run progresses)
    detected_interfaces: list[DetectedInterface] = field(default_factory=list)
    extraction_result: ExtractionResult | None = None
    analysis_results: list[AnalysisResult] = field(default_factory=list)

    # Timing
    ended_at: datetime | None = None

    # Raw notes from any stage (freeform strings for the final report)
    notes: list[str] = field(default_factory=list)

    def add_note(self, note: str) -> None:
        """Append a freeform note to the session log."""
        log.debug(f"[session] {note}")
        self.notes.append(note)

    def mark_complete(self) -> None:
        """Record session end time."""
        self.ended_at = datetime.now()

    @property
    def duration_seconds(self) -> float | None:
        """Elapsed time in seconds, or None if session not finished."""
        if self.ended_at is None:
            return None
        return (self.ended_at - self.started_at).total_seconds()

    @property
    def firmware_extracted(self) -> bool:
        return (
            self.extraction_result is not None
            and self.extraction_result.success
            and self.extraction_result.firmware_path is not None
        )

    def to_report_dict(self) -> dict[str, Any]:
        """
        Serialize session to a JSON-serialisable dict for the final report.
        """
        return {
            "session_id": self.session_id,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "duration_seconds": self.duration_seconds,
            "output_dir": str(self.output_dir),
            "detected_interfaces": [
                {
                    "type": iface.interface_type,
                    "port": iface.port_or_device,
                    "metadata": iface.metadata,
                }
                for iface in self.detected_interfaces
            ],
            "extraction": {
                "success": self.extraction_result.success,
                "method": self.extraction_result.method,
                "firmware_path": str(self.extraction_result.firmware_path)
                if self.extraction_result and self.extraction_result.firmware_path
                else None,
                "size_bytes": self.extraction_result.size_bytes
                if self.extraction_result
                else 0,
                "checksum_sha256": self.extraction_result.checksum_sha256
                if self.extraction_result
                else "",
            }
            if self.extraction_result
            else None,
            "analysis": [
                {
                    "tool": r.tool,
                    "success": r.success,
                    "findings_count": len(r.findings),
                    "extracted_dir": str(r.extracted_dir) if r.extracted_dir else None,
                    "error": r.error_message,
                }
                for r in self.analysis_results
            ],
            "notes": self.notes,
        }

    def save_report(self) -> Path:
        """
        Write the session report JSON to the output directory.

        Returns:
            Path to the written report file.
        """
        report_path = self.output_dir / "report.json"
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(self.to_report_dict(), f, indent=2)
            log.info(f"Report saved → {report_path}")
        except OSError as exc:
            log.error(f"Failed to save report: {exc}")
        return report_path


def create_session(config: FirmXtractConfig | None = None) -> Session:
    """
    Factory: create a new Session with a timestamped output directory.

    Args:
        config: Optional config override. Defaults to get_config().

    Returns:
        A Session with output_dir created on disk (mode 0o700).
    """
    cfg = config or get_config()
    now = datetime.now()
    session_id = now.strftime("%Y%m%d_%H%M%S")

    output_dir = cfg.output.base_dir / session_id
    try:
        output_dir.mkdir(parents=True, exist_ok=True, mode=cfg.output.permissions)
    except OSError as exc:
        # Fallback to /tmp if home dir is unavailable
        log.warning(f"Could not create session dir {output_dir}: {exc}. Using /tmp.")
        output_dir = Path("/tmp") / f"firmxtract_{session_id}"
        output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    session = Session(
        session_id=session_id,
        started_at=now,
        output_dir=output_dir,
        config=cfg,
    )
    log.info(f"Session [bold]{session_id}[/bold] → {output_dir}")
    return session
