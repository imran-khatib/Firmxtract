"""
FirmXtract Built-in Plugin: Entropy Analyzer

Analyzes firmware binary for entropy distribution.
High entropy regions indicate encryption or compression.
Low entropy regions may contain readable strings or config data.

Hooks: POST_EXTRACT — runs immediately after firmware is extracted.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import TYPE_CHECKING

from firmxtract.core.base import BasePlugin, HookPoint, ModuleResult, ModuleStatus

if TYPE_CHECKING:
    from firmxtract.core.session import Session


class EntropyAnalyzerPlugin(BasePlugin):
    """
    Analyzes entropy of extracted firmware to identify encrypted/compressed regions.

    Findings:
      - HIGH_ENTROPY:   region likely encrypted or compressed (entropy > 7.2)
      - LOW_ENTROPY:    region may contain plaintext/config (entropy < 1.0)
      - NORMAL_ENTROPY: typical firmware code/data region
    """

    name        = "entropy_analyzer"
    description = "Entropy analysis — identifies encrypted/compressed firmware regions"
    version     = "1.0.0"
    author      = "FirmXtract"
    hooks       = [HookPoint.POST_EXTRACT]
    priority    = 10   # runs early, before analysis stages

    # Block size for entropy calculation (4KB)
    BLOCK_SIZE = 4096
    HIGH_ENTROPY_THRESHOLD = 7.2
    LOW_ENTROPY_THRESHOLD  = 1.0

    def run(self, session: "Session") -> ModuleResult:
        """Calculate block entropy on the extracted firmware file."""
        if (
            session.extraction_result is None
            or not session.extraction_result.firmware_path
            or not session.extraction_result.firmware_path.exists()
        ):
            return ModuleResult(
                module_name=self.name,
                status=ModuleStatus.SKIPPED,
                error="No firmware file available for entropy analysis.",
            )

        firmware_path = session.extraction_result.firmware_path
        findings = self._analyze_entropy(firmware_path)

        high = sum(1 for f in findings if f["type"] == "HIGH_ENTROPY")
        low  = sum(1 for f in findings if f["type"] == "LOW_ENTROPY")

        session.add_note(
            f"Entropy analysis: {len(findings)} blocks — "
            f"{high} high-entropy, {low} low-entropy regions."
        )

        # Save entropy report
        report_path = session.output_dir / "entropy_report.txt"
        self._write_report(report_path, findings, firmware_path)

        return ModuleResult(
            module_name=self.name,
            status=ModuleStatus.SUCCESS,
            findings=findings,
            output_path=str(report_path),
            metadata={
                "total_blocks": len(findings),
                "high_entropy_blocks": high,
                "low_entropy_blocks": low,
                "firmware_size": firmware_path.stat().st_size,
            },
        )

    def _analyze_entropy(self, path: Path) -> list[dict]:
        """Calculate Shannon entropy for each block of the firmware."""
        findings = []
        offset = 0

        with open(path, "rb") as f:
            while True:
                block = f.read(self.BLOCK_SIZE)
                if not block:
                    break
                entropy = self._shannon_entropy(block)
                block_type = (
                    "HIGH_ENTROPY" if entropy > self.HIGH_ENTROPY_THRESHOLD
                    else "LOW_ENTROPY" if entropy < self.LOW_ENTROPY_THRESHOLD
                    else "NORMAL"
                )
                if block_type != "NORMAL":
                    findings.append({
                        "type": block_type,
                        "offset": offset,
                        "hex_offset": f"0x{offset:08X}",
                        "entropy": round(entropy, 4),
                        "size": len(block),
                        "description": (
                            "Likely encrypted or compressed data"
                            if block_type == "HIGH_ENTROPY"
                            else "Low-entropy region — may contain config or strings"
                        ),
                    })
                offset += len(block)

        return findings

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of a byte sequence (0.0 to 8.0)."""
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        length = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    def _write_report(
        self, path: Path, findings: list[dict], firmware_path: Path
    ) -> None:
        """Write entropy report to file."""
        lines = [
            f"Entropy Analysis Report — {firmware_path.name}",
            f"Size: {firmware_path.stat().st_size:,} bytes",
            f"Block size: {self.BLOCK_SIZE} bytes",
            f"Notable regions: {len(findings)}",
            "=" * 60,
        ]
        for f in findings:
            lines.append(
                f"[{f['type']:12}]  {f['hex_offset']}  "
                f"entropy={f['entropy']:.4f}  {f['description']}"
            )
        path.write_text("\n".join(lines) + "\n")
