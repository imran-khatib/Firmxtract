"""
FirmXtract Orchestrator — central pipeline controller.

The Orchestrator wires together all pipeline stages:
  1. Hardware detection (via HAL)
  2. Firmware extraction (UART primary → SPI fallback)
  3. Post-extraction analysis (binwalk)
  4. Secrets scan (on extracted filesystem)
  5. Report generation

It does NOT contain hardware or analysis logic — it delegates entirely
to the relevant modules and handles fallback/error coordination.

Usage:
    orchestrator = Orchestrator(session)
    orchestrator.run()                    # full pipeline, auto-detect hardware
    orchestrator.run_with_interfaces()    # skip detection, use pre-seeded interfaces
"""

from firmxtract.core.session import Session
from firmxtract.hardware.hal import HAL, InterfaceType
from firmxtract.hardware.uart import UARTHandler
from firmxtract.hardware.spi import SPIHandler
from firmxtract.analysis.secrets import SecretsHunter
from firmxtract.extraction.binwalk_wrapper import BinwalkWrapper
from firmxtract.utils.logger import get_logger

log = get_logger(__name__)


class Orchestrator:
    """
    Coordinates the full FirmXtract extraction and analysis pipeline.

    Attributes:
        session: The active Session instance (owns output paths + state).
        hal: Hardware Abstraction Layer instance.
    """

    def __init__(self, session: Session) -> None:
        self.session = session
        self.hal = HAL(session.config)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self) -> bool:
        """
        Execute the full pipeline: detect hardware → extract → analyze → report.

        Returns:
            True if firmware was successfully extracted (and analyzed if applicable).
        """
        log.info("[bold green]FirmXtract pipeline starting...[/bold green]")
        try:
            self._stage_detect_hardware()
            return self._run_extract_analyze()
        except KeyboardInterrupt:
            log.warning("Pipeline interrupted by user.")
            self.session.add_note("Pipeline interrupted by user (KeyboardInterrupt).")
            return False
        except Exception as exc:
            log.critical(f"Unhandled pipeline error: {exc}", exc_info=True)
            self.session.add_note(f"Pipeline aborted due to unhandled error: {exc}")
            return False
        finally:
            self._stage_finalize()

    def run_with_interfaces(self, skip_analyze: bool = False) -> bool:
        """
        Execute the pipeline assuming session.detected_interfaces is pre-populated.

        Use this when the caller has already seeded specific interfaces (e.g. the CLI
        was given --port /dev/ttyUSB0 explicitly) and hardware detection should be
        skipped entirely.

        Args:
            skip_analyze: If True, skip binwalk analysis after extraction.

        Returns:
            True if firmware was successfully extracted.
        """
        log.info("[bold green]FirmXtract pipeline starting (pre-seeded interfaces)...[/bold green]")
        try:
            return self._run_extract_analyze(skip_analyze=skip_analyze)
        except KeyboardInterrupt:
            log.warning("Pipeline interrupted by user.")
            self.session.add_note("Pipeline interrupted by user (KeyboardInterrupt).")
            return False
        except Exception as exc:
            log.critical(f"Unhandled pipeline error: {exc}", exc_info=True)
            self.session.add_note(f"Pipeline aborted due to unhandled error: {exc}")
            return False
        finally:
            self._stage_finalize()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_extract_analyze(self, skip_analyze: bool = False) -> bool:
        """Shared extract→analyze logic used by both run() variants."""
        extraction_ok = self._stage_extract_firmware()
        if extraction_ok and not skip_analyze:
            self._stage_analyze_firmware()
            self._stage_scan_secrets()
        elif not extraction_ok:
            log.error("Firmware extraction failed. Skipping analysis.")
        return self.session.firmware_extracted

    # ------------------------------------------------------------------
    # Pipeline stages (private — not part of public API)
    # ------------------------------------------------------------------

    def _stage_detect_hardware(self) -> None:
        """Stage 1: Detect available hardware interfaces via HAL."""
        log.info("─── Stage 1: Hardware Detection ────────────────────────")
        interfaces = self.hal.detect_interfaces()

        if not interfaces:
            log.warning("No hardware interfaces detected.")
            self.session.add_note("Hardware detection: no interfaces found.")
        else:
            for iface in interfaces:
                log.info(
                    f"  [green]✓[/green] {iface.interface_type.upper()} → "
                    f"{iface.port_or_device}"
                )
                self.session.detected_interfaces.append(iface)

    def _stage_extract_firmware(self) -> bool:
        """
        Stage 2: Extract firmware — UART first, SPI on failure.

        Returns:
            True if extraction succeeded via any method.
        """
        log.info("─── Stage 2: Firmware Extraction ───────────────────────")

        uart_interfaces = [
            i for i in self.session.detected_interfaces
            if i.interface_type == InterfaceType.UART
        ]
        if uart_interfaces:
            log.info(f"Attempting UART extraction on {uart_interfaces[0].port_or_device}...")
            result = UARTHandler(self.session).extract(uart_interfaces[0])
            self.session.extraction_result = result
            if result.success:
                log.info(
                    f"[green]UART extraction succeeded[/green] — "
                    f"{result.size_bytes:,} bytes → {result.firmware_path}"
                )
                return True
            log.warning(f"UART extraction failed: {result.error_message}")
            log.info("Falling back to SPI extraction...")
        else:
            log.info("No UART interface detected. Attempting SPI directly.")

        spi_interfaces = [
            i for i in self.session.detected_interfaces
            if i.interface_type == InterfaceType.SPI
        ]
        if not spi_interfaces:
            log.warning(
                "No SPI interface detected. "
                "Check hardware connections and programmer setup."
            )
            self.session.add_note("No UART or SPI interface available for extraction.")
            return False

        log.info(f"Attempting SPI extraction via {spi_interfaces[0].port_or_device}...")
        result = SPIHandler(self.session).extract(spi_interfaces[0])
        self.session.extraction_result = result

        if result.success:
            log.info(
                f"[green]SPI extraction succeeded[/green] — "
                f"{result.size_bytes:,} bytes → {result.firmware_path}"
            )
            return True

        log.error(f"SPI extraction failed: {result.error_message}")
        self.session.add_note(
            f"Both UART and SPI extraction failed. Last error: {result.error_message}"
        )
        return False

    def _stage_analyze_firmware(self) -> None:
        """Stage 3: Analyze extracted firmware with binwalk."""
        log.info("─── Stage 3: Firmware Analysis ─────────────────────────")

        if (
            self.session.extraction_result is None
            or not self.session.extraction_result.firmware_path
        ):
            log.error("No firmware path in session — cannot analyze. This is a bug.")
            return

        firmware_path = self.session.extraction_result.firmware_path
        result = BinwalkWrapper(self.session).analyze(firmware_path)
        self.session.analysis_results.append(result)

        if result.success:
            log.info(
                f"[green]binwalk complete[/green] — "
                f"{len(result.findings)} signature(s) found."
            )
            if result.extracted_dir:
                log.info(f"  Extracted filesystem → {result.extracted_dir}")
        else:
            log.warning(f"binwalk analysis failed: {result.error_message}")


    def _stage_scan_secrets(self) -> None:
        """Stage 4: Scan extracted filesystem for hardcoded secrets."""
        log.info("─── Stage 4: Secrets Scan ──────────────────────────────")

        # Find the extraction directory from the binwalk result
        extracted_dir = None
        for result in self.session.analysis_results:
            if result.tool == "binwalk" and result.extracted_dir:
                extracted_dir = result.extracted_dir
                break

        # Fall back to raw firmware file if no extracted filesystem
        scan_target = extracted_dir
        if scan_target is None:
            if (
                self.session.extraction_result is not None
                and self.session.extraction_result.firmware_path is not None
            ):
                scan_target = self.session.extraction_result.firmware_path
                log.info(
                    "No extracted filesystem found — scanning raw firmware file."
                )
            else:
                log.warning("No target available for secrets scan. Skipping.")
                return

        result = SecretsHunter(self.session).analyze(scan_target)
        self.session.analysis_results.append(result)

    def _stage_finalize(self) -> None:
        """Finalize: mark session complete, save report, print summary."""
        log.info("─── Finalizing Session ─────────────────────────────────")
        self.session.mark_complete()
        report_path = self.session.save_report()

        duration = self.session.duration_seconds or 0.0
        status = (
            "[green]SUCCESS[/green]" if self.session.firmware_extracted
            else "[red]FAILED[/red]"
        )
        log.info(
            f"Session [bold]{self.session.session_id}[/bold] complete "
            f"({duration:.1f}s) — {status}"
        )
        log.info(f"Report → {report_path}")
