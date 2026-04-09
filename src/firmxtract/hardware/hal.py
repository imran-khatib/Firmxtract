"""
FirmXtract Hardware Abstraction Layer (HAL).

Provides a unified interface for hardware detection and communication.
In Phase 1, detection is pure Python (pyserial + flashrom probing).
In Phase 2, performance-critical paths will delegate to Rust via PyO3.

The HAL registry pattern allows future hardware modules (JTAG, I2C, etc.)
to be added without modifying the orchestrator.

Usage:
    hal = HAL(config)
    interfaces = hal.detect_interfaces()
    # returns list[DetectedInterface]
"""

import shutil
from abc import ABC, abstractmethod
from typing import Any

from firmxtract.core.session import DetectedInterface
from firmxtract.utils.config import FirmXtractConfig
from firmxtract.utils.logger import get_logger

log = get_logger(__name__)


class InterfaceType:
    """String constants for interface types (avoids stringly-typed bugs)."""

    UART = "uart"
    SPI = "spi"
    JTAG = "jtag"
    I2C = "i2c"
    UNKNOWN = "unknown"


class HardwareInterface(ABC):
    """
    Abstract base class for all hardware interface detectors.

    Subclasses implement detect() to probe for their specific hardware.
    The HAL calls detect() on all registered interfaces during discovery.
    """

    interface_type: str = InterfaceType.UNKNOWN

    def __init__(self, config: FirmXtractConfig) -> None:
        self.config = config

    @abstractmethod
    def detect(self) -> list[DetectedInterface]:
        """
        Probe the system for available hardware interfaces of this type.

        Returns:
            List of DetectedInterface objects (empty list if none found).
            Must NOT raise exceptions — catch internally and log.
        """
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """
        Quick check: is the required tooling/driver available on this system?
        Used to skip detection entirely if prerequisites are missing.

        Returns:
            True if detection can proceed.
        """
        ...


class UARTDetector(HardwareInterface):
    """
    Detects UART / serial interfaces.

    Delegates full logic to hardware.uart — this class is the HAL-facing
    thin wrapper that calls the uart module's port enumeration.
    """

    interface_type = InterfaceType.UART

    def is_available(self) -> bool:
        """pyserial is always available if installed (no external tool needed)."""
        try:
            import serial.tools.list_ports  # noqa: F401
            return True
        except ImportError:
            log.warning("pyserial not installed — UART detection unavailable.")
            return False

    def detect(self) -> list[DetectedInterface]:
        if not self.is_available():
            return []
        try:
            from firmxtract.hardware.uart import enumerate_uart_ports
            return enumerate_uart_ports(self.config.uart)
        except Exception as exc:
            log.warning(f"UART detection error: {exc}")
            return []


class SPIDetector(HardwareInterface):
    """
    Detects SPI flash programmers supported by flashrom.

    Probes for common USB-to-SPI programmers using flashrom's
    --flash-name / --get-size quick probe (read-only, safe).
    """

    interface_type = InterfaceType.SPI

    def is_available(self) -> bool:
        """Check if flashrom binary is on PATH."""
        path = shutil.which(self.config.spi.flashrom_path)
        if path is None:
            log.warning(
                f"flashrom not found at '{self.config.spi.flashrom_path}'. "
                "SPI detection unavailable. Install with: apt install flashrom"
            )
            return False
        return True

    def detect(self) -> list[DetectedInterface]:
        if not self.is_available():
            return []
        try:
            from firmxtract.hardware.spi import probe_spi_programmer
            return probe_spi_programmer(self.config.spi)
        except Exception as exc:
            log.warning(f"SPI detection error: {exc}")
            return []


# Phase 2 stub — will wrap OpenOCD
class JTAGDetector(HardwareInterface):
    """JTAG interface detector (Phase 2 — not yet implemented)."""

    interface_type = InterfaceType.JTAG

    def is_available(self) -> bool:
        available = shutil.which("openocd") is not None
        if not available:
            log.debug("openocd not found — JTAG detection skipped.")
        return available

    def detect(self) -> list[DetectedInterface]:
        log.debug("JTAG detection not yet implemented (Phase 2).")
        return []


# ---------------------------------------------------------------------------
# HAL — registry and orchestration
# ---------------------------------------------------------------------------


class HAL:
    """
    Hardware Abstraction Layer.

    Maintains a registry of interface detectors and orchestrates discovery.
    New interface types can be registered via HAL.register().

    Phase 2 note: detect_interfaces() will optionally call into Rust-compiled
    detection routines via PyO3 for faster baud-rate scanning and signal analysis.
    """

    def __init__(self, config: FirmXtractConfig) -> None:
        self.config = config
        self._detectors: list[HardwareInterface] = [
            UARTDetector(config),
            SPIDetector(config),
            JTAGDetector(config),
        ]

    def register(self, detector: HardwareInterface) -> None:
        """
        Register a custom hardware interface detector.

        Args:
            detector: An instance of a HardwareInterface subclass.
        """
        self._detectors.append(detector)
        log.debug(f"HAL: registered detector for {detector.interface_type}")

    def detect_interfaces(self) -> list[DetectedInterface]:
        """
        Run all registered detectors and return all found interfaces.

        Detection is sequential (Phase 1). Phase 2 will parallelize with asyncio.
        Detectors that are unavailable (missing tools) are skipped silently.

        Returns:
            Flat list of DetectedInterface from all detectors.
        """
        log.debug("HAL: starting interface detection sweep...")
        found: list[DetectedInterface] = []

        for detector in self._detectors:
            itype = detector.interface_type
            log.debug(f"HAL: probing {itype}...")
            results = detector.detect()
            if results:
                log.debug(f"HAL: {itype} → {len(results)} interface(s) found.")
            found.extend(results)

        log.debug(f"HAL: detection complete — {len(found)} total interface(s).")
        return found

    def get_interface(
        self, interface_type: str
    ) -> list[DetectedInterface]:
        """
        Convenience: detect and filter to a specific interface type.

        Args:
            interface_type: One of InterfaceType.* constants.

        Returns:
            Filtered list of DetectedInterface.
        """
        all_ifaces = self.detect_interfaces()
        return [i for i in all_ifaces if i.interface_type == interface_type]
