"""
Shared mock objects and fixtures for FirmXtract tests.

Import these in any test module instead of re-defining them.

Usage:
    from tests.mocks import (
        make_session,
        make_uart_interface,
        make_spi_interface,
        MockSerialPort,
        mock_successful_uart_result,
        mock_failed_uart_result,
        mock_successful_spi_result,
        mock_binwalk_result,
        mock_secrets_result,
    )
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterator
from unittest.mock import MagicMock, patch

from firmxtract.core.session import (
    AnalysisResult,
    DetectedInterface,
    ExtractionResult,
    Session,
)
from firmxtract.utils.config import (
    BinwalkConfig,
    FirmXtractConfig,
    OutputConfig,
    SPIConfig,
    UARTConfig,
)


# ---------------------------------------------------------------------------
# Config factory — isolated, never touches ~/.firmxtract
# ---------------------------------------------------------------------------


def make_test_config(tmp_path: Path) -> FirmXtractConfig:
    """
    Return a FirmXtractConfig wired to tmp_path.

    All output goes to tmp_path — never touches the user's home directory.
    """
    cfg = FirmXtractConfig()
    cfg.output = OutputConfig(base_dir=tmp_path / "sessions")
    cfg.uart = UARTConfig(
        default_baudrate=115200,
        baudrates=[115200, 9600],
        read_timeout=0.5,
        detection_timeout=1.0,
        detection_sample_bytes=128,
    )
    cfg.spi = SPIConfig(
        flashrom_path="flashrom",
        default_programmer="ch341a_spi",
        verify_after_dump=False,   # skip verify in tests
        dump_retries=1,
        chip_id_timeout=2.0,
    )
    cfg.binwalk = BinwalkConfig(
        binwalk_path="binwalk",
        extract=False,   # no real extraction in unit tests
        matryoshka=False,
    )
    return cfg


# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------


def make_session(tmp_path: Path) -> Session:
    """
    Return a real Session pointed at tmp_path.

    Output directory is created automatically.
    """
    cfg = make_test_config(tmp_path)
    output_dir = tmp_path / "sessions" / "test_session"
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    return Session(
        session_id="test_session",
        started_at=datetime(2026, 4, 2, 12, 0, 0),
        output_dir=output_dir,
        config=cfg,
    )


# ---------------------------------------------------------------------------
# DetectedInterface factories
# ---------------------------------------------------------------------------


def make_uart_interface(
    port: str = "/dev/ttyUSB0",
    baudrate: int = 115200,
    active: bool = True,
) -> DetectedInterface:
    """Return a pre-built UART DetectedInterface."""
    return DetectedInterface(
        interface_type="uart",
        port_or_device=port,
        metadata={
            "description": "CH341 USB Serial",
            "hwid": "USB VID:PID=1A86:7523",
            "active_output": active,
            "detected_baudrate": baudrate,
        },
    )


def make_spi_interface(
    programmer: str = "ch341a_spi",
    chip_name: str = "W25Q64.V",
) -> DetectedInterface:
    """Return a pre-built SPI DetectedInterface."""
    return DetectedInterface(
        interface_type="spi",
        port_or_device=programmer,
        metadata={
            "chip_id": f'vendor="Winbond" name="{chip_name}"',
            "chip_name": chip_name,
            "flashrom_path": "/usr/bin/flashrom",
        },
    )


# ---------------------------------------------------------------------------
# ExtractionResult factories
# ---------------------------------------------------------------------------


def mock_successful_uart_result(firmware_path: Path) -> ExtractionResult:
    """A successful UART extraction result pointing at firmware_path."""
    return ExtractionResult(
        success=True,
        method="uart",
        firmware_path=firmware_path,
        size_bytes=firmware_path.stat().st_size if firmware_path.exists() else 1024,
        checksum_sha256="a" * 64,
    )


def mock_failed_uart_result(reason: str = "No signal detected") -> ExtractionResult:
    """A failed UART extraction result."""
    return ExtractionResult(
        success=False,
        method="uart",
        error_message=reason,
    )


def mock_successful_spi_result(firmware_path: Path) -> ExtractionResult:
    """A successful SPI extraction result."""
    return ExtractionResult(
        success=True,
        method="spi",
        firmware_path=firmware_path,
        size_bytes=firmware_path.stat().st_size if firmware_path.exists() else 8 * 1024 * 1024,
        checksum_sha256="b" * 64,
    )


def mock_failed_spi_result(reason: str = "Chip not responding") -> ExtractionResult:
    """A failed SPI extraction result."""
    return ExtractionResult(
        success=False,
        method="spi",
        error_message=reason,
    )


# ---------------------------------------------------------------------------
# AnalysisResult factories
# ---------------------------------------------------------------------------


def mock_binwalk_result(
    extracted_dir: Path | None = None,
    findings: int = 3,
) -> AnalysisResult:
    """A successful binwalk result with synthetic findings."""
    return AnalysisResult(
        tool="binwalk",
        success=True,
        findings=[
            {
                "offset": i * 0x10000,
                "hex_offset": f"0x{i * 0x10000:X}",
                "description": f"Synthetic signature {i}",
            }
            for i in range(findings)
        ],
        extracted_dir=extracted_dir,
    )


def mock_failed_binwalk_result(reason: str = "binwalk not found") -> AnalysisResult:
    """A failed binwalk result."""
    return AnalysisResult(
        tool="binwalk",
        success=False,
        error_message=reason,
    )


def mock_secrets_result(n_findings: int = 2) -> AnalysisResult:
    """A secrets scan result with synthetic findings."""
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    return AnalysisResult(
        tool="secrets",
        success=True,
        findings=[
            {
                "pattern": f"pattern_{i}",
                "severity": severities[i % len(severities)],
                "description": f"Test finding {i}",
                "file": f"etc/config_{i}.conf",
                "line": i + 1,
                "preview": "ab***cd",
                "context": f"password=ab***cd  # line {i}",
            }
            for i in range(n_findings)
        ],
    )


# ---------------------------------------------------------------------------
# MockSerialPort — reusable pyserial mock
# ---------------------------------------------------------------------------


class MockSerialPort:
    """
    A controllable mock for serial.Serial.

    Feed response_bytes through the read() calls and track what was written.
    Supports context manager protocol.

    Usage:
        mock_port = MockSerialPort(response=b"U-Boot 2022\r\n=> ")
        with patch("serial.Serial", return_value=mock_port):
            result = some_uart_function(...)
    """

    def __init__(
        self,
        response: bytes = b"",
        chunk_size: int = 256,
        raise_on_open: Exception | None = None,
    ) -> None:
        self._response = bytearray(response)
        self._chunk_size = chunk_size
        self._raise_on_open = raise_on_open
        self.written: bytearray = bytearray()
        self.baudrate: int = 115200
        self.timeout: float = 1.0

    # Context manager
    def __enter__(self) -> "MockSerialPort":
        if self._raise_on_open:
            raise self._raise_on_open
        return self

    def __exit__(self, *args: object) -> None:
        pass

    # serial.Serial interface
    def read(self, size: int = 1) -> bytes:
        n = min(size, self._chunk_size, len(self._response))
        chunk = bytes(self._response[:n])
        self._response = self._response[n:]
        return chunk

    def write(self, data: bytes) -> int:
        self.written.extend(data)
        return len(data)

    def reset_input_buffer(self) -> None:
        pass

    def close(self) -> None:
        pass

    @property
    def in_waiting(self) -> int:
        return len(self._response)

    def feed(self, data: bytes) -> None:
        """Add more data to the response buffer (call between read()s in tests)."""
        self._response.extend(data)
