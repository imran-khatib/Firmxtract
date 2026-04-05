"""
Tests for firmxtract.hardware.spi

Uses subprocess mocking — no hardware required.
Hardware tests are marked @pytest.mark.hardware.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

from firmxtract.hardware.spi import (
    _get_chip_id,
    _parse_chip_id,
    _parse_chip_name,
    probe_spi_programmer,
    SPIHandler,
)
from firmxtract.utils.config import SPIConfig


FLASHROM_CHIP_OUTPUT = 'vendor="Winbond" name="W25Q64.V"'
FLASHROM_NO_CHIP_STDERR = "No EEPROM/flash device found."


# ---------------------------------------------------------------------------
# _parse_chip_id / _parse_chip_name
# ---------------------------------------------------------------------------


class TestChipParsing:
    def test_parse_chip_id_found(self):
        result = _parse_chip_id(FLASHROM_CHIP_OUTPUT)
        assert result is not None
        assert "Winbond" in result

    def test_parse_chip_name_found(self):
        result = _parse_chip_name(FLASHROM_CHIP_OUTPUT)
        assert result == "W25Q64.V"

    def test_parse_chip_name_missing(self):
        result = _parse_chip_name("No chip found.")
        assert result is None

    def test_parse_chip_id_empty(self):
        result = _parse_chip_id("")
        assert result is None


# ---------------------------------------------------------------------------
# _get_chip_id
# ---------------------------------------------------------------------------


class TestGetChipId:
    @patch("firmxtract.hardware.spi.subprocess.run")
    def test_chip_detected(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=FLASHROM_CHIP_OUTPUT,
            stderr="",
        )
        chip_id, chip_name = _get_chip_id("flashrom", "ch341a_spi", timeout=10.0)
        assert chip_id is not None
        assert chip_name == "W25Q64.V"

    @patch("firmxtract.hardware.spi.subprocess.run")
    def test_no_chip_returns_none(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=3,
            stdout="",
            stderr=FLASHROM_NO_CHIP_STDERR,
        )
        chip_id, chip_name = _get_chip_id("flashrom", "ch341a_spi", timeout=10.0)
        assert chip_id is None
        assert chip_name is None

    @patch("firmxtract.hardware.spi.subprocess.run")
    def test_timeout_returns_none(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="flashrom", timeout=10)
        chip_id, chip_name = _get_chip_id("flashrom", "ch341a_spi", timeout=10.0)
        assert chip_id is None

    @patch("firmxtract.hardware.spi.subprocess.run")
    def test_binary_not_found_returns_none(self, mock_run):
        mock_run.side_effect = FileNotFoundError("flashrom not found")
        chip_id, chip_name = _get_chip_id("/nonexistent/flashrom", "ch341a_spi", timeout=10.0)
        assert chip_id is None


# ---------------------------------------------------------------------------
# probe_spi_programmer
# ---------------------------------------------------------------------------


class TestProbeSpiProgrammer:
    @patch("firmxtract.hardware.spi.shutil.which")
    @patch("firmxtract.hardware.spi._get_chip_id")
    def test_programmer_detected(self, mock_get_chip, mock_which):
        mock_which.return_value = "/usr/bin/flashrom"
        mock_get_chip.return_value = ("detected", "W25Q64.V")

        config = SPIConfig()
        result = probe_spi_programmer(config)

        assert len(result) == 1
        assert result[0].interface_type == "spi"
        assert result[0].metadata["chip_name"] == "W25Q64.V"

    @patch("firmxtract.hardware.spi.shutil.which")
    def test_flashrom_missing_returns_empty(self, mock_which):
        mock_which.return_value = None
        config = SPIConfig()
        result = probe_spi_programmer(config)
        assert result == []

    @patch("firmxtract.hardware.spi.shutil.which")
    @patch("firmxtract.hardware.spi._get_chip_id")
    def test_no_chip_returns_empty(self, mock_get_chip, mock_which):
        mock_which.return_value = "/usr/bin/flashrom"
        mock_get_chip.return_value = (None, None)

        config = SPIConfig()
        result = probe_spi_programmer(config)
        assert result == []


# ---------------------------------------------------------------------------
# SPIHandler.extract
# ---------------------------------------------------------------------------


class TestSPIHandlerExtract:
    def _make_session(self, tmp_path: Path) -> MagicMock:
        session = MagicMock()
        session.output_dir = tmp_path
        session.config.spi.flashrom_path = "flashrom"
        session.config.spi.dump_retries = 2
        session.config.spi.verify_after_dump = False
        return session

    def _make_interface(self) -> MagicMock:
        iface = MagicMock()
        iface.port_or_device = "ch341a_spi"
        iface.metadata = {
            "chip_name": "W25Q64.V",
            "flashrom_path": "/usr/bin/flashrom",
        }
        return iface

    @patch("firmxtract.hardware.spi.subprocess.run")
    def test_successful_dump(self, mock_run, tmp_path):
        # Simulate flashrom writing the dump file
        def fake_run(cmd, **kwargs):
            output_path = Path(cmd[cmd.index("-r") + 1])
            output_path.write_bytes(b"\xFF" * 8 * 1024 * 1024)  # 8MB fake dump
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = fake_run

        session = self._make_session(tmp_path)
        handler = SPIHandler(session)
        result = handler.extract(self._make_interface())

        assert result.success is True
        assert result.method == "spi"
        assert result.size_bytes == 8 * 1024 * 1024
        assert result.checksum_sha256 != ""

    @patch("firmxtract.hardware.spi.subprocess.run")
    def test_failed_dump_returns_error(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Chip not responding",
        )

        session = self._make_session(tmp_path)
        handler = SPIHandler(session)
        result = handler.extract(self._make_interface())

        assert result.success is False
        assert "Chip not responding" in result.error_message or "failed" in result.error_message


# ---------------------------------------------------------------------------
# Hardware integration tests
# ---------------------------------------------------------------------------


@pytest.mark.hardware
class TestSPIHardware:
    """Real hardware tests — require a physical SPI programmer + chip."""

    def test_probe_finds_programmer(self):
        config = SPIConfig()
        result = probe_spi_programmer(config)
        assert len(result) > 0, "No SPI programmer detected."
