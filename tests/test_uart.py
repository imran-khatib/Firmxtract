"""
Tests for firmxtract.hardware.uart

Hardware tests are marked @pytest.mark.hardware — skipped in CI.
All other tests use mocked serial ports (no physical device needed).
"""

from __future__ import annotations

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, call

from firmxtract.hardware.uart import (
    _detect_shell_type,
    MtdPartition,
    _score_serial_data,
    _detect_prompt_type,
    _parse_mtd_table,
    _select_best_partition,
    enumerate_uart_ports,
    detect_baudrate,
    UARTHandler,
)
from firmxtract.utils.config import UARTConfig


# ---------------------------------------------------------------------------
# _score_serial_data
# ---------------------------------------------------------------------------


class TestScoreSerialData:
    def test_empty_returns_zero(self):
        assert _score_serial_data(b"") == 0.0

    def test_too_short_returns_zero(self):
        assert _score_serial_data(b"hello") == 0.0

    def test_uboot_banner_returns_one(self):
        assert _score_serial_data(b"\r\nU-Boot 2022.07 (Jan 01 2023)\r\n") == 1.0

    def test_linux_version_returns_one(self):
        assert _score_serial_data(b"Linux version 5.10.0 (gcc 10.2)\r\n") == 1.0

    def test_busybox_returns_one(self):
        assert _score_serial_data(b"BusyBox v1.33.1 built-in shell\r\n# ") == 1.0

    def test_uboot_prompt_returns_one(self):
        assert _score_serial_data(b"Hit any key to stop autoboot\r\n=> ") == 1.0

    def test_binary_garbage_returns_zero(self):
        # lots of non-printable bytes
        assert _score_serial_data(bytes(range(256)) * 4) == 0.0

    def test_printable_text_moderate_score(self):
        data = b"Some readable output without known signatures\r\n" * 5
        score = _score_serial_data(data)
        assert 0.0 < score <= 0.5

    def test_case_insensitive_matching(self):
        assert _score_serial_data(b"u-boot version 2022\r\n") == 1.0


# ---------------------------------------------------------------------------
# _detect_prompt_type
# ---------------------------------------------------------------------------


class TestDetectPromptType:
    def test_shell_root_prompt(self):
        assert _detect_prompt_type(b"root@router:~# ") == "shell"

    def test_shell_busybox(self):
        assert _detect_prompt_type(b"BusyBox v1.33 (TT) built-in shell\n# ") == "shell"

    def test_uboot_prompt(self):
        assert _detect_prompt_type(b"U-Boot 2019.07\r\n=> ") == "uboot"

    def test_uboot_cfe(self):
        assert _detect_prompt_type(b"CFE version 1.0\r\nCFE> ") == "uboot"

    def test_unknown_printable(self):
        assert _detect_prompt_type(b"some random text without known markers") == "unknown"

    def test_uboot_takes_priority_over_shell(self):
        # U-Boot prints Linux banners before handing off sometimes
        data = b"U-Boot 2022 => Linux version 5.10"
        # U-Boot signature hits first in the list
        assert _detect_prompt_type(data) == "uboot"


# ---------------------------------------------------------------------------
# _parse_mtd_table
# ---------------------------------------------------------------------------


MTD_SAMPLE = b"""dev:    size   erasesize  name
mtd0: 00020000 00010000 "u-boot"
mtd1: 00010000 00010000 "u-boot-env"
mtd2: 00ed0000 00010000 "firmware"
mtd3: 00100000 00010000 "kernel"
mtd4: 00dc0000 00010000 "rootfs"
"""


class TestParseMtdTable:
    def test_parses_all_partitions(self):
        result = _parse_mtd_table(MTD_SAMPLE)
        assert len(result) == 5

    def test_partition_names(self):
        result = _parse_mtd_table(MTD_SAMPLE)
        names = [p["name"] for p in result]
        assert "u-boot" in names
        assert "firmware" in names
        assert "rootfs" in names

    def test_partition_sizes(self):
        result = _parse_mtd_table(MTD_SAMPLE)
        fw = next(p for p in result if p["name"] == "firmware")
        assert fw["size_bytes"] == 0x00ED0000

    def test_partition_devices(self):
        result = _parse_mtd_table(MTD_SAMPLE)
        devices = [p["device"] for p in result]
        assert "mtd0" in devices
        assert "mtd4" in devices

    def test_empty_input(self):
        assert _parse_mtd_table(b"") == []

    def test_malformed_input(self):
        assert _parse_mtd_table(b"not mtd output at all") == []


# ---------------------------------------------------------------------------
# _select_best_partition
# ---------------------------------------------------------------------------


class TestSelectBestPartition:
    def _make_partitions(self):
        return [
            {"device": "mtd0", "size_bytes": 0x20000, "name": "u-boot"},
            {"device": "mtd1", "size_bytes": 0x10000, "name": "u-boot-env"},
            {"device": "mtd2", "size_bytes": 0xED0000, "name": "firmware"},
            {"device": "mtd3", "size_bytes": 0x100000, "name": "kernel"},
            {"device": "mtd4", "size_bytes": 0xDC0000, "name": "rootfs"},
        ]

    def test_selects_firmware_partition(self):
        result = _select_best_partition(self._make_partitions())
        assert result is not None
        assert result["name"] == "firmware"

    def test_empty_returns_none(self):
        assert _select_best_partition([]) is None

    def test_no_name_match_picks_largest(self):
        partitions = [
            {"device": "mtd0", "size_bytes": 0x10000, "name": "env"},
            {"device": "mtd1", "size_bytes": 0x800000, "name": "data"},
            {"device": "mtd2", "size_bytes": 0x20000, "name": "boot"},
        ]
        result = _select_best_partition(partitions)
        assert result is not None
        assert result["device"] == "mtd1"

    def test_rootfs_preferred_over_unknown(self):
        partitions = [
            {"device": "mtd0", "size_bytes": 0x1000000, "name": "unknown_blob"},
            {"device": "mtd1", "size_bytes": 0x500000, "name": "rootfs"},
        ]
        result = _select_best_partition(partitions)
        assert result is not None
        assert result["name"] == "rootfs"


# ---------------------------------------------------------------------------
# enumerate_uart_ports
# ---------------------------------------------------------------------------


class TestEnumerateUartPorts:
    @patch("firmxtract.hardware.uart.serial.tools.list_ports.comports")
    def test_no_ports_returns_empty(self, mock_comports):
        mock_comports.return_value = []
        assert enumerate_uart_ports(UARTConfig()) == []

    @patch("firmxtract.hardware.uart._probe_port")
    @patch("firmxtract.hardware.uart.serial.tools.list_ports.comports")
    def test_active_port_detected(self, mock_comports, mock_probe):
        port = MagicMock()
        port.device = "/dev/ttyUSB0"
        port.description = "CH341 USB"
        port.hwid = "USB VID:PID=1A86:7523"
        mock_comports.return_value = [port]
        mock_probe.return_value = (True, 115200)

        result = enumerate_uart_ports(UARTConfig())
        assert len(result) == 1
        assert result[0].metadata["active_output"] is True
        assert result[0].metadata["detected_baudrate"] == 115200

    @patch("firmxtract.hardware.uart._probe_port")
    @patch("firmxtract.hardware.uart.serial.tools.list_ports.comports")
    def test_active_ports_sorted_first(self, mock_comports, mock_probe):
        ports = []
        for device in ["/dev/ttyUSB0", "/dev/ttyUSB1"]:
            p = MagicMock()
            p.device = device
            p.description = "Test"
            p.hwid = "TEST"
            ports.append(p)
        mock_comports.return_value = ports

        mock_probe.side_effect = lambda d, _cfg: (True, 115200) if "USB1" in d else (False, None)
        result = enumerate_uart_ports(UARTConfig())
        assert result[0].port_or_device == "/dev/ttyUSB1"


# ---------------------------------------------------------------------------
# detect_baudrate
# ---------------------------------------------------------------------------


class TestDetectBaudrate:
    @patch("firmxtract.hardware.uart.serial.Serial")
    def test_uboot_detected_immediately(self, MockSerial):
        mock_ser = MagicMock()
        mock_ser.__enter__ = lambda s: s
        mock_ser.__exit__ = MagicMock(return_value=False)
        mock_ser.read.return_value = b"U-Boot 2022.07 - MIPS\r\n=> "
        MockSerial.return_value = mock_ser

        result = detect_baudrate("/dev/ttyUSB0", UARTConfig(baudrates=[115200, 9600]))
        assert result == 115200

    @patch("firmxtract.hardware.uart.serial.Serial")
    def test_no_output_returns_none(self, MockSerial):
        mock_ser = MagicMock()
        mock_ser.__enter__ = lambda s: s
        mock_ser.__exit__ = MagicMock(return_value=False)
        mock_ser.read.return_value = b""
        MockSerial.return_value = mock_ser

        result = detect_baudrate("/dev/ttyUSB0", UARTConfig(baudrates=[9600, 115200]))
        assert result is None


# ---------------------------------------------------------------------------
# UARTHandler.extract — integration scenarios (mocked serial)
# ---------------------------------------------------------------------------


class TestUARTHandlerExtract:
    def _make_session(self, tmp_path: Path) -> MagicMock:
        session = MagicMock()
        session.output_dir = tmp_path
        session.config.uart = UARTConfig(
            detection_timeout=2.0,
            read_timeout=1.0,
            detection_sample_bytes=256,
        )
        return session

    def _make_interface(self, baud: int = 115200) -> MagicMock:
        iface = MagicMock()
        iface.port_or_device = "/dev/ttyUSB0"
        iface.metadata = {"detected_baudrate": baud, "active_output": True}
        return iface

    @patch("firmxtract.hardware.uart.serial.Serial")
    def test_no_output_returns_failure(self, MockSerial, tmp_path):
        mock_ser = MagicMock()
        mock_ser.__enter__ = lambda s: s
        mock_ser.__exit__ = MagicMock(return_value=False)
        mock_ser.read.return_value = b""
        MockSerial.return_value = mock_ser

        session = self._make_session(tmp_path)
        handler = UARTHandler(session)
        result = handler.extract(self._make_interface())
        assert result.success is False

    @patch("firmxtract.hardware.uart._flush_until_quiet")
    @patch("firmxtract.hardware.uart.serial.Serial")
    def test_uboot_prompt_returns_capture(self, MockSerial, mock_flush, tmp_path):
        """U-Boot detected → returns capture log (not firmware.bin), success=True."""
        mock_ser = MagicMock()
        mock_ser.__enter__ = lambda s: s
        mock_ser.__exit__ = MagicMock(return_value=False)
        # Initial sample triggers U-Boot detection
        mock_ser.read.return_value = b"U-Boot 2022.07\r\n=> "
        MockSerial.return_value = mock_ser
        mock_flush.return_value = b""

        session = self._make_session(tmp_path)
        handler = UARTHandler(session)
        result = handler.extract(self._make_interface())

        assert result.success is True
        assert result.method == "uart"
        assert result.firmware_path is not None
        assert "uart_capture" in result.firmware_path.name


# ---------------------------------------------------------------------------
# Hardware integration tests (require physical device)
# ---------------------------------------------------------------------------


@pytest.mark.hardware
class TestUARTHardware:
    def test_enumerate_finds_port(self):
        from firmxtract.hardware.uart import enumerate_uart_ports
        result = enumerate_uart_ports(UARTConfig())
        assert len(result) > 0, "No serial ports found — is USB adapter connected?"


# ---------------------------------------------------------------------------
# New Part B tests: baud sweep, /proc/mtd parsing, dd+base64 extraction
# ---------------------------------------------------------------------------


class TestDetectShellType:
    def test_uboot(self):
        assert _detect_shell_type(b"U-Boot 2022.07\r\n=> ") == "uboot"

    def test_busybox(self):
        assert _detect_shell_type(b"BusyBox v1.33.1\r\n# ") == "busybox"

    def test_linux(self):
        assert _detect_shell_type(b"Linux version 5.10\r\nroot@router:~# ") == "linux"

    def test_login(self):
        assert _detect_shell_type(b"OpenWrt login: ") == "login"

    def test_unknown(self):
        assert _detect_shell_type(b"some random text with no prompt") == "unknown"


class TestParseMtd:
    """Test /proc/mtd parsing via _read_proc_mtd with a mocked serial port."""

    _PROC_MTD_OUTPUT = (
        b"dev:    size   erasesize  name\n"
        b"mtd0: 00040000 00010000 \"u-boot\"\n"
        b"mtd1: 00010000 00010000 \"u-boot-env\"\n"
        b"mtd2: 00010000 00010000 \"art\"\n"
        b"mtd3: 00780000 00010000 \"firmware\"\n"
        b"mtd4: 001a0000 00010000 \"kernel\"\n"
        b"mtd5: 005e0000 00010000 \"rootfs\"\n"
    )

    def _make_mock_ser(self, response: bytes) -> MagicMock:
        ser = MagicMock()
        # _drain_prompt reads in chunks until silence; return response then empty
        reads = [response[i:i+256] for i in range(0, len(response), 256)] + [b""] * 10
        ser.read.side_effect = reads
        return ser

    def test_parses_all_partitions(self):
        from firmxtract.hardware.uart import _read_proc_mtd
        from firmxtract.utils.config import UARTConfig

        ser = self._make_mock_ser(self._PROC_MTD_OUTPUT)
        partitions = _read_proc_mtd(ser, UARTConfig())
        assert len(partitions) == 6

    def test_sorted_by_size_descending(self):
        from firmxtract.hardware.uart import _read_proc_mtd
        from firmxtract.utils.config import UARTConfig

        ser = self._make_mock_ser(self._PROC_MTD_OUTPUT)
        partitions = _read_proc_mtd(ser, UARTConfig())
        sizes = [p.size for p in partitions]
        assert sizes == sorted(sizes, reverse=True)

    def test_correct_hex_conversion(self):
        from firmxtract.hardware.uart import _read_proc_mtd
        from firmxtract.utils.config import UARTConfig

        ser = self._make_mock_ser(self._PROC_MTD_OUTPUT)
        partitions = _read_proc_mtd(ser, UARTConfig())
        # mtd3: 0x00780000 = 7,864,320 bytes
        firmware_part = next(p for p in partitions if p.name == "firmware")
        assert firmware_part.size == 0x00780000
        assert firmware_part.device == "mtd3"


class TestChooseTargetPartition:
    def _make_partition(self, name: str, size: int) -> "MtdPartition":
        from firmxtract.hardware.uart import MtdPartition
        return MtdPartition(device="mtd0", size=size, erasesize=0x10000, name=name)

    def test_firmware_name_takes_priority(self):
        from firmxtract.hardware.uart import _choose_target_partition
        parts = [
            self._make_partition("u-boot", 0x40000),
            self._make_partition("firmware", 0x780000),
            self._make_partition("rootfs", 0x5e0000),
        ]
        chosen = _choose_target_partition(parts)
        assert chosen is not None
        assert chosen.name == "firmware"

    def test_largest_when_no_name_match(self):
        from firmxtract.hardware.uart import _choose_target_partition
        parts = [
            self._make_partition("mtd0", 0x40000),
            self._make_partition("mtd1", 0x200000),
            self._make_partition("mtd2", 0x100000),
        ]
        chosen = _choose_target_partition(parts)
        assert chosen is not None
        assert chosen.size == 0x200000

    def test_empty_returns_none(self):
        from firmxtract.hardware.uart import _choose_target_partition
        assert _choose_target_partition([]) is None


class TestBase64Transfer:
    """Test dd+base64 extraction helpers."""

    def test_is_valid_base64_line_accepts_valid(self):
        from firmxtract.hardware.uart import _is_valid_base64_line
        assert _is_valid_base64_line(b"SGVsbG8gV29ybGQ=")

    def test_is_valid_base64_line_rejects_prompt(self):
        from firmxtract.hardware.uart import _is_valid_base64_line
        assert not _is_valid_base64_line(b"root@router:~# ")

    def test_is_valid_base64_line_rejects_empty(self):
        from firmxtract.hardware.uart import _is_valid_base64_line
        assert not _is_valid_base64_line(b"")

    def test_transfer_size_cap(self, tmp_path):
        from firmxtract.hardware.uart import _transfer_via_dd_base64, _MAX_TRANSFER_BYTES
        from firmxtract.utils.config import UARTConfig
        ser = MagicMock()
        ok, err = _transfer_via_dd_base64(
            ser=ser,
            device_path="/dev/mtd3",
            size_bytes=_MAX_TRANSFER_BYTES + 1,
            output_path=tmp_path / "fw.bin",
            config=UARTConfig(),
        )
        assert ok is False
        assert "cap" in err.lower() or "exceed" in err.lower()

    def test_transfer_decodes_correctly(self, tmp_path):
        """Simulate a successful dd | base64 transfer end-to-end."""
        import base64 as b64lib
        from firmxtract.hardware.uart import (
            _transfer_via_dd_base64, _XFER_START, _XFER_END
        )
        from firmxtract.utils.config import UARTConfig

        # Fake firmware content
        fake_firmware = b"\xff" * 8192 + b"\x00" * 8192
        b64_encoded = b64lib.b64encode(fake_firmware)

        # Build the "serial output" as the device would produce it
        fake_output = (
            b"\r\n" + _XFER_START + b"\n"
            + b64_encoded + b"\n"
            + _XFER_END + b"\n"
        )

        # Mock ser.read to return the fake output then silence
        chunks = [fake_output[i:i+512] for i in range(0, len(fake_output), 512)]
        chunks += [b""] * 5

        ser = MagicMock()
        ser.read.side_effect = chunks

        out = tmp_path / "firmware.bin"
        ok, err = _transfer_via_dd_base64(
            ser=ser,
            device_path="/dev/mtd3",
            size_bytes=len(fake_firmware),
            output_path=out,
            config=UARTConfig(),
        )

        assert ok is True, f"Transfer failed: {err}"
        assert out.exists()
        assert out.read_bytes() == fake_firmware
