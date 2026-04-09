"""
Integration tests for firmxtract.core.orchestrator

Tests the full pipeline wiring without any real hardware.
All external calls (UARTHandler, SPIHandler, BinwalkWrapper, SecretsHunter,
HAL.detect_interfaces) are patched at the boundary.

Test matrix:
  - UART success  → full pipeline (binwalk + secrets)
  - UART fail + SPI success → fallback path
  - UART fail + SPI fail → both fail
  - No interfaces detected → graceful failure
  - skip_analyze flag → extraction only
  - KeyboardInterrupt during pipeline → handled cleanly
  - Unhandled exception during pipeline → handled cleanly
  - Session report written after every run
  - run_with_interfaces() skips detection stage
  - Secrets scan uses extracted_dir when available
  - Secrets scan falls back to firmware file when no extracted_dir
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from firmxtract.core.orchestrator import Orchestrator
from firmxtract.core.session import (
    AnalysisResult,
    DetectedInterface,
    ExtractionResult,
    Session,
)
from tests.mocks import (
    make_session,
    make_uart_interface,
    make_spi_interface,
    mock_successful_uart_result,
    mock_failed_uart_result,
    mock_successful_spi_result,
    mock_failed_spi_result,
    mock_binwalk_result,
    mock_failed_binwalk_result,
    mock_secrets_result,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_firmware(tmp_path: Path, name: str = "firmware.bin") -> Path:
    """Write a small fake firmware file and return its path."""
    p = tmp_path / "sessions" / "test_session" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"\xff" * 1024)
    return p


def _patch_all(
    hal_interfaces: list[DetectedInterface] | None = None,
    uart_result: ExtractionResult | None = None,
    spi_result: ExtractionResult | None = None,
    binwalk_result: AnalysisResult | None = None,
    secrets_result: AnalysisResult | None = None,
):
    """
    Context manager: patch every external dependency of the Orchestrator.

    Returns a dict of the mock objects so tests can inspect calls.
    """
    import contextlib

    @contextlib.contextmanager
    def _ctx():
        with (
            patch(
                "firmxtract.core.orchestrator.HAL.detect_interfaces",
                return_value=hal_interfaces or [],
            ) as mock_hal,
            patch(
                "firmxtract.core.orchestrator.UARTHandler.extract",
                return_value=uart_result or mock_failed_uart_result(),
            ) as mock_uart,
            patch(
                "firmxtract.core.orchestrator.SPIHandler.extract",
                return_value=spi_result or mock_failed_spi_result(),
            ) as mock_spi,
            patch(
                "firmxtract.core.orchestrator.BinwalkWrapper.analyze",
                return_value=binwalk_result or mock_failed_binwalk_result(),
            ) as mock_binwalk,
            patch(
                "firmxtract.core.orchestrator.SecretsHunter.analyze",
                return_value=secrets_result or mock_secrets_result(0),
            ) as mock_secrets,
        ):
            yield {
                "hal": mock_hal,
                "uart": mock_uart,
                "spi": mock_spi,
                "binwalk": mock_binwalk,
                "secrets": mock_secrets,
            }

    return _ctx()


# ---------------------------------------------------------------------------
# Stage 1: Hardware detection
# ---------------------------------------------------------------------------


class TestStageDetectHardware:
    def test_no_interfaces_logged(self, tmp_path):
        session = make_session(tmp_path)
        with _patch_all(hal_interfaces=[]) as mocks:
            orch = Orchestrator(session)
            orch._stage_detect_hardware()

        assert session.detected_interfaces == []
        assert any("no interfaces found" in n.lower() for n in session.notes)

    def test_detected_interfaces_added_to_session(self, tmp_path):
        session = make_session(tmp_path)
        ifaces = [make_uart_interface(), make_spi_interface()]
        with _patch_all(hal_interfaces=ifaces):
            orch = Orchestrator(session)
            orch._stage_detect_hardware()

        assert len(session.detected_interfaces) == 2
        assert session.detected_interfaces[0].interface_type == "uart"
        assert session.detected_interfaces[1].interface_type == "spi"


# ---------------------------------------------------------------------------
# Stage 2: Firmware extraction
# ---------------------------------------------------------------------------


class TestStageExtractFirmware:
    def test_uart_success_returns_true(self, tmp_path):
        session = make_session(tmp_path)
        fw = _make_firmware(tmp_path)
        session.detected_interfaces.append(make_uart_interface())

        with _patch_all(uart_result=mock_successful_uart_result(fw)) as mocks:
            orch = Orchestrator(session)
            result = orch._stage_extract_firmware()

        assert result is True
        assert session.extraction_result is not None
        assert session.extraction_result.success is True
        assert session.extraction_result.method == "uart"
        mocks["spi"].assert_not_called()  # fallback never triggered

    def test_uart_fail_falls_back_to_spi(self, tmp_path):
        session = make_session(tmp_path)
        fw = _make_firmware(tmp_path)
        session.detected_interfaces.extend([
            make_uart_interface(),
            make_spi_interface(),
        ])

        with _patch_all(
            uart_result=mock_failed_uart_result("No signal"),
            spi_result=mock_successful_spi_result(fw),
        ) as mocks:
            orch = Orchestrator(session)
            result = orch._stage_extract_firmware()

        assert result is True
        assert session.extraction_result.method == "spi"
        mocks["uart"].assert_called_once()
        mocks["spi"].assert_called_once()

    def test_both_fail_returns_false(self, tmp_path):
        session = make_session(tmp_path)
        session.detected_interfaces.extend([
            make_uart_interface(),
            make_spi_interface(),
        ])

        with _patch_all(
            uart_result=mock_failed_uart_result(),
            spi_result=mock_failed_spi_result(),
        ):
            orch = Orchestrator(session)
            result = orch._stage_extract_firmware()

        assert result is False
        assert session.extraction_result.success is False

    def test_no_interfaces_returns_false(self, tmp_path):
        session = make_session(tmp_path)
        # No interfaces seeded

        with _patch_all():
            orch = Orchestrator(session)
            result = orch._stage_extract_firmware()

        assert result is False

    def test_spi_only_skips_uart(self, tmp_path):
        """If only SPI is detected, UART handler is never called."""
        session = make_session(tmp_path)
        fw = _make_firmware(tmp_path)
        session.detected_interfaces.append(make_spi_interface())

        with _patch_all(spi_result=mock_successful_spi_result(fw)) as mocks:
            orch = Orchestrator(session)
            orch._stage_extract_firmware()

        mocks["uart"].assert_not_called()
        mocks["spi"].assert_called_once()


# ---------------------------------------------------------------------------
# Stage 3: Firmware analysis (binwalk)
# ---------------------------------------------------------------------------


class TestStageAnalyzeFirmware:
    def test_binwalk_called_with_firmware_path(self, tmp_path):
        session = make_session(tmp_path)
        fw = _make_firmware(tmp_path)
        session.extraction_result = mock_successful_uart_result(fw)

        bw_result = mock_binwalk_result(findings=5)
        with _patch_all(binwalk_result=bw_result) as mocks:
            orch = Orchestrator(session)
            orch._stage_analyze_firmware()

        mocks["binwalk"].assert_called_once_with(fw)
        assert len(session.analysis_results) == 1
        assert session.analysis_results[0].tool == "binwalk"
        assert len(session.analysis_results[0].findings) == 5

    def test_no_firmware_path_skips_gracefully(self, tmp_path):
        session = make_session(tmp_path)
        # extraction_result is None

        with _patch_all() as mocks:
            orch = Orchestrator(session)
            orch._stage_analyze_firmware()

        mocks["binwalk"].assert_not_called()
        assert session.analysis_results == []


# ---------------------------------------------------------------------------
# Stage 4: Secrets scan
# ---------------------------------------------------------------------------


class TestStageScanSecrets:
    def test_uses_binwalk_extracted_dir(self, tmp_path):
        session = make_session(tmp_path)
        fw = _make_firmware(tmp_path)
        extracted = tmp_path / "extracted"
        extracted.mkdir()

        session.extraction_result = mock_successful_uart_result(fw)
        session.analysis_results.append(mock_binwalk_result(extracted_dir=extracted))

        secrets = mock_secrets_result(n_findings=3)
        with _patch_all(secrets_result=secrets) as mocks:
            orch = Orchestrator(session)
            orch._stage_scan_secrets()

        mocks["secrets"].assert_called_once_with(extracted)

    def test_falls_back_to_firmware_file_when_no_extracted_dir(self, tmp_path):
        session = make_session(tmp_path)
        fw = _make_firmware(tmp_path)
        session.extraction_result = mock_successful_uart_result(fw)
        # binwalk result with no extracted_dir
        session.analysis_results.append(mock_binwalk_result(extracted_dir=None))

        with _patch_all() as mocks:
            orch = Orchestrator(session)
            orch._stage_scan_secrets()

        mocks["secrets"].assert_called_once_with(fw)

    def test_skips_when_no_extraction_result(self, tmp_path):
        session = make_session(tmp_path)

        with _patch_all() as mocks:
            orch = Orchestrator(session)
            orch._stage_scan_secrets()

        mocks["secrets"].assert_not_called()

    def test_findings_added_to_session(self, tmp_path):
        session = make_session(tmp_path)
        fw = _make_firmware(tmp_path)
        session.extraction_result = mock_successful_uart_result(fw)
        session.analysis_results.append(mock_binwalk_result(extracted_dir=None))

        with _patch_all(secrets_result=mock_secrets_result(n_findings=4)):
            orch = Orchestrator(session)
            orch._stage_scan_secrets()

        secrets_results = [r for r in session.analysis_results if r.tool == "secrets"]
        assert len(secrets_results) == 1
        assert len(secrets_results[0].findings) == 4


# ---------------------------------------------------------------------------
# Full pipeline: run()
# ---------------------------------------------------------------------------


class TestOrchestratorRun:
    def test_full_success_pipeline(self, tmp_path):
        """UART success → binwalk → secrets → finalize. Returns True."""
        session = make_session(tmp_path)
        fw = _make_firmware(tmp_path)
        extracted = tmp_path / "extracted"
        extracted.mkdir()

        with _patch_all(
            hal_interfaces=[make_uart_interface()],
            uart_result=mock_successful_uart_result(fw),
            binwalk_result=mock_binwalk_result(extracted_dir=extracted, findings=2),
            secrets_result=mock_secrets_result(n_findings=1),
        ) as mocks:
            orch = Orchestrator(session)
            success = orch.run()

        assert success is True
        assert session.firmware_extracted is True
        # All four stages ran
        mocks["hal"].assert_called_once()
        mocks["uart"].assert_called_once()
        mocks["binwalk"].assert_called_once()
        mocks["secrets"].assert_called_once()
        # Session finalized
        assert session.ended_at is not None
        # Report written
        assert (session.output_dir / "report.json").exists()

    def test_no_hardware_returns_false(self, tmp_path):
        session = make_session(tmp_path)

        with _patch_all(hal_interfaces=[]):
            orch = Orchestrator(session)
            success = orch.run()

        assert success is False
        assert (session.output_dir / "report.json").exists()  # report still written

    def test_uart_fail_spi_success(self, tmp_path):
        session = make_session(tmp_path)
        fw = _make_firmware(tmp_path)

        with _patch_all(
            hal_interfaces=[make_uart_interface(), make_spi_interface()],
            uart_result=mock_failed_uart_result("timeout"),
            spi_result=mock_successful_spi_result(fw),
            binwalk_result=mock_binwalk_result(),
            secrets_result=mock_secrets_result(0),
        ) as mocks:
            orch = Orchestrator(session)
            success = orch.run()

        assert success is True
        assert session.extraction_result.method == "spi"

    def test_both_fail_returns_false_and_writes_report(self, tmp_path):
        session = make_session(tmp_path)

        with _patch_all(
            hal_interfaces=[make_uart_interface(), make_spi_interface()],
            uart_result=mock_failed_uart_result(),
            spi_result=mock_failed_spi_result(),
        ):
            orch = Orchestrator(session)
            success = orch.run()

        assert success is False
        report = session.output_dir / "report.json"
        assert report.exists()
        data = json.loads(report.read_text())
        assert data["extraction"] is not None
        assert data["extraction"]["success"] is False

    def test_keyboard_interrupt_handled(self, tmp_path):
        session = make_session(tmp_path)

        with patch(
            "firmxtract.core.orchestrator.HAL.detect_interfaces",
            side_effect=KeyboardInterrupt,
        ):
            orch = Orchestrator(session)
            success = orch.run()

        assert success is False
        assert any("interrupted" in n.lower() for n in session.notes)
        assert (session.output_dir / "report.json").exists()

    def test_unhandled_exception_handled(self, tmp_path):
        session = make_session(tmp_path)

        with patch(
            "firmxtract.core.orchestrator.HAL.detect_interfaces",
            side_effect=RuntimeError("disk full"),
        ):
            orch = Orchestrator(session)
            success = orch.run()

        assert success is False
        assert any("disk full" in n for n in session.notes)
        assert (session.output_dir / "report.json").exists()

    def test_analyze_skipped_when_extraction_fails(self, tmp_path):
        """binwalk and secrets must NOT run if extraction failed."""
        session = make_session(tmp_path)

        with _patch_all(
            hal_interfaces=[make_uart_interface()],
            uart_result=mock_failed_uart_result(),
        ) as mocks:
            orch = Orchestrator(session)
            orch.run()

        mocks["binwalk"].assert_not_called()
        mocks["secrets"].assert_not_called()


# ---------------------------------------------------------------------------
# run_with_interfaces()
# ---------------------------------------------------------------------------


class TestRunWithInterfaces:
    def test_skips_hal_detection(self, tmp_path):
        session = make_session(tmp_path)
        fw = _make_firmware(tmp_path)
        session.detected_interfaces.append(make_uart_interface())

        with _patch_all(
            uart_result=mock_successful_uart_result(fw),
            binwalk_result=mock_binwalk_result(),
            secrets_result=mock_secrets_result(0),
        ) as mocks:
            orch = Orchestrator(session)
            success = orch.run_with_interfaces()

        assert success is True
        mocks["hal"].assert_not_called()
        mocks["uart"].assert_called_once()

    def test_skip_analyze_flag(self, tmp_path):
        """skip_analyze=True means binwalk and secrets are never called."""
        session = make_session(tmp_path)
        fw = _make_firmware(tmp_path)
        session.detected_interfaces.append(make_uart_interface())

        with _patch_all(uart_result=mock_successful_uart_result(fw)) as mocks:
            orch = Orchestrator(session)
            success = orch.run_with_interfaces(skip_analyze=True)

        assert success is True
        mocks["binwalk"].assert_not_called()
        mocks["secrets"].assert_not_called()

    def test_finalize_always_called(self, tmp_path):
        session = make_session(tmp_path)
        session.detected_interfaces.append(make_uart_interface())

        with _patch_all(uart_result=mock_failed_uart_result()):
            orch = Orchestrator(session)
            orch.run_with_interfaces()

        assert session.ended_at is not None
        assert (session.output_dir / "report.json").exists()

    def test_keyboard_interrupt_handled(self, tmp_path):
        session = make_session(tmp_path)
        session.detected_interfaces.append(make_uart_interface())

        with patch(
            "firmxtract.core.orchestrator.UARTHandler.extract",
            side_effect=KeyboardInterrupt,
        ):
            orch = Orchestrator(session)
            success = orch.run_with_interfaces()

        assert success is False
        assert (session.output_dir / "report.json").exists()


# ---------------------------------------------------------------------------
# Report content validation
# ---------------------------------------------------------------------------


class TestSessionReport:
    def test_report_contains_all_sections(self, tmp_path):
        session = make_session(tmp_path)
        fw = _make_firmware(tmp_path)

        with _patch_all(
            hal_interfaces=[make_uart_interface()],
            uart_result=mock_successful_uart_result(fw),
            binwalk_result=mock_binwalk_result(findings=3),
            secrets_result=mock_secrets_result(n_findings=2),
        ):
            orch = Orchestrator(session)
            orch.run()

        report_path = session.output_dir / "report.json"
        assert report_path.exists()
        data = json.loads(report_path.read_text())

        assert "session_id" in data
        assert "started_at" in data
        assert "ended_at" in data
        assert "duration_seconds" in data
        assert "output_dir" in data
        assert "detected_interfaces" in data
        assert "extraction" in data
        assert "analysis" in data
        assert "notes" in data

    def test_report_extraction_fields(self, tmp_path):
        session = make_session(tmp_path)
        fw = _make_firmware(tmp_path)

        with _patch_all(
            hal_interfaces=[make_uart_interface()],
            uart_result=mock_successful_uart_result(fw),
            binwalk_result=mock_binwalk_result(),
            secrets_result=mock_secrets_result(0),
        ):
            orch = Orchestrator(session)
            orch.run()

        data = json.loads((session.output_dir / "report.json").read_text())
        ext = data["extraction"]
        assert ext["success"] is True
        assert ext["method"] == "uart"
        assert ext["checksum_sha256"] == "a" * 64

    def test_report_analysis_tools_listed(self, tmp_path):
        session = make_session(tmp_path)
        fw = _make_firmware(tmp_path)

        with _patch_all(
            hal_interfaces=[make_uart_interface()],
            uart_result=mock_successful_uart_result(fw),
            binwalk_result=mock_binwalk_result(findings=2),
            secrets_result=mock_secrets_result(n_findings=1),
        ):
            orch = Orchestrator(session)
            orch.run()

        data = json.loads((session.output_dir / "report.json").read_text())
        tools = [r["tool"] for r in data["analysis"]]
        assert "binwalk" in tools
        assert "secrets" in tools

    def test_report_is_valid_json(self, tmp_path):
        session = make_session(tmp_path)

        with _patch_all(hal_interfaces=[]):
            orch = Orchestrator(session)
            orch.run()

        report_path = session.output_dir / "report.json"
        # Should not raise
        data = json.loads(report_path.read_text())
        assert isinstance(data, dict)

    def test_duration_is_positive(self, tmp_path):
        session = make_session(tmp_path)
        fw = _make_firmware(tmp_path)

        with _patch_all(
            hal_interfaces=[make_uart_interface()],
            uart_result=mock_successful_uart_result(fw),
            binwalk_result=mock_binwalk_result(),
            secrets_result=mock_secrets_result(0),
        ):
            orch = Orchestrator(session)
            orch.run()

        data = json.loads((session.output_dir / "report.json").read_text())
        assert data["duration_seconds"] is not None
        assert data["duration_seconds"] >= 0.0
