"""
FirmXtract UART Module.

Handles:
  - Serial port enumeration (pyserial)
  - Baud rate auto-detection (sweep + heuristic scoring)
  - Shell type detection: U-Boot, Linux shell, BusyBox
  - Automated firmware extraction:
      1. Detect active shell
      2. Read /proc/mtd -> identify largest/root partition
      3. dd | base64 over serial -> decode on host -> firmware.bin
  - Interactive UART console (pass-through terminal)

Hardware safety: READ-ONLY. Never writes to flash or modifies device state.
Phase 2: baud sweep -> Rust native (firmxtract._native.uart_scanner)
"""

from __future__ import annotations

import base64
import hashlib
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import serial
import serial.tools.list_ports

from firmxtract.core.session import DetectedInterface, ExtractionResult
from firmxtract.utils.config import UARTConfig
from firmxtract.utils.logger import get_logger

if TYPE_CHECKING:
    from firmxtract.core.session import Session

log = get_logger(__name__)

_CMD_SETTLE_SECS = 0.15

_SHELL_PROMPT_PATTERNS: list[re.Pattern[bytes]] = [
    re.compile(rb"U-Boot\s+[\d.]+"),
    re.compile(rb"=>\s*$", re.MULTILINE),
    re.compile(rb"CFE>\s*$", re.MULTILINE),
    re.compile(rb"boot>\s*$", re.MULTILINE),
    re.compile(rb"(?:root|admin)@\S+[#\$]\s*"),
    re.compile(rb"\$\s*$", re.MULTILINE),
    re.compile(rb"#\s*$", re.MULTILINE),
    re.compile(rb"BusyBox\s+v[\d.]+"),
    re.compile(rb"login:\s*$", re.MULTILINE),
]

_STRONG_SIGNATURES: list[bytes] = [
    b"U-Boot", b"Linux version", b"BusyBox", b"init:", b"Starting kernel",
    b"Booting", b"root@", b"login:", b"=>", b"CFE>",
]

_MTD_HEADER = b"dev:    size   erasesize  name"
_XFER_START = b"FIRMXTRACT_BEGIN"
_XFER_END = b"FIRMXTRACT_END"
_MAX_TRANSFER_BYTES = 128 * 1024 * 1024
_FIRMWARE_PARTITION_NAMES = [
    "firmware", "firmware0", "firmware1",
    "rootfs", "root", "squashfs",
    "linux", "os-image", "image",
    "jffs2", "ubifs",
]


@dataclass
class ShellInfo:
    """Shell environment detected on the target device."""
    shell_type: str
    prompt_bytes: bytes
    has_base64: bool = False
    has_uuencode: bool = False
    has_dd: bool = False
    has_proc_mtd: bool = False


@dataclass
class MtdPartition:
    """One row from /proc/mtd."""
    device: str
    size: int
    erasesize: int
    name: str


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _score_serial_data(data: bytes) -> float:
    """Score raw bytes for likelihood of being valid UART console output (0.0-1.0)."""
    if len(data) < 8:
        return 0.0
    lower = data.lower()
    for sig in _STRONG_SIGNATURES:
        if sig.lower() in lower:
            return 1.0
    for pat in _SHELL_PROMPT_PATTERNS:
        if pat.search(data):
            return 1.0
    printable = sum(1 for b in data if 0x09 <= b <= 0x7E or b in (0x0A, 0x0D))
    ratio = printable / len(data)
    return 0.0 if ratio < 0.70 else ratio * 0.5


def _detect_shell_type(data: bytes) -> str:
    """Return shell type: uboot | busybox | login | linux | unknown."""
    lower = data.lower()
    if b"u-boot" in lower or b"=>" in data:
        return "uboot"
    if b"busybox" in lower:
        return "busybox"
    if b"login:" in lower:
        return "login"
    if b"linux version" in lower or b"root@" in lower or b"# " in data:
        return "linux"
    return "unknown"


# ---------------------------------------------------------------------------
# Port enumeration
# ---------------------------------------------------------------------------

def enumerate_uart_ports(config: UARTConfig) -> list[DetectedInterface]:
    """Enumerate serial ports and probe each for active UART output."""
    ports = list(serial.tools.list_ports.comports())
    if not ports:
        log.info("No serial ports found. Check USB adapter connection.")
        return []
    log.info(f"Found {len(ports)} serial port(s):")
    results: list[DetectedInterface] = []
    for port_info in ports:
        log.info(f"  {port_info.device}  {port_info.description}")
        active, baud_detected = _probe_port(port_info.device, config)
        results.append(DetectedInterface(
            interface_type="uart",
            port_or_device=port_info.device,
            metadata={
                "description": port_info.description,
                "hwid": port_info.hwid,
                "active_output": active,
                "detected_baudrate": baud_detected,
            },
        ))
    results.sort(key=lambda x: not x.metadata.get("active_output", False))
    return results


def _probe_port(device: str, config: UARTConfig) -> tuple[bool, int | None]:
    """Quick read at default baud to check for active console output."""
    try:
        with serial.Serial(
            port=device, baudrate=config.default_baudrate, bytesize=config.bytesize,
            parity=config.parity, stopbits=config.stopbits, timeout=config.read_timeout,
        ) as ser:
            ser.reset_input_buffer()
            ser.write(b"\r\n")
            time.sleep(0.3)
            data = ser.read(config.detection_sample_bytes)
        if data and _score_serial_data(data) > 0.5:
            return True, config.default_baudrate
        return False, None
    except serial.SerialException as exc:
        log.debug(f"  -> Cannot open {device}: {exc}")
        return False, None


# ---------------------------------------------------------------------------
# Baud rate sweep
# ---------------------------------------------------------------------------

def detect_baudrate(device: str, config: UARTConfig) -> int | None:
    """
    Sweep candidate baud rates and return the best match.

    Args:
        device: Serial device path.
        config: UARTConfig with baudrates list.

    Returns:
        Detected baud rate integer, or None.
    """
    log.info(f"Baud sweep on {device} ({len(config.baudrates)} rates)...")
    best_rate: int | None = None
    best_score: float = 0.0
    for baud in config.baudrates:
        try:
            with serial.Serial(
                port=device, baudrate=baud, bytesize=config.bytesize,
                parity=config.parity, stopbits=config.stopbits,
                timeout=config.read_timeout,
            ) as ser:
                ser.reset_input_buffer()
                ser.write(b"\r\n")
                time.sleep(0.5)
                data = ser.read(config.detection_sample_bytes)
            score = _score_serial_data(data)
            log.debug(f"  {baud:>7} baud -> score={score:.2f}")
            if score >= 1.0:
                log.info(f"[green]Baud confirmed: {baud}[/green]")
                return baud
            if score > best_score:
                best_score = score
                best_rate = baud
        except serial.SerialException as exc:
            log.debug(f"  {baud:>7} baud -> error: {exc}")
    if best_rate and best_score > 0.4:
        log.info(f"Best baud candidate: {best_rate} (score={best_score:.2f})")
        return best_rate
    log.warning("Baud sweep inconclusive.")
    return None


# ---------------------------------------------------------------------------
# Serial I/O helpers
# ---------------------------------------------------------------------------

def _serial_write_cmd(ser: serial.Serial, cmd: str) -> None:
    """Send a shell command followed by CRLF."""
    ser.write(cmd.encode() + b"\r\n")
    ser.flush()


def _serial_read_until(
    ser: serial.Serial, sentinel: bytes, timeout: float,
    max_bytes: int = 4 * 1024 * 1024,
) -> bytes:
    """Read until sentinel appears, timeout, or max_bytes reached."""
    buf = bytearray()
    deadline = time.time() + timeout
    while time.time() < deadline:
        chunk = ser.read(512)
        if chunk:
            buf.extend(chunk)
            if sentinel in buf:
                break
            if len(buf) >= max_bytes:
                log.warning(f"_serial_read_until: hit {max_bytes} byte cap")
                break
    return bytes(buf)


def _drain_prompt(ser: serial.Serial, timeout: float = 2.0) -> bytes:
    """Read until 300ms of silence. Returns everything read."""
    buf = bytearray()
    deadline = time.time() + timeout
    while time.time() < deadline:
        chunk = ser.read(256)
        if chunk:
            buf.extend(chunk)
            deadline = time.time() + 0.3
    return bytes(buf)


# ---------------------------------------------------------------------------
# Shell capability probing
# ---------------------------------------------------------------------------

def _probe_shell_capabilities(ser: serial.Serial, config: UARTConfig) -> ShellInfo:
    """
    Detect available tools on the target shell (dd, base64, /proc/mtd).

    All test commands are read-only and non-destructive.

    Args:
        ser: Connected Serial instance.
        config: UARTConfig for timeouts.

    Returns:
        ShellInfo with capability flags set.
    """
    log.info("Probing shell capabilities...")
    prompt_bytes = _drain_prompt(ser, timeout=1.5)
    shell_type = _detect_shell_type(prompt_bytes)
    log.info(f"  Shell type: [bold]{shell_type}[/bold]")
    info = ShellInfo(shell_type=shell_type, prompt_bytes=prompt_bytes)

    if shell_type == "uboot":
        return info

    _serial_write_cmd(ser, "cat /proc/mtd 2>/dev/null && echo MTD_OK")
    time.sleep(_CMD_SETTLE_SECS)
    resp = _drain_prompt(ser, timeout=config.cmd_response_timeout)
    info.has_proc_mtd = b"MTD_OK" in resp or _MTD_HEADER in resp
    log.info(f"  /proc/mtd  {'[green]OK[/green]' if info.has_proc_mtd else '[red]missing[/red]'}")

    _serial_write_cmd(ser, "dd if=/dev/null of=/dev/null 2>/dev/null && echo DD_OK")
    time.sleep(_CMD_SETTLE_SECS)
    resp = _drain_prompt(ser, timeout=config.cmd_response_timeout)
    info.has_dd = b"DD_OK" in resp or b"records" in resp
    log.info(f"  dd         {'[green]OK[/green]' if info.has_dd else '[red]missing[/red]'}")

    _serial_write_cmd(ser, "echo dGVzdA== | base64 -d 2>/dev/null && echo B64_OK")
    time.sleep(_CMD_SETTLE_SECS)
    resp = _drain_prompt(ser, timeout=config.cmd_response_timeout)
    info.has_base64 = b"B64_OK" in resp or b"test" in resp
    log.info(f"  base64     {'[green]OK[/green]' if info.has_base64 else '[red]missing[/red]'}")

    if not info.has_base64:
        _serial_write_cmd(ser, "echo test | uuencode -m - 2>/dev/null && echo UU_OK")
        time.sleep(_CMD_SETTLE_SECS)
        resp = _drain_prompt(ser, timeout=config.cmd_response_timeout)
        info.has_uuencode = b"UU_OK" in resp
        log.info(
            f"  uuencode   "
            f"{'[green]OK[/green]' if info.has_uuencode else '[red]missing[/red]'}"
        )

    return info


# ---------------------------------------------------------------------------
# /proc/mtd parsing
# ---------------------------------------------------------------------------

def _read_proc_mtd(ser: serial.Serial, config: UARTConfig) -> list[MtdPartition]:
    """
    Read and parse /proc/mtd from the target.

    Returns:
        Partitions sorted by size descending.
    """
    _serial_write_cmd(ser, "cat /proc/mtd")
    time.sleep(_CMD_SETTLE_SECS)
    raw = _drain_prompt(ser, timeout=config.cmd_response_timeout)
    log.debug(f"/proc/mtd raw:\n{raw.decode(errors='replace')}")

    partitions: list[MtdPartition] = []
    for line in raw.decode(errors="replace").splitlines():
        m = re.match(
            r"(mtd\d+):\s+([0-9a-f]+)\s+([0-9a-f]+)\s+\"([^\"]+)\"",
            line.strip(), re.I,
        )
        if m:
            partitions.append(MtdPartition(
                device=m.group(1), size=int(m.group(2), 16),
                erasesize=int(m.group(3), 16), name=m.group(4).lower(),
            ))

    log.info(f"  {len(partitions)} MTD partition(s):")
    for p in partitions:
        log.info(f"    /dev/{p.device:<8} {p.size // 1024:>6} KB  [{p.name}]")
    return sorted(partitions, key=lambda p: p.size, reverse=True)


def _choose_target_partition(partitions: list[MtdPartition]) -> MtdPartition | None:
    """Select best partition: priority name match, else largest."""
    if not partitions:
        return None
    for priority_name in _FIRMWARE_PARTITION_NAMES:
        for p in partitions:
            if priority_name in p.name:
                log.info(f"  Target: /dev/{p.device} [{p.name}] ({p.size // 1024} KB)")
                return p
    chosen = partitions[0]
    log.info(f"  Target: /dev/{chosen.device} [{chosen.name}] ({chosen.size // 1024} KB) — largest")
    return chosen


# ---------------------------------------------------------------------------
# dd + base64 transfer
# ---------------------------------------------------------------------------

def _is_valid_base64_line(line: bytes) -> bool:
    """Return True if line contains only valid base64 characters."""
    VALID = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    return len(line) > 0 and all(b in VALID for b in line)


def _transfer_via_dd_base64(
    ser: serial.Serial,
    device_path: str,
    size_bytes: int,
    output_path: Path,
    config: UARTConfig,
) -> tuple[bool, str]:
    """
    Transfer a block device over UART via: dd if=<dev> bs=4096 | base64

    Protocol:
      - Host sends command wrapping output with FIRMXTRACT_BEGIN/END sentinels
      - Device streams base64-encoded firmware
      - Host decodes and writes firmware.bin

    Args:
        ser: Connected Serial instance.
        device_path: Target device node (e.g. /dev/mtd3).
        size_bytes: Expected size for safety cap check.
        output_path: Host output path for decoded binary.
        config: UARTConfig for timeouts.

    Returns:
        (success, error_message)
    """
    if size_bytes > _MAX_TRANSFER_BYTES:
        return False, (
            f"Partition {size_bytes // (1024 ** 2)} MB exceeds "
            f"safety cap {_MAX_TRANSFER_BYTES // (1024 ** 2)} MB"
        )

    cmd = (
        f"echo {_XFER_START.decode()}; "
        f"dd if={device_path} bs=4096 2>/dev/null | base64; "
        f"echo {_XFER_END.decode()}"
    )

    size_mb = size_bytes / (1024 * 1024)
    log.info(f"Transfer: {device_path} ({size_mb:.1f} MB) — do not interrupt...")
    _serial_write_cmd(ser, cmd)

    raw = _serial_read_until(
        ser, sentinel=_XFER_END,
        timeout=config.extraction_timeout,
        max_bytes=_MAX_TRANSFER_BYTES * 2,
    )

    start_idx = raw.find(_XFER_START)
    end_idx = raw.find(_XFER_END)

    if start_idx == -1:
        return False, "Start sentinel not found — command may not have executed"
    if end_idx == -1:
        return False, "End sentinel not found — transfer likely interrupted"

    nl_idx = raw.index(b"\n", start_idx) + 1
    b64_payload = raw[nl_idx:end_idx].strip()

    if not b64_payload:
        return False, "Empty base64 payload between sentinels"

    log.info(f"  {len(b64_payload):,} base64 bytes received — decoding...")
    clean_b64 = b"".join(
        line.strip() for line in b64_payload.splitlines()
        if line.strip() and _is_valid_base64_line(line.strip())
    )

    try:
        firmware_bytes = base64.b64decode(clean_b64, validate=False)
    except Exception as exc:
        return False, f"base64 decode failed: {exc}"

    if len(firmware_bytes) < 1024:
        return False, f"Decoded size too small ({len(firmware_bytes)}B) — likely corrupt"

    output_path.write_bytes(firmware_bytes)
    log.info(f"  [green]Transfer complete[/green]: {len(firmware_bytes):,} bytes")
    return True, ""


# ---------------------------------------------------------------------------
# UARTHandler
# ---------------------------------------------------------------------------

class UARTHandler:
    """
    Coordinates the full UART firmware extraction pipeline.

    Stages (all read-only):
      1. Connect + confirm/sweep baud rate
      2. Wait for shell prompt
      3. Probe shell capabilities (dd, base64, /proc/mtd)
      4. Parse /proc/mtd -> choose target partition
      5. Transfer via dd | base64 -> firmware.bin
      6. Graceful fallback to boot log at any failure point
    """

    def __init__(self, session: "Session") -> None:
        self.session = session
        self.config = session.config.uart

    def extract(self, interface: DetectedInterface) -> ExtractionResult:
        """
        Run UART extraction for the given interface.

        Args:
            interface: DetectedInterface of type "uart".

        Returns:
            ExtractionResult with firmware.bin on success,
            or uart_capture.log as partial result on fallback.
        """
        device = interface.port_or_device
        baud: int = (
            interface.metadata.get("detected_baudrate") or self.config.default_baudrate
        )
        log.info(f"UART extraction: {device} @ {baud} baud")
        try:
            return self._run_extraction(device, baud)
        except serial.SerialException as exc:
            return ExtractionResult(
                success=False, method="uart",
                error_message=f"Serial port error: {exc}",
            )
        except Exception as exc:
            log.warning(f"Unexpected UART error: {exc}", exc_info=True)
            return ExtractionResult(
                success=False, method="uart",
                error_message=f"Unexpected error: {exc}",
            )

    def _run_extraction(self, device: str, baud: int) -> ExtractionResult:
        """Open port and drive the full 5-stage pipeline."""
        capture_log = self.session.output_dir / "uart_capture.log"
        firmware_out = self.session.output_dir / "firmware.bin"

        with serial.Serial(
            port=device, baudrate=baud, bytesize=self.config.bytesize,
            parity=self.config.parity, stopbits=self.config.stopbits,
            timeout=1.0,
        ) as ser:
            baud = self._confirm_or_sweep_baud(ser, device, baud)

            captured, prompt_ok = self._wait_for_prompt(ser, capture_log)
            if not prompt_ok:
                return ExtractionResult(
                    success=False, method="uart",
                    error_message=(
                        f"No shell prompt within {self.config.shell_prompt_timeout:.0f}s. "
                        f"Boot log: {capture_log}."
                    ),
                )

            shell_type = _detect_shell_type(captured)
            log.info(f"Shell: [bold]{shell_type}[/bold]")
            self.session.add_note(f"UART: {shell_type} on {device}@{baud}")

            if shell_type == "uboot":
                return self._handle_uboot(captured, capture_log)

            shell_info = _probe_shell_capabilities(ser, self.config)

            if not shell_info.has_proc_mtd:
                return self._fallback_capture(captured, capture_log, "/proc/mtd not available")

            partitions = _read_proc_mtd(ser, self.config)
            target = _choose_target_partition(partitions)
            if target is None:
                return self._fallback_capture(captured, capture_log, "Could not parse /proc/mtd")

            can_transfer = shell_info.has_dd and (shell_info.has_base64 or shell_info.has_uuencode)
            if not can_transfer:
                return self._fallback_capture(
                    captured, capture_log, "dd or base64/uuencode missing on target"
                )

            ok, err = _transfer_via_dd_base64(
                ser=ser, device_path=f"/dev/{target.device}",
                size_bytes=target.size, output_path=firmware_out,
                config=self.config,
            )

        if ok and firmware_out.exists() and firmware_out.stat().st_size > 0:
            checksum = _sha256(firmware_out)
            size = firmware_out.stat().st_size
            log.info(f"[green bold]Firmware extracted[/green bold]: {size:,}B  SHA256={checksum[:16]}...")
            self.session.add_note(
                f"UART dd: /dev/{target.device} [{target.name}], {size:,}B, SHA256={checksum}"
            )
            return ExtractionResult(
                success=True, method="uart",
                firmware_path=firmware_out,
                size_bytes=size,
                checksum_sha256=checksum,
            )

        return self._fallback_capture(captured, capture_log, err or "Transfer produced empty output")

    def _confirm_or_sweep_baud(self, ser: serial.Serial, device: str, baud: int) -> int:
        """Validate baud rate by sampling; sweep if it looks like garbage."""
        ser.reset_input_buffer()
        ser.write(b"\r\n")
        time.sleep(0.4)
        sample = ser.read(self.config.detection_sample_bytes)
        if _score_serial_data(sample) >= 0.5:
            return baud
        log.info(f"Baud {baud} looks wrong — running sweep...")
        detected = detect_baudrate(device, self.config)
        if detected and detected != baud:
            ser.baudrate = detected
            return detected
        log.warning(f"Sweep inconclusive — staying at {baud}.")
        return baud

    def _wait_for_prompt(self, ser: serial.Serial, capture_log: Path) -> tuple[bytes, bool]:
        """
        Read until shell prompt detected or timeout.

        Returns:
            (all_captured_bytes, prompt_was_detected)
        """
        buf = bytearray()
        deadline = time.time() + self.config.shell_prompt_timeout
        prompt_detected = False
        log.info(f"Waiting for prompt ({self.config.shell_prompt_timeout:.0f}s timeout)...")
        ser.reset_input_buffer()
        ser.write(b"\r\n")

        while time.time() < deadline:
            chunk = ser.read(256)
            if chunk:
                buf.extend(chunk)
                if _score_serial_data(bytes(buf[-1024:])) >= 1.0:
                    prompt_detected = True
                    time.sleep(0.5)
                    buf.extend(ser.read(512))
                    break
            else:
                elapsed = deadline - time.time()
                if elapsed % 5 < 1.0:
                    ser.write(b"\r\n")

        captured = bytes(buf)
        capture_log.write_bytes(captured)
        log.info(f"Boot log: {capture_log} ({len(captured):,} bytes)")
        return captured, prompt_detected

    def _handle_uboot(self, captured: bytes, capture_log: Path) -> ExtractionResult:
        """Handle U-Boot detection — save log, advise manual workflow."""
        self.session.add_note(
            "U-Boot detected. Use 'firmxtract console' to interact. "
            "Automated U-Boot memory dump is Phase 2."
        )
        log.info(
            "[yellow]U-Boot console detected.[/yellow] "
            "Use [bold]firmxtract console --port <port>[/bold] to interact manually."
        )
        return ExtractionResult(
            success=True, method="uart",
            firmware_path=capture_log,
            size_bytes=len(captured),
            checksum_sha256=hashlib.sha256(captured).hexdigest(),
        )

    def _fallback_capture(self, captured: bytes, capture_log: Path, reason: str) -> ExtractionResult:
        """
        Return boot-log-only result when full extraction is not possible.

        success=True because the shell was reached (partial success).
        Orchestrator can still run binwalk on the capture log.
        """
        log.warning(f"Full firmware dump not possible: {reason}")
        log.info("Returning boot log as partial extraction result.")
        self.session.add_note(f"UART fallback: {reason}")
        if not captured:
            return ExtractionResult(success=False, method="uart", error_message=reason)
        return ExtractionResult(
            success=True, method="uart",
            firmware_path=capture_log,
            size_bytes=len(captured),
            checksum_sha256=hashlib.sha256(captured).hexdigest(),
        )


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _sha256(path: Path) -> str:
    """Compute SHA256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Interactive UART console
# ---------------------------------------------------------------------------

class UARTConsole:
    """
    Interactive pass-through terminal for a serial port.

    Device output -> stdout; stdin -> device. Press Ctrl+] to exit.
    """

    EXIT_CHAR = b"\x1d"

    def __init__(self, port: str, baudrate: int, uart_config: UARTConfig) -> None:
        self.port = port
        self.baudrate = baudrate
        self.config = uart_config

    def run(self) -> None:
        """Start interactive session. Blocks until user exits."""
        import sys
        import threading

        try:
            ser = serial.Serial(
                port=self.port, baudrate=self.baudrate, bytesize=self.config.bytesize,
                parity=self.config.parity, stopbits=self.config.stopbits, timeout=0.1,
            )
        except serial.SerialException as exc:
            log.error(f"Cannot open {self.port}: {exc}")
            return

        log.info(f"[green]Connected[/green] {self.port} @ {self.baudrate} baud. Ctrl+] to exit.")
        stop_event = threading.Event()

        def _reader() -> None:
            while not stop_event.is_set():
                try:
                    data = ser.read(256)
                    if data:
                        sys.stdout.buffer.write(data)
                        sys.stdout.buffer.flush()
                except serial.SerialException:
                    log.warning("Serial port disconnected.")
                    stop_event.set()

        threading.Thread(target=_reader, daemon=True).start()
        try:
            _set_raw_mode()
            while not stop_event.is_set():
                try:
                    ch = sys.stdin.buffer.read(1)
                    if not ch or ch == self.EXIT_CHAR:
                        break
                    ser.write(ch)
                except (KeyboardInterrupt, EOFError):
                    break
        finally:
            stop_event.set()
            _restore_terminal()
            ser.close()
            log.info("Console session ended.")


# ---------------------------------------------------------------------------
# Terminal raw mode (POSIX only)
# ---------------------------------------------------------------------------

_uart_terminal_state: dict[str, object] = {}


def _set_raw_mode() -> None:
    """Switch stdin to raw mode. No-op on Windows or non-TTY."""
    import sys
    if not sys.stdin.isatty():
        return
    try:
        import termios, tty
        fd = sys.stdin.fileno()
        _uart_terminal_state["settings"] = termios.tcgetattr(fd)
        _uart_terminal_state["fd"] = fd
        tty.setraw(fd)
    except (ImportError, Exception):
        pass


def _restore_terminal() -> None:
    """Restore terminal settings saved by _set_raw_mode()."""
    try:
        import termios
        if "settings" in _uart_terminal_state:
            termios.tcsetattr(
                _uart_terminal_state["fd"],  # type: ignore[arg-type]
                termios.TCSADRAIN,
                _uart_terminal_state["settings"],
            )
    except (ImportError, Exception):
        pass
