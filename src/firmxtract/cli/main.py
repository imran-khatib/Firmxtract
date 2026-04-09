"""
FirmXtract CLI — entry point.

Commands:
  firmxtract extract   Run full extraction pipeline (detect → dump → analyze)
  firmxtract analyze   Re-analyze an existing firmware dump (no hardware needed)
  firmxtract console   Open interactive UART console on a serial port
  firmxtract report    Display the most recent session report
  firmxtract info      Show system info: tool versions, serial ports
  firmxtract version   Print version and exit

Usage examples:
  firmxtract extract
  firmxtract extract --port /dev/ttyUSB0 --baud 115200
  firmxtract extract --method spi --programmer ch341a_spi
  firmxtract analyze firmware.bin
  firmxtract console --port /dev/ttyUSB0
  firmxtract report
  firmxtract info
"""

from __future__ import annotations

import shutil
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from firmxtract import get_version
from firmxtract.utils.config import get_config
from firmxtract.utils.logger import get_logger, setup_logging

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="firmxtract",
    help=(
        "[bold]FirmXtract[/bold] — Unified IoT Firmware Extraction, "
        "Analysis & Red-Teaming Framework"
    ),
    rich_markup_mode="rich",
    no_args_is_help=True,
    add_completion=True,
)

console = Console()
log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Shared option types
# ---------------------------------------------------------------------------


class ExtractionMethod(str, Enum):
    """Firmware extraction method."""

    AUTO = "auto"
    UART = "uart"
    SPI = "spi"


# ---------------------------------------------------------------------------
# Global options callback (runs before any command)
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def _global_options(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug output."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Errors only."),
) -> None:
    """FirmXtract — IoT firmware extraction and analysis."""
    import logging

    level = logging.INFO
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.ERROR
    setup_logging(level=level)

    # Show banner + help when no subcommand given
    if ctx.invoked_subcommand is None:
        _print_banner()
        console.print(ctx.get_help())


# ---------------------------------------------------------------------------
# firmxtract extract
# ---------------------------------------------------------------------------


@app.command()
def extract(
    port: str | None = typer.Option(
        None, "--port", "-p",
        help="Serial port for UART (e.g. /dev/ttyUSB0). Auto-detected if omitted.",
    ),
    baudrate: int | None = typer.Option(
        None, "--baud", "-b",
        help="UART baud rate. Auto-detected if omitted.",
    ),
    method: ExtractionMethod = typer.Option(
        ExtractionMethod.AUTO, "--method", "-m",
        help="Extraction method: auto (UART then SPI fallback), uart, or spi.",
    ),
    programmer: str | None = typer.Option(
        None, "--programmer",
        help="flashrom programmer string (e.g. ch341a_spi). Auto-detected if omitted.",
    ),
    output_dir: Path | None = typer.Option(
        None, "--output-dir", "-o",
        help="Session output directory. Default: ~/.firmxtract/sessions/<timestamp>/",
    ),
    no_analyze: bool = typer.Option(
        False, "--no-analyze",
        help="Skip binwalk analysis after extraction.",
    ),
) -> None:
    """
    [bold]Run the full extraction pipeline.[/bold]

    Auto-detects hardware, extracts firmware, and analyzes with binwalk.
    UART is tried first; SPI is used as fallback (or force with --method spi).

    Examples:

      [dim]# Auto-detect everything[/dim]
      firmxtract extract

      [dim]# Specific UART port[/dim]
      firmxtract extract --port /dev/ttyUSB0 --baud 115200

      [dim]# Force SPI with ch341a[/dim]
      firmxtract extract --method spi --programmer ch341a_spi
    """
    from firmxtract.core.orchestrator import Orchestrator
    from firmxtract.core.session import DetectedInterface, create_session

    cfg = get_config()
    if baudrate is not None:
        cfg.uart.default_baudrate = baudrate
    if programmer is not None:
        cfg.spi.default_programmer = programmer
    if output_dir is not None:
        cfg.output.base_dir = output_dir

    _print_banner()
    session = create_session(cfg)
    orchestrator = Orchestrator(session)

    # If the user explicitly named a port, skip HAL detection and seed directly.
    if port is not None and method in (ExtractionMethod.UART, ExtractionMethod.AUTO):
        session.detected_interfaces.append(
            DetectedInterface(
                interface_type="uart",
                port_or_device=port,
                metadata={"detected_baudrate": baudrate, "active_output": True},
            )
        )
        success = orchestrator.run_with_interfaces(skip_analyze=no_analyze)
    else:
        success = orchestrator.run()

    raise typer.Exit(code=0 if success else 1)


# ---------------------------------------------------------------------------
# firmxtract analyze
# ---------------------------------------------------------------------------


@app.command()
def analyze(
    firmware: Path = typer.Argument(..., help="Path to firmware binary."),
    output_dir: Path | None = typer.Option(
        None, "--output-dir", "-o",
        help="Output directory for analysis results.",
    ),
    no_extract: bool = typer.Option(
        False, "--no-extract",
        help="Signature scan only — skip filesystem extraction.",
    ),
) -> None:
    """
    [bold]Analyze an existing firmware dump.[/bold]

    Runs binwalk on a local file — no hardware required.

    Example:

      firmxtract analyze firmware.bin
    """
    from firmxtract.core.session import ExtractionResult, create_session
    from firmxtract.extraction.binwalk_wrapper import BinwalkWrapper

    if not firmware.exists():
        console.print(f"[red]Error:[/red] file not found: {firmware}")
        raise typer.Exit(1)
    if not firmware.is_file():
        console.print(f"[red]Error:[/red] not a file: {firmware}")
        raise typer.Exit(1)

    cfg = get_config()
    if output_dir is not None:
        cfg.output.base_dir = output_dir
    if no_extract:
        cfg.binwalk.extract = False

    _print_banner()
    session = create_session(cfg)

    session.extraction_result = ExtractionResult(
        success=True,
        method="local_file",
        firmware_path=firmware,
        size_bytes=firmware.stat().st_size,
    )

    result = BinwalkWrapper(session).analyze(firmware)
    session.analysis_results.append(result)
    session.mark_complete()
    session.save_report()

    if result.success:
        console.print(
            f"\n[green]Analysis complete.[/green] "
            f"{len(result.findings)} signature(s) found."
        )
        if result.extracted_dir:
            console.print(f"Extracted → {result.extracted_dir}")
        raise typer.Exit(0)

    console.print(f"\n[red]Analysis failed:[/red] {result.error_message}")
    raise typer.Exit(1)


# ---------------------------------------------------------------------------
# firmxtract console
# ---------------------------------------------------------------------------


@app.command("console")
def console_cmd(
    port: str = typer.Option(..., "--port", "-p", help="Serial port (e.g. /dev/ttyUSB0)."),
    baudrate: int | None = typer.Option(
        None, "--baud", "-b",
        help="Baud rate. Auto-detected if omitted.",
    ),
) -> None:
    """
    [bold]Open an interactive UART console.[/bold]

    Connects to a serial port and provides a pass-through terminal session.
    Press Ctrl+] to exit (like telnet).

    Example:

      firmxtract console --port /dev/ttyUSB0 --baud 115200
    """
    from firmxtract.hardware.uart import UARTConsole

    cfg = get_config()
    baud = baudrate or cfg.uart.default_baudrate

    _print_banner()
    console.print(
        f"Connecting to [bold]{port}[/bold] @ [bold]{baud}[/bold] baud\n"
        "[dim]Press Ctrl+] to exit.[/dim]\n"
    )

    uc = UARTConsole(port=port, baudrate=baud, uart_config=cfg.uart)
    uc.run()



# ---------------------------------------------------------------------------
# Hardware subcommand group
# firmxtract hardware uart scan
# firmxtract hardware uart console --port /dev/ttyUSB0
# firmxtract hardware spi detect
# firmxtract hardware spi dump --programmer ch341a_spi
# firmxtract hardware list
# ---------------------------------------------------------------------------

hardware_app = typer.Typer(
    name="hardware",
    help="[bold]Hardware interface commands.[/bold] UART, SPI, JTAG detection and interaction.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
app.add_typer(hardware_app, name="hardware")

uart_app = typer.Typer(
    name="uart",
    help="UART interface commands.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
hardware_app.add_typer(uart_app, name="uart")

spi_app = typer.Typer(
    name="spi",
    help="SPI flash interface commands.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
hardware_app.add_typer(spi_app, name="spi")


@hardware_app.command("list")
def hardware_list() -> None:
    """
    [bold]Detect and list all connected hardware interfaces.[/bold]

    Scans for UART serial ports and SPI programmers.

    Example:

      firmxtract hardware list
    """
    from firmxtract.hardware.hal import HAL
    from rich.table import Table

    _print_banner()
    setup_logging()
    cfg = get_config()
    hal = HAL(cfg)

    console.print("[bold]Scanning for hardware interfaces...[/bold]\n")
    interfaces = hal.detect_interfaces()

    if not interfaces:
        console.print("[yellow]No hardware interfaces detected.[/yellow]")
        console.print("[dim]Check USB connections and run 'firmxtract info' for tool status.[/dim]")
        raise typer.Exit(1)

    table = Table(show_header=True, header_style="bold cyan", box=None)
    table.add_column("Type",    style="bold", min_width=8)
    table.add_column("Device",  min_width=20)
    table.add_column("Details")
    table.add_column("Status")

    for iface in interfaces:
        details = ", ".join(
            f"{k}={v}" for k, v in iface.metadata.items()
            if k not in ("hwid",) and v is not None
        )
        active = iface.metadata.get("active_output", False)
        status = "[green]active[/green]" if active else "[dim]detected[/dim]"
        table.add_row(
            iface.interface_type.upper(),
            iface.port_or_device,
            details[:60],
            status,
        )

    console.print(table)
    console.print(f"\n[dim]{len(interfaces)} interface(s) found.[/dim]")


@uart_app.command("scan")
def uart_scan(
    port: str | None = typer.Option(
        None, "--port", "-p", help="Specific port to scan (e.g. /dev/ttyUSB0)."
    ),
    baud: int | None = typer.Option(
        None, "--baud", "-b", help="Baud rate to test. Sweeps all rates if omitted."
    ),
) -> None:
    """
    [bold]Scan for active UART consoles.[/bold]

    Enumerates serial ports and probes for bootloader or shell output.
    If a port is specified with no baud rate, performs a full baud rate sweep.

    Examples:

      firmxtract hardware uart scan
      firmxtract hardware uart scan --port /dev/ttyUSB0
      firmxtract hardware uart scan --port /dev/ttyUSB0 --baud 115200
    """
    import serial.tools.list_ports
    from firmxtract.hardware.uart import detect_baudrate, enumerate_uart_ports
    from rich.table import Table

    _print_banner()
    setup_logging()
    cfg = get_config()

    if port:
        # Scan specific port
        console.print(f"Scanning [bold]{port}[/bold]...\n")
        detected_baud = baud or detect_baudrate(port, cfg.uart)
        if detected_baud:
            console.print(f"[green]✓ Active console detected[/green] @ {detected_baud} baud")
            console.print(f"  Connect with: [cyan]firmxtract hardware uart console --port {port} --baud {detected_baud}[/cyan]")
        else:
            console.print("[yellow]No active console detected on this port.[/yellow]")
        return

    # Scan all ports
    interfaces = enumerate_uart_ports(cfg.uart)
    if not interfaces:
        console.print("[yellow]No serial ports found. Check USB adapter connection.[/yellow]")
        raise typer.Exit(1)

    table = Table(show_header=True, header_style="bold cyan", box=None)
    table.add_column("Port",        style="bold", min_width=15)
    table.add_column("Description", min_width=25)
    table.add_column("Baud",        min_width=10)
    table.add_column("Status")

    for iface in interfaces:
        active = iface.metadata.get("active_output", False)
        detected = iface.metadata.get("detected_baudrate")
        status = "[green]● active[/green]" if active else "[dim]○ silent[/dim]"
        table.add_row(
            iface.port_or_device,
            iface.metadata.get("description", "—")[:30],
            str(detected) if detected else "—",
            status,
        )

    console.print(table)


@uart_app.command("console")
def uart_console(
    port: str = typer.Option(..., "--port", "-p", help="Serial port (e.g. /dev/ttyUSB0)."),
    baud: int | None = typer.Option(None, "--baud", "-b", help="Baud rate."),
) -> None:
    """
    [bold]Open interactive UART console.[/bold]

    Pass-through terminal to a UART device. Press Ctrl+] to exit.

    Example:

      firmxtract hardware uart console --port /dev/ttyUSB0 --baud 115200
    """
    from firmxtract.hardware.uart import UARTConsole

    _print_banner()
    setup_logging()
    cfg = get_config()
    baudrate = baud or cfg.uart.default_baudrate

    console.print(
        f"Connecting to [bold]{port}[/bold] @ [bold]{baudrate}[/bold] baud\n"
        "[dim]Press Ctrl+] to exit.[/dim]\n"
    )
    uc = UARTConsole(port=port, baudrate=baudrate, uart_config=cfg.uart)
    uc.run()


@spi_app.command("detect")
def spi_detect() -> None:
    """
    [bold]Detect connected SPI flash programmer and chip.[/bold]

    Probes for known programmers (ch341a, ft2232h, buspirate, serprog).
    Read-only — does not dump flash.

    Example:

      firmxtract hardware spi detect
    """
    from firmxtract.hardware.spi import probe_spi_programmer

    _print_banner()
    setup_logging()
    cfg = get_config()

    console.print("[bold]Probing for SPI flash programmer...[/bold]\n")
    interfaces = probe_spi_programmer(cfg.spi)

    if not interfaces:
        console.print("[yellow]No SPI programmer detected.[/yellow]")
        console.print("[dim]Supported: ch341a_spi, ft2232_spi, buspirate_spi, serprog, dediprog[/dim]")
        raise typer.Exit(1)

    for iface in interfaces:
        chip = iface.metadata.get("chip_name") or iface.metadata.get("chip_id", "unknown")
        console.print(f"[green]✓ Programmer:[/green] {iface.port_or_device}")
        console.print(f"  Chip:        [bold]{chip}[/bold]")
        console.print(f"  flashrom:    {iface.metadata.get('flashrom_path', 'flashrom')}")
        console.print(f"\n  Dump with:   [cyan]firmxtract hardware spi dump --programmer {iface.port_or_device}[/cyan]")


@spi_app.command("dump")
def spi_dump(
    programmer: str = typer.Option(
        "ch341a_spi", "--programmer", "-P",
        help="flashrom programmer string (e.g. ch341a_spi, ft2232_spi).",
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o",
        help="Output file path. Default: ./firmxtract_sessions/<ts>/firmware.bin",
    ),
    no_verify: bool = typer.Option(
        False, "--no-verify", help="Skip post-dump verification read."
    ),
) -> None:
    """
    [bold]Dump SPI flash chip to file.[/bold]

    Reads the full flash chip contents using flashrom.
    Verifies the dump with a second read by default.

    Examples:

      firmxtract hardware spi dump
      firmxtract hardware spi dump --programmer ch341a_spi
      firmxtract hardware spi dump --output /tmp/router.bin --no-verify
    """
    from firmxtract.core.session import create_session, DetectedInterface
    from firmxtract.hardware.spi import SPIHandler
    import shutil

    _print_banner()
    setup_logging()
    cfg = get_config()

    if shutil.which(cfg.spi.flashrom_path) is None:
        console.print(f"[red]flashrom not found.[/red] Install with: sudo apt install flashrom")
        raise typer.Exit(1)

    if no_verify:
        cfg.spi.verify_after_dump = False

    session = create_session(cfg)

    iface = DetectedInterface(
        interface_type="spi",
        port_or_device=programmer,
        metadata={"chip_name": "unknown", "flashrom_path": cfg.spi.flashrom_path},
    )

    console.print(f"[yellow]⚡ Ensure correct voltage levels before proceeding.[/yellow]\n")
    handler = SPIHandler(session)
    result = handler.extract(iface)

    if result.success:
        final_path = output or result.firmware_path
        if output and result.firmware_path:
            import shutil as sh
            sh.copy2(result.firmware_path, output)
            final_path = output

        console.print(f"\n[green]Dump complete![/green]")
        console.print(f"  File:    [bold]{final_path}[/bold]")
        console.print(f"  Size:    {result.size_bytes:,} bytes")
        console.print(f"  SHA256:  {result.checksum_sha256}")
        console.print(f"\n  Analyze: [cyan]firmxtract analyze {final_path}[/cyan]")
    else:
        console.print(f"[red]Dump failed:[/red] {result.error_message}")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Plugin commands
# firmxtract plugins list
# ---------------------------------------------------------------------------

plugins_app = typer.Typer(
    name="plugins",
    help="[bold]Plugin management commands.[/bold]",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
app.add_typer(plugins_app, name="plugins")


@plugins_app.command("list")
def plugins_list() -> None:
    """
    [bold]List all discovered plugins.[/bold]

    Shows built-in plugins, user plugins from ~/.firmxtract/plugins/,
    and any installed third-party plugins.

    Example:

      firmxtract plugins list
    """
    from firmxtract.core.plugin_loader import PluginLoader
    from rich.table import Table

    _print_banner()
    setup_logging()

    loader = PluginLoader()
    plugins_meta = loader.list_available()

    if not plugins_meta:
        console.print("[yellow]No plugins found.[/yellow]")
        return

    table = Table(show_header=True, header_style="bold cyan", box=None)
    table.add_column("Name",        style="bold", min_width=20)
    table.add_column("Version",     min_width=8)
    table.add_column("Description", min_width=35)
    table.add_column("Hooks",       min_width=15)
    table.add_column("Status")

    for p in plugins_meta:
        hooks_str = ", ".join(p["hooks"]) if p["hooks"] else "standalone"
        available = "[green]✓[/green]" if p["available"] else "[red]missing deps[/red]"
        table.add_row(
            p["name"],
            p["version"],
            p["description"][:40],
            hooks_str,
            available,
        )

    console.print(table)
    console.print(f"\n[dim]{len(plugins_meta)} plugin(s) loaded.[/dim]")
    console.print("[dim]Add plugins to ~/.firmxtract/plugins/ or install via pip.[/dim]")


# ---------------------------------------------------------------------------
# run full — one command does everything
# firmxtract run full firmware.bin
# firmxtract run full --port /dev/ttyUSB0
# ---------------------------------------------------------------------------

run_app = typer.Typer(
    name="run",
    help="[bold]High-level run commands.[/bold] One command to rule them all.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)
app.add_typer(run_app, name="run")


@run_app.command("full")
def run_full(
    target: str | None = typer.Argument(
        None,
        help="Firmware file to analyze, OR leave empty to auto-detect hardware.",
    ),
    port: str | None = typer.Option(
        None, "--port", "-p", help="UART port (e.g. /dev/ttyUSB0)."
    ),
    programmer: str | None = typer.Option(
        None, "--programmer", help="SPI programmer (e.g. ch341a_spi)."
    ),
    output_dir: Path | None = typer.Option(
        None, "--output-dir", "-o", help="Session output directory."
    ),
    no_plugins: bool = typer.Option(
        False, "--no-plugins", help="Disable plugin execution."
    ),
) -> None:
    """
    [bold]Run the complete FirmXtract pipeline.[/bold]

    The all-in-one command:
      detect → extract → analyze → secrets → entropy → report

    Accepts a firmware file OR hardware connection details.

    Examples:

      [dim]# Analyze existing firmware file[/dim]
      firmxtract run full firmware.bin

      [dim]# Auto-detect hardware and extract[/dim]
      firmxtract run full

      [dim]# Extract from specific UART port[/dim]
      firmxtract run full --port /dev/ttyUSB0

      [dim]# Full run with SPI programmer[/dim]
      firmxtract run full --programmer ch341a_spi
    """
    from firmxtract.core.session import create_session, ExtractionResult, DetectedInterface
    from firmxtract.core.plugin_loader import PluginLoader
    from firmxtract.core.orchestrator import Orchestrator

    _print_banner()
    setup_logging()

    cfg = get_config()
    if output_dir:
        cfg.output.base_dir = output_dir
    if programmer:
        cfg.spi.default_programmer = programmer

    session = create_session(cfg)

    # Load plugins
    if not no_plugins:
        loader = PluginLoader()
        plugins = loader.discover_all()
        enabled = [p for p in plugins if p.enabled and p.is_available()]
        if enabled:
            log.info(f"Plugins loaded: {', '.join(p.name for p in enabled)}")
        session.add_note(f"Plugins: {len(enabled)} active")

    orchestrator = Orchestrator(session)

    # Case 1: existing firmware file provided
    if target:
        firmware_path = Path(target)
        if not firmware_path.exists():
            console.print(f"[red]File not found:[/red] {firmware_path}")
            raise typer.Exit(1)

        session.extraction_result = ExtractionResult(
            success=True,
            method="local_file",
            firmware_path=firmware_path,
            size_bytes=firmware_path.stat().st_size,
        )
        log.info(f"Target firmware: {firmware_path} ({firmware_path.stat().st_size:,} bytes)")
        orchestrator._stage_analyze_firmware()
        orchestrator._stage_scan_secrets()
        orchestrator._stage_finalize()
        success = session.firmware_extracted

    # Case 2: specific UART port
    elif port:
        session.detected_interfaces.append(
            DetectedInterface(
                interface_type="uart",
                port_or_device=port,
                metadata={"detected_baudrate": None, "active_output": True},
            )
        )
        success = orchestrator.run_with_interfaces()

    # Case 3: auto-detect hardware
    else:
        success = orchestrator.run()

    # Final summary
    console.print("")
    if success:
        console.print("[green]╔══════════════════════════════════════╗[/green]")
        console.print("[green]║   Pipeline complete — SUCCESS        ║[/green]")
        console.print("[green]╚══════════════════════════════════════╝[/green]")
    else:
        console.print("[red]╔══════════════════════════════════════╗[/red]")
        console.print("[red]║   Pipeline complete — FAILED         ║[/red]")
        console.print("[red]╚══════════════════════════════════════╝[/red]")

    console.print(f"\n  Session: [dim]{session.output_dir}[/dim]")
    console.print(f"  Report:  [cyan]firmxtract report[/cyan]")
    raise typer.Exit(0 if success else 1)

# ---------------------------------------------------------------------------
# firmxtract report
# ---------------------------------------------------------------------------


@app.command()
def report(
    session_dir: Path | None = typer.Argument(
        None,
        help="Path to a specific session directory. "
             "Defaults to the most recent session.",
    ),
) -> None:
    """
    [bold]Display a session report.[/bold]

    Shows findings from the most recent session, or a specific session directory.

    Examples:

      firmxtract report
      firmxtract report ~/.firmxtract/sessions/20260402_143022
    """
    import json

    cfg = get_config()

    # Find the target report file
    if session_dir is not None:
        report_path = session_dir / "report.json"
    else:
        # Find most recent session by directory mtime
        base = cfg.output.base_dir
        if not base.exists():
            console.print("[yellow]No sessions found.[/yellow] Run firmxtract extract first.")
            raise typer.Exit(0)
        sessions = sorted(
            (d for d in base.iterdir() if d.is_dir()),
            key=lambda d: d.stat().st_mtime,
            reverse=True,
        )
        if not sessions:
            console.print("[yellow]No sessions found.[/yellow] Run firmxtract extract first.")
            raise typer.Exit(0)
        report_path = sessions[0] / "report.json"

    if not report_path.exists():
        console.print(f"[red]Report not found:[/red] {report_path}")
        raise typer.Exit(1)

    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        console.print(f"[red]Failed to read report:[/red] {exc}")
        raise typer.Exit(1)

    _print_report(data)


def _print_report(data: dict) -> None:  # type: ignore[type-arg]
    """Render a session report dict to the terminal."""
    from rich.panel import Panel

    _print_banner()

    # Header
    status = "[green]SUCCESS[/green]" if data.get("extraction", {}) else "[red]FAILED[/red]"
    if data.get("extraction") and data["extraction"].get("success"):
        status = "[green]SUCCESS[/green]"
    else:
        status = "[red]FAILED[/red]"

    console.print(Panel(
        f"[bold]Session:[/bold] {data.get('session_id', '?')}\n"
        f"[bold]Status:[/bold]  {status}\n"
        f"[bold]Duration:[/bold] {data.get('duration_seconds', 0):.1f}s\n"
        f"[bold]Output:[/bold]  {data.get('output_dir', '?')}",
        title="Session Summary",
        border_style="cyan",
    ))

    # Extraction
    ext = data.get("extraction")
    if ext:
        console.print(f"\n[bold]Extraction[/bold] (method: {ext.get('method', '?')})")
        if ext.get("firmware_path"):
            size_mb = ext.get("size_bytes", 0) / (1024 * 1024)
            console.print(f"  Path:     {ext['firmware_path']}")
            console.print(f"  Size:     {size_mb:.2f} MB ({ext.get('size_bytes', 0):,} bytes)")
            if ext.get("checksum_sha256"):
                console.print(f"  SHA256:   {ext['checksum_sha256']}")

    # Analysis
    analysis = data.get("analysis", [])
    if analysis:
        console.print(f"\n[bold]Analysis[/bold] ({len(analysis)} tool(s) run)")
        for r in analysis:
            icon = "[green]✓[/green]" if r.get("success") else "[red]✗[/red]"
            console.print(
                f"  {icon} {r.get('tool', '?')}: "
                f"{r.get('findings_count', 0)} finding(s)"
            )
            if r.get("extracted_dir"):
                console.print(f"    Extracted → {r['extracted_dir']}")

    # Notes
    notes = data.get("notes", [])
    if notes:
        console.print("\n[bold]Notes[/bold]")
        for note in notes:
            console.print(f"  [dim]•[/dim] {note}")

    console.print(f"\n[dim]Full report: {data.get('output_dir', '?')}/report.json[/dim]")


# ---------------------------------------------------------------------------
# firmxtract info
# ---------------------------------------------------------------------------


@app.command()
def info() -> None:
    """
    [bold]Show system information.[/bold]

    Lists tool availability (flashrom, binwalk, openocd) and detected serial ports.
    """
    setup_logging()
    _print_banner()

    console.print("[bold]External Tools[/bold]\n")
    tools_table = Table(show_header=True, header_style="bold cyan", box=None)
    tools_table.add_column("Tool", style="bold", min_width=12)
    tools_table.add_column("Status", min_width=14)
    tools_table.add_column("Path")

    for tool in ["flashrom", "binwalk", "openocd", "dd", "python3"]:
        path = shutil.which(tool)
        if path:
            tools_table.add_row(tool, "[green]✓ found[/green]", path)
        else:
            tools_table.add_row(tool, "[red]✗ not found[/red]", "—")

    console.print(tools_table)

    console.print("\n[bold]Serial Ports[/bold]\n")
    try:
        import serial.tools.list_ports

        ports = list(serial.tools.list_ports.comports())
        if ports:
            ports_table = Table(show_header=True, header_style="bold cyan", box=None)
            ports_table.add_column("Device", style="bold")
            ports_table.add_column("Description")
            ports_table.add_column("HWID")
            for p in ports:
                ports_table.add_row(p.device, p.description or "—", p.hwid or "—")
            console.print(ports_table)
        else:
            console.print("[yellow]No serial ports detected.[/yellow]")
    except ImportError:
        console.print("[red]pyserial not installed.[/red]")

    from firmxtract.utils.config import DEFAULT_CONFIG_FILE

    cfg_status = "exists" if DEFAULT_CONFIG_FILE.exists() else "not found — using defaults"
    console.print(f"\n[dim]Config:[/dim] {DEFAULT_CONFIG_FILE} ({cfg_status})")


# ---------------------------------------------------------------------------
# firmxtract version
# ---------------------------------------------------------------------------


@app.command()
def version() -> None:
    """Print FirmXtract version and exit."""
    _print_banner()
    console.print(f"Version: [bold]{get_version()}[/bold]")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _print_banner() -> None:
    ver = get_version()
    console.print("")
    console.print("[bold cyan]███████╗██╗██████╗ ███╗   ███╗██╗  ██╗████████╗██████╗  █████╗  ██████╗████████╗[/bold cyan]")
    console.print("[bold cyan]██╔════╝██║██╔══██╗████╗ ████║╚██╗██╔╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝[/bold cyan]")
    console.print("[bold cyan]█████╗  ██║██████╔╝██╔████╔██║ ╚███╔╝    ██║   ██████╔╝███████║██║        ██║   [/bold cyan]")
    console.print("[bold cyan]██╔══╝  ██║██╔══██╗██║╚██╔╝██║ ██╔██╗    ██║   ██╔══██╗██╔══██║██║        ██║   [/bold cyan]")
    console.print("[bold cyan]██║     ██║██║  ██║██║ ╚═╝ ██║██╔╝ ██╗   ██║   ██║  ██║██║  ██║╚██████╗   ██║   [/bold cyan]")
    console.print("[bold cyan]╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝   ╚═╝   [/bold cyan]")
    console.print("")
    console.print(
        f"    [dim]v{ver}[/dim]  [bold white]|[/bold white]  "
        "[dim]IoT Firmware Extraction & Red-Teaming Framework[/dim]"
    )
    console.print(
        "    [dim]by imran-khatib[/dim]  [bold white]|[/bold white]  "
        "[dim]https://github.com/imran-khatib/Firmxtract[/dim]"
    )
    console.print("    [cyan]" + "═" * 65 + "[/cyan]")
    console.print("")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Package entry point registered in pyproject.toml [project.scripts]."""
    app()


if __name__ == "__main__":
    main()
