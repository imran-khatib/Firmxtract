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


@app.callback()
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


@app.command()
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
    console.print(f"FirmXtract [bold]{get_version()}[/bold]")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _print_banner() -> None:
    ver = get_version()
    pad = " " * (13 - len(ver))
    console.print(
        "\n[bold cyan]╔══════════════════════════════════════╗[/bold cyan]"
        f"\n[bold cyan]║[/bold cyan]  [bold white]FirmXtract[/bold white] "
        f"[dim]v{ver}[/dim]{pad}[bold cyan]           ║[/bold cyan]"
        "\n[bold cyan]║[/bold cyan]  [dim]IoT Firmware Analysis Framework[/dim]"
        "    [bold cyan]║[/bold cyan]"
        "\n[bold cyan]╚══════════════════════════════════════╝[/bold cyan]\n"
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Package entry point registered in pyproject.toml [project.scripts]."""
    app()


if __name__ == "__main__":
    main()
