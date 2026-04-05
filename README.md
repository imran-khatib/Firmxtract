# FirmXtract

```
███████╗██╗██████╗ ███╗   ███╗██╗  ██╗████████╗██████╗  █████╗  ██████╗████████╗
██╔════╝██║██╔══██╗████╗ ████║╚██╗██╔╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝
█████╗  ██║██████╔╝██╔████╔██║ ╚███╔╝    ██║   ██████╔╝███████║██║        ██║
██╔══╝  ██║██╔══██╗██║╚██╔╝██║ ██╔██╗    ██║   ██╔══██╗██╔══██║██║        ██║
██║     ██║██║  ██║██║ ╚═╝ ██║██╔╝ ██╗   ██║   ██║  ██║██║  ██║╚██████╗   ██║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝   ╚═╝

    v0.1.0  |  IoT Firmware Extraction & Red-Teaming Framework
    by imran-khatib  |  https://github.com/imran-khatib/Firmxtract
    ═══════════════════════════════════════════════════════════════
```

> Unified IoT Firmware Extraction, Analysis, and Red-Teaming Framework

FirmXtract replaces fragmented tools (binwalk, flashrom, OpenOCD, UART utilities) with one
intelligent, automated platform.

```
One command → Hardware detect → Firmware extract → Unpack → Analyze → Secrets hunt → Report
```

---

## ⚠️ Legal Notice

FirmXtract is intended for **authorized security research, penetration testing, and firmware
analysis on devices you own or have explicit written permission to test**.
Unauthorized use against third-party devices may violate computer fraud and abuse laws.
The authors accept no liability for misuse.

---

## Phase 1 Feature Set

| Feature | Status |
|---------|--------|
| UART console detection (pyserial) | ✅ |
| UART baud rate auto-sweep | ✅ |
| Interactive UART console (`firmxtract console`) | ✅ |
| SPI flash dump via flashrom | ✅ |
| Programmer auto-detection (ch341a, ft2232h, buspirate, serprog) | ✅ |
| UART → SPI automatic fallback | ✅ |
| binwalk signature scan + recursive extraction | ✅ |
| Session management + JSON report | ✅ |
| `firmxtract report` viewer | ✅ |
| Rich CLI (typer + rich) | ✅ |

## Roadmap

| Phase | Features |
|-------|----------|
| 2 | Rust native modules (fast baud scan, entropy), JTAG/OpenOCD, radare2 integration |
| 3 | Tauri GUI, Ollama LLM co-pilot, Neo4j attack graph, vulnerability dashboard |

---

## Requirements

| Requirement | Notes |
|-------------|-------|
| Python 3.11+ | 3.12 also supported |
| flashrom | `apt install flashrom` / `brew install flashrom` |
| binwalk | `pip install binwalk` / `apt install binwalk` |
| USB-to-UART adapter | CH340, CP2102, or FTDI (for UART extraction) |
| SPI programmer | ch341a, ft2232h, Bus Pirate, or serprog device (for SPI extraction) |

flashrom and binwalk are **optional** — FirmXtract will skip unavailable tools gracefully.

---

## Installation

### From source (recommended for development)

```bash
# 1. Clone the repository
git clone https://github.com/imran-khatib/Firmxtract
cd Firmxtract

# 2. Install in editable mode with development dependencies
pip install -e ".[dev]"

# 3. Verify the install
firmxtract version
firmxtract info
```

### From source (runtime only — no dev tools)

```bash
pip install -e .
```

### Using requirements file

```bash
pip install -r requirements-dev.txt
pip install -e .
```

> **Note for Linux users:** If pip warns about `--break-system-packages`, use a
> virtual environment: `python3 -m venv .venv && source .venv/bin/activate`
> before running the install commands above.

---

## Quick Start

```bash
# Show system information: tool availability + detected serial ports
firmxtract info

# Auto-detect hardware and run full extraction pipeline
firmxtract extract

# Specify UART port and baud rate explicitly
firmxtract extract --port /dev/ttyUSB0 --baud 115200

# Force SPI extraction with a specific programmer
firmxtract extract --method spi --programmer ch341a_spi

# Save session output to a custom directory
firmxtract extract --output-dir /tmp/router_fw/

# Extract without running binwalk afterward
firmxtract extract --no-analyze

# Analyze an existing firmware dump (no hardware needed)
firmxtract analyze firmware.bin

# Analyze without extracting filesystem (signature scan only)
firmxtract analyze firmware.bin --no-extract

# Open an interactive UART console
firmxtract console --port /dev/ttyUSB0 --baud 115200

# View the most recent session report
firmxtract report

# View a specific session report
firmxtract report ~/.firmxtract/sessions/20260402_143022/
```

---

## Hardware Setup

### UART Extraction

1. Connect USB-to-UART adapter to target board: TX→RX, RX→TX, GND→GND
2. **Do NOT connect the 3.3V/5V pin if the board is externally powered** — you will fry it
3. Run `firmxtract info` to confirm the port appears under "Serial Ports"
4. Run `firmxtract extract --port /dev/ttyUSB0` (or let it auto-detect)

**Common UART adapter device names:**

| OS | Adapter | Device |
|----|---------|--------|
| Linux | CH340 | `/dev/ttyUSB0` |
| Linux | CP2102 | `/dev/ttyUSB0` |
| Linux | FTDI | `/dev/ttyUSB0` or `/dev/ttyACM0` |
| macOS | CH340 | `/dev/cu.usbserial-*` |
| macOS | FTDI | `/dev/cu.usbserial-*` |

If you get a "permission denied" error on Linux: `sudo usermod -aG dialout $USER` (re-login required).

### SPI Flash Extraction (ch341a programmer)

1. **Power OFF** the target device completely
2. Connect the ch341a SOIC8 clip to the SPI flash chip (pin 1 marked with dot)
3. Consult the flash chip datasheet to confirm pinout
4. Run `firmxtract extract --method spi --programmer ch341a_spi`

> **Voltage warning:** ch341a outputs 3.3V. Some older flash chips require 5V.
> Verify the chip's VCC spec before connecting.

---

## Configuration

FirmXtract looks for `~/.firmxtract/config.toml`. If not found, built-in defaults are used.

### Full example config

```toml
[uart]
default_baudrate = 115200
baudrates = [9600, 38400, 57600, 115200, 230400, 921600]
read_timeout = 2.0
detection_timeout = 5.0

[spi]
default_programmer = "ch341a_spi"
verify_after_dump = true
dump_retries = 3

[binwalk]
extract = true
matryoshka = true   # recursive extraction
entropy_scan = false

[output]
base_dir = "~/.firmxtract/sessions"
```

### Environment variable overrides

```bash
export FIRMXTRACT_OUTPUT_DIR=/mnt/data/fw_sessions
export FIRMXTRACT_SPI_PROGRAMMER=ft2232_spi
export FIRMXTRACT_UART_BAUD=115200
export FIRMXTRACT_FLASHROM_PATH=/usr/local/bin/flashrom
export FIRMXTRACT_BINWALK_PATH=/usr/bin/binwalk
```

---

## Session Output

Each run creates a timestamped directory under `~/.firmxtract/sessions/`:

```
~/.firmxtract/sessions/20260402_143022/
├── firmware.bin                   # SPI flash dump (raw binary)
│   OR uart_capture.log            # UART boot log capture (Phase 1)
├── _firmware.bin.extracted/       # binwalk recursive extraction
│   ├── squashfs-root/             # Unpacked root filesystem
│   │   ├── etc/passwd
│   │   ├── usr/bin/
│   │   └── ...
│   └── ...
├── binwalk_scan.log               # binwalk CSV output (all signatures)
└── report.json                    # Full machine-readable session report
```

View the report with: `firmxtract report`

---

## Development

```bash
# Run all tests (no hardware required)
pytest -m "not hardware"

# Run with coverage
pytest -m "not hardware" --cov=src/firmxtract --cov-report=term-missing

# Lint (ruff)
ruff check src/ tests/

# Format check (black)
black --check src/ tests/

# Auto-fix formatting
black src/ tests/

# Type check (mypy)
mypy src/

# Run everything (recommended before commit)
ruff check src/ tests/ && black --check src/ tests/ && mypy src/ && pytest -m "not hardware"
```

### Running hardware tests

Hardware tests require a physical device and are skipped by default:

```bash
# Run hardware tests (device must be connected)
pytest -m hardware -v
```

---

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full system design, data flow diagrams, and
module responsibility breakdown.

## Project Conventions

See [CLAUDE.md](CLAUDE.md) for coding standards, module boundary rules, hardware safety
requirements, and contribution guidelines.

## Task Tracker

See [TODO.md](TODO.md) for current phase status and upcoming work.
