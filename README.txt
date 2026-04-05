================================================================================
  FirmXtract v0.1.0
  Unified IoT Firmware Extraction, Analysis & Red-Teaming Framework
================================================================================

  One command -> Hardware detect -> Firmware extract -> Analyze -> Secrets -> Report

--------------------------------------------------------------------------------
  LEGAL WARNING
--------------------------------------------------------------------------------

  FirmXtract is for AUTHORIZED security research only.
  Only use it on devices you OWN or have EXPLICIT WRITTEN PERMISSION to test.
  Unauthorized use may violate computer fraud laws in your jurisdiction.
  The authors accept NO liability for misuse.

--------------------------------------------------------------------------------
  WHAT IT DOES
--------------------------------------------------------------------------------

  - Automatically detects UART and SPI hardware interfaces
  - Extracts firmware over UART (auto baud-rate detection, dd+base64 transfer)
  - Dumps SPI flash chips via flashrom (ch341a, ft2232h, buspirate, serprog)
  - Falls back from UART to SPI automatically if UART fails
  - Analyzes firmware with binwalk (signature scan + filesystem extraction)
  - Hunts for 20 types of hardcoded secrets (passwords, keys, WiFi PSK, etc.)
  - Saves everything to a timestamped session folder with a JSON report
  - Interactive UART console (pass-through terminal)

--------------------------------------------------------------------------------
  REQUIREMENTS
--------------------------------------------------------------------------------

  REQUIRED:
    - Python 3.10 or higher  (check: python3 --version)
    - pip

  OPTIONAL (FirmXtract works without them but features are limited):
    - flashrom    -> needed for SPI flash extraction
    - binwalk     -> needed for firmware analysis and unpacking

  HARDWARE (only needed for extraction from physical devices):
    - USB-to-UART adapter: CH340, CP2102, or FTDI chip
    - SPI programmer:      ch341a (most common), ft2232h, Bus Pirate, serprog

  INSTALL SYSTEM TOOLS:

    Ubuntu / Debian / Kali:
      sudo apt install flashrom binwalk python3 python3-pip

    macOS (with Homebrew):
      brew install flashrom binwalk python3

    Kali Linux already has most tools pre-installed.

--------------------------------------------------------------------------------
  QUICK INSTALL  (run install.sh instead of doing this manually)
--------------------------------------------------------------------------------

  If you prefer to install manually:

    1. Unzip the project:
         unzip firmxtract_phase1_final.zip
         cd firmxtract

    2. Create a virtual environment:
         python3 -m venv .venv
         source .venv/bin/activate          (Linux / macOS)
         .venv\Scripts\activate             (Windows)

    3. Install FirmXtract:
         pip install -e ".[dev]"

    4. Verify:
         firmxtract version
         firmxtract info

    OR just run:  bash install.sh
    (The install script does all of the above automatically.)

--------------------------------------------------------------------------------
  COMMANDS
--------------------------------------------------------------------------------

  firmxtract info
    Show system status: which tools are installed, which serial ports detected.
    Run this first to confirm your setup is correct.

  firmxtract extract
    Run the full pipeline. Auto-detects hardware, extracts firmware,
    runs binwalk, hunts for secrets, saves a report.

    Options:
      --port /dev/ttyUSB0      Use a specific serial port (skip auto-detect)
      --baud 115200            Set baud rate (auto-detected if omitted)
      --method uart            Force UART only (default: auto = UART then SPI)
      --method spi             Force SPI only
      --programmer ch341a_spi  Set flashrom programmer (auto-detected if omitted)
      --output-dir /tmp/out    Save session to a custom directory
      --no-analyze             Skip binwalk + secrets scan after extraction
      -v / --verbose           Show debug output

  firmxtract analyze firmware.bin
    Analyze an existing firmware file. No hardware needed.

    Options:
      --no-extract             Signature scan only, skip filesystem extraction
      --output-dir /tmp/out    Save results to custom directory

  firmxtract console --port /dev/ttyUSB0
    Open an interactive terminal on a UART port.
    Everything you type is sent to the device. Device output is printed here.
    Press Ctrl+] to exit (same as telnet).

    Options:
      --baud 115200            Set baud rate (uses config default if omitted)

  firmxtract report
    Display the most recent session report in the terminal.

    firmxtract report ~/.firmxtract/sessions/20260402_143022/
    View a specific session by path.

  firmxtract version
    Print the installed version number.

--------------------------------------------------------------------------------
  TYPICAL USAGE EXAMPLES
--------------------------------------------------------------------------------

  EXAMPLE 1: Extract firmware from a router over UART

    Step 1 - Connect USB-UART adapter: TX->RX, RX->TX, GND->GND
    Step 2 - Find your port:
               firmxtract info
    Step 3 - Extract:
               firmxtract extract --port /dev/ttyUSB0
    Step 4 - View results:
               firmxtract report

  EXAMPLE 2: Dump SPI flash with ch341a programmer

    Step 1 - Power OFF the target device
    Step 2 - Clip onto SPI chip (pin 1 = dot on chip)
    Step 3 - Run:
               firmxtract extract --method spi --programmer ch341a_spi
    Step 4 - View results:
               firmxtract report

  EXAMPLE 3: Analyze a firmware file you already have

    firmxtract analyze /path/to/firmware.bin

  EXAMPLE 4: Auto-detect everything (simplest)

    firmxtract extract
    (FirmXtract tries UART first, falls back to SPI if UART fails)

  EXAMPLE 5: Extract then manually analyze later

    firmxtract extract --no-analyze
    firmxtract analyze ~/.firmxtract/sessions/latest/firmware.bin

--------------------------------------------------------------------------------
  HARDWARE WIRING REFERENCE
--------------------------------------------------------------------------------

  UART WIRING:
    Your USB adapter        Target board
    ─────────────           ─────────────
    TX              ──>     RX
    RX              <──     TX
    GND             ───     GND
    VCC             DO NOT CONNECT (if board is externally powered)

  IMPORTANT: Never connect VCC if the target board is already powered.
             This can permanently damage both devices.

  LINUX PERMISSION FIX (if you get "Permission denied" on serial port):
    sudo usermod -aG dialout $USER
    Then log out and log back in.

  SPI WIRING (ch341a):
    1. Power the target device OFF completely
    2. Attach the SOIC8 clip to the flash chip
    3. Pin 1 of the chip is marked with a small dot or notch
    4. Connect ch341a USB to your computer
    5. Verify with: firmxtract info  (should show the programmer)
    6. Run: firmxtract extract --method spi

  COMMON UART DEVICE NAMES:
    Linux:
      CH340 adapter  ->  /dev/ttyUSB0
      CP2102         ->  /dev/ttyUSB0
      FTDI           ->  /dev/ttyUSB0  or  /dev/ttyACM0
    macOS:
      Any adapter    ->  /dev/cu.usbserial-XXXXXXXX

--------------------------------------------------------------------------------
  SESSION OUTPUT (where files are saved)
--------------------------------------------------------------------------------

  Every run creates a timestamped folder:
    ~/.firmxtract/sessions/YYYYMMDD_HHMMSS/

  Contents:
    firmware.bin              Raw firmware dump (SPI) or UART dd extraction
    uart_capture.log          UART boot log (fallback if shell not accessible)
    _firmware.bin.extracted/  Filesystem extracted by binwalk
      squashfs-root/          Unpacked root filesystem
        etc/passwd            (example files found inside)
        etc/shadow
        usr/bin/
        ...
    binwalk_scan.log          All signatures found (CSV format)
    report.json               Full machine-readable JSON report

  View in terminal:   firmxtract report
  View raw JSON:      cat ~/.firmxtract/sessions/<session>/report.json

--------------------------------------------------------------------------------
  CONFIGURATION (optional)
--------------------------------------------------------------------------------

  FirmXtract works with zero configuration using built-in defaults.
  To customize, create:  ~/.firmxtract/config.toml

  Example config file:

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
    matryoshka = true

    [output]
    base_dir = "~/.firmxtract/sessions"

  Environment variable overrides:
    export FIRMXTRACT_OUTPUT_DIR=/mnt/data/sessions
    export FIRMXTRACT_SPI_PROGRAMMER=ft2232_spi
    export FIRMXTRACT_UART_BAUD=115200
    export FIRMXTRACT_FLASHROM_PATH=/usr/local/bin/flashrom
    export FIRMXTRACT_BINWALK_PATH=/usr/bin/binwalk

--------------------------------------------------------------------------------
  RUNNING TESTS
--------------------------------------------------------------------------------

  All tests run without hardware:
    pytest -m "not hardware"

  With coverage report:
    pytest -m "not hardware" --cov=src/firmxtract --cov-report=term-missing

  Hardware tests (physical device required):
    pytest -m hardware -v

--------------------------------------------------------------------------------
  TROUBLESHOOTING
--------------------------------------------------------------------------------

  Problem:  "command not found: firmxtract"
  Fix:      Make sure your virtual environment is activated:
              source .venv/bin/activate
            Then reinstall:
              pip install -e .

  Problem:  "Permission denied" on /dev/ttyUSB0
  Fix:      sudo usermod -aG dialout $USER
            Log out and log back in.

  Problem:  "flashrom not found"
  Fix:      sudo apt install flashrom
            or: brew install flashrom

  Problem:  "binwalk not found"
  Fix:      pip install binwalk
            or: sudo apt install binwalk

  Problem:  "No serial ports detected" in firmxtract info
  Fix:      Unplug and replug USB adapter. Check dmesg | tail -20 for errors.

  Problem:  UART produces garbled output
  Fix:      Wrong baud rate. Run baud sweep:
              firmxtract extract --port /dev/ttyUSB0
            FirmXtract will auto-sweep common rates.

  Problem:  pip install fails with "externally managed environment"
  Fix:      Use a virtual environment:
              python3 -m venv .venv && source .venv/bin/activate
              pip install -e ".[dev]"
            Or run: bash install.sh  (handles this automatically)

--------------------------------------------------------------------------------
  PROJECT STRUCTURE
--------------------------------------------------------------------------------

  firmxtract/
  |-- src/firmxtract/
  |   |-- cli/main.py          Command-line interface (6 commands)
  |   |-- core/
  |   |   |-- orchestrator.py  Pipeline controller
  |   |   +-- session.py       Session state and JSON report
  |   |-- hardware/
  |   |   |-- hal.py           Hardware Abstraction Layer
  |   |   |-- uart.py          UART extraction (baud sweep, dd+base64)
  |   |   +-- spi.py           SPI extraction (flashrom wrapper)
  |   |-- extraction/
  |   |   +-- binwalk_wrapper.py  binwalk integration
  |   |-- analysis/
  |   |   +-- secrets.py       Secrets hunter (20 patterns)
  |   +-- utils/
  |       |-- logger.py        Structured logging
  |       +-- config.py        TOML config + env vars
  |-- tests/                   113 tests (no hardware needed)
  |-- pyproject.toml           Python package config
  |-- requirements-dev.txt     Dev dependencies
  |-- install.sh               Automated installer
  |-- README.txt               This file
  +-- README.md                Full documentation (Markdown)

--------------------------------------------------------------------------------
  VERSION HISTORY
--------------------------------------------------------------------------------

  v0.1.0  -  Phase 1 complete
    - UART extraction with auto baud detection and dd+base64 transfer
    - SPI flash dump via flashrom with programmer auto-detection
    - binwalk integration for firmware analysis
    - Secrets hunter with 20 detection patterns
    - 6 CLI commands, 113 tests, full session reporting

================================================================================
  For full documentation see README.md
  For project conventions see CLAUDE.md
  For architecture details see ARCHITECTURE.md
================================================================================
