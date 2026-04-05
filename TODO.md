# FirmXtract — TODO

Last updated: 2026-04-02

Legend: ✅ Done | 🔄 In Progress | ⬜ Pending | 🔴 Blocked

---

## Phase 1: Core CLI + UART/SPI Extraction  ✅ COMPLETE


### Project Scaffold
- ✅ Folder structure created (src/firmxtract/ layout fixed)
- ✅ ARCHITECTURE.md written
- ✅ CLAUDE.md written
- ✅ requirements-dev.txt created
- ✅ TODO.md created
- ✅ pyproject.toml (setuptools Phase 1; Maturin stub commented for Phase 2)
- ✅ Cargo.toml (Rust workspace stub)
- ✅ README.md (complete with install, quickstart, hardware setup, troubleshooting)

### CLI
- ✅ `src/cli/main.py` — extract, analyze, console, report, info, version commands
- ⬜ `--verbose` / `--quiet` flags wired to logger
- ⬜ `--output-dir` flag with default to `~/.firmxtract/sessions/<timestamp>/`
- ✅ Shell completion (built into typer via add_completion=True)

### Core
- ✅ `src/core/orchestrator.py` — run() + run_with_interfaces() public API
- ✅ `src/core/session.py` — full session lifecycle + JSON report
- ✅ JSON report output at end of session
- ✅ `firmxtract report` command — view last session
- ⬜ Session resume (re-analyze existing dump without re-extracting)

### Hardware Abstraction Layer
- ✅ `src/hardware/hal.py` — HAL base classes + interface registry
- ⬜ HAL plugin discovery (entry_points based)

### UART Module
- ✅ `src/hardware/uart.py` — full extraction: baud sweep, shell detect, MTD, dd+base64
- ⬜ Baud rate sweep (9600 → 921600)
- ⬜ U-Boot / Linux shell heuristic detection
- ✅ Interactive console mode (`firmxtract console --port /dev/ttyUSB0`)
- ⬜ Automated dump via `dmesg`, `cat /proc/mtd`, `dd` commands

### SPI Module
- 🔄 `src/hardware/spi.py` — flashrom subprocess wrapper
- ⬜ Programmer auto-detection (ch341a, ft2232h, serprog, buspirate)
- ⬜ Chip ID verification before full dump
- ⬜ MD5/SHA256 checksum of dump
- ⬜ Retry logic on partial read failure

### Extraction
- 🔄 `src/extraction/binwalk_wrapper.py` — binwalk integration
- ⬜ Parse binwalk JSON output into structured results
- ⬜ Recursive extraction mode
- ⬜ File system type identification

### Analysis (Phase 1 Stubs)
- ✅ `src/analysis/secrets.py` — working, 20 patterns, entropy filter
- ✅ Full secrets hunter: 20 patterns, binary filter, deduplication, severity ranking

### Utils
- 🔄 `src/utils/logger.py` — rich + logging
- 🔄 `src/utils/config.py` — TOML config loader

### Tests
- ⬜ `tests/test_uart.py` — mock serial port tests
- ⬜ `tests/test_spi.py` — mock flashrom subprocess tests
- ⬜ `tests/test_orchestrator.py` — pipeline integration test

---

## Phase 2: Rust Integration + Advanced Analysis (Future)

- ⬜ PyO3 + Maturin setup
- ⬜ Rust UART baud rate scanner
- ⬜ Rust entropy analyzer
- ⬜ radare2 headless integration
- ⬜ JTAG detection module (OpenOCD wrapper)
- ⬜ asyncio pipeline for parallel extraction

## Phase 3: GUI + LLM Co-pilot (Future)

- ⬜ Tauri or Dear PyGui shell
- ⬜ Ollama integration for firmware co-pilot
- ⬜ Neo4j attack graph database
- ⬜ Vulnerability dashboard
- ⬜ Attack path generation
