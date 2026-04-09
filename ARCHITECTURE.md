# FirmXtract — Architecture Document

**Version:** 0.1.0 (Phase 1)
**Last Updated:** 2026-04-02
**Status:** Active Development

---

## Vision

FirmXtract is a unified IoT firmware extraction, analysis, and red-teaming framework.
Goal: One command → hardware auto-detect → firmware extraction → unpacking → analysis →
secrets hunting → emulation → vulnerability dashboard + attack path generation.

---

## Phase 1 Scope  ✅ COMPLETE

- UART detection and interactive console
- SPI flash dump via flashrom subprocess wrapper
- Fallback logic: UART failure → SPI attempt
- binwalk integration for post-extraction analysis
- CLI entry point (typer)
- Hardware Abstraction Layer (Python, Rust stubs for Phase 2)
- Structured logging and session tracking

---

## High-Level Data Flow

```
User invokes CLI
      │
      ▼
  Orchestrator.run()
      │
      ├─── SessionManager (tracks run state, paths, results)
      │
      ├─── HAL.detect_interfaces()
      │         ├── UART → UARTHandler.detect() → connect() → dump()
      │         └── SPI  → SPIHandler.detect()  → dump()    (fallback)
      │
      ├─── ExtractionResult (raw binary blob + metadata)
      │
      ├─── BinwalkWrapper.analyze(firmware_path)
      │         └── Unpacks, identifies file systems, returns findings
      │
      ├─── SecretsHunter.analyze(extracted_dir | firmware_path)
      │         └── 20 regex patterns, binary filter, severity ranking
      │
      └─── Report (console + JSON output)
```

---

## Module Responsibilities

### `src/cli/main.py`
- Typer-based CLI entry point
- Commands: `extract`, `analyze`, `info`, `version`
- Parses user flags, instantiates Orchestrator, handles top-level errors

### `src/core/orchestrator.py`
- Central pipeline controller
- Coordinates HAL → extraction → analysis → reporting
- Does NOT contain hardware or analysis logic itself

### `src/core/session.py`
- Immutable-ish run context: output paths, timestamps, device metadata
- Passed by reference through the entire pipeline

### `src/hardware/hal.py`
- Hardware Abstraction Layer
- Abstracts UART/SPI/JTAG behind a common interface
- Phase 2: will delegate performance-critical paths to Rust via PyO3

### `src/hardware/uart.py`
- Enumerate serial ports via pyserial
- Baud rate auto-detection (common rates: 9600, 38400, 57600, 115200, 230400)
- Interactive console capture mode
- U-Boot / shell detection heuristics

### `src/hardware/spi.py`
- flashrom subprocess wrapper
- Programmer auto-detect (ch341a, ft2232h, buspirate, serprog, etc.)
- Chip ID detection before full dump
- Checksum verification post-dump

### `src/extraction/binwalk_wrapper.py`
- Subprocess wrapper around binwalk
- Parses binwalk JSON/text output into structured results
- Recursive extraction support
- Returns list of identified signatures + extracted paths

### `src/analysis/secrets.py`
- Phase 1: Placeholder
- Phase 2: grep-based + regex secrets hunter (credentials, keys, tokens)
- Phase 3: LLM-assisted analysis via Ollama

### `src/utils/logger.py`
- Structured logging (rich + Python logging)
- Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
- File + console handlers

### `src/utils/config.py`
- TOML-based config (~/.firmxtract/config.toml)
- Environment variable overrides
- Defaults for all hardware parameters

---

## Phase 2 Preview (Rust Integration)

Rust modules will be compiled as Python extension modules via PyO3 + Maturin.

Planned Rust modules:
- `rust/src/uart_scanner.rs` — High-speed baud rate detection
- `rust/src/spi_parser.rs`  — Low-level SPI protocol parser
- `rust/src/entropy.rs`     — Fast entropy analysis on firmware blobs

Python will import these as: `from firmxtract_native import uart_scanner`

---

## Technology Stack

| Layer            | Technology                        |
|------------------|-----------------------------------|
| CLI              | Python 3.11+ / Typer              |
| Orchestration    | Python / asyncio (Phase 2)        |
| Hardware Comms   | pyserial, flashrom (subprocess)   |
| Firmware Analysis| binwalk, radare2 (Phase 2)        |
| Native Perf      | Rust + PyO3 + Maturin (Phase 2)   |
| GUI              | Tauri or Dear PyGui (Phase 3)     |
| Database         | SQLite → Neo4j (Phase 3)          |
| LLM Co-pilot     | Ollama local / OpenAI (Phase 3)   |

---

## Security Considerations

- Never write to target device without explicit `--write` flag + confirmation prompt
- Voltage detection warnings before hardware connection (Phase 2)
- All subprocess calls use `shlex.split` or list form — no shell=True unless audited
- Session output directories are chmod 700
- No secrets logged at INFO level or above

---

## Testing Strategy

- Unit tests: `tests/` with pytest
- Hardware tests: marked `@pytest.mark.hardware` — skipped in CI, require real devices
- Mock interfaces for all hardware modules (pyserial Mock, flashrom stub)
- 113 test functions across 4 test modules
- Target: >80% coverage on non-hardware code

---

## Directory Layout

```
firmxtract/
├── src/
│   ├── core/          # Orchestrator, Session
│   ├── hardware/      # HAL, UART, SPI
│   ├── extraction/    # binwalk wrapper
│   ├── analysis/      # Secrets, vuln scanning
│   ├── cli/           # Typer entry point
│   └── utils/         # Logger, Config
├── rust/              # PyO3 native modules (Phase 2)
├── tests/             # pytest suite
├── docs/              # Extended docs
├── Cargo.toml         # Rust workspace
├── pyproject.toml     # Python packaging + maturin
├── CLAUDE.md          # Project conventions
├── ARCHITECTURE.md    # This file
├── TODO.md            # Task tracking
└── README.md          # User-facing docs
```
