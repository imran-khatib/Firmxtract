# Changelog

All notable changes to FirmXtract are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [0.1.0] — 2026-04-05

### Phase 1 — Initial Release

#### Added
- **CLI** — 6 commands: `extract`, `analyze`, `console`, `report`, `info`, `version`
- **UART extraction** — serial port enumeration, baud rate auto-sweep (9600–921600),
  U-Boot / Linux shell detection, automated dd+base64 firmware transfer over serial,
  `/proc/mtd` parsing and best-partition selection, graceful fallback to boot log capture
- **SPI extraction** — flashrom subprocess wrapper, programmer auto-detection
  (ch341a, ft2232h, buspirate, serprog), chip ID verification, read-verify with SHA256,
  retry logic
- **UART → SPI automatic fallback** — if UART extraction fails, SPI is attempted
- **binwalk integration** — signature scan, recursive filesystem extraction,
  CSV log parsing
- **Secrets hunter** — 20 regex patterns across 5 categories (private keys,
  credentials, WiFi PSK, cloud/API keys, sensitive config), binary file filtering,
  entropy-based skip, deduplication, severity ranking (CRITICAL/HIGH/MEDIUM/LOW),
  redacted logging (secrets never stored plaintext)
- **Hardware Abstraction Layer** — pluggable detector registry (UART, SPI, JTAG stub)
- **Session management** — timestamped output directories, JSON report generation,
  `firmxtract report` viewer
- **Interactive UART console** — pass-through terminal with Ctrl+] exit (like telnet)
- **Configuration** — TOML config file + environment variable overrides
- **Testing** — 113 tests across 4 modules, full mock layer, hardware test separation
- **Packaging** — `pip install -e .` installable, Python 3.10+ compatible,
  `install.sh` automated installer for Linux and macOS

#### Security
- All subprocess calls use list form — no `shell=True`
- Read-only by default — never writes to flash without explicit flag
- Secrets never logged above DEBUG level
- Session output directories created with mode 0o700
- Chip ID verified before any SPI dump operation

---

## [Unreleased] — Phase 2 (planned)

- Rust native modules via PyO3 + Maturin (fast baud scan, entropy analysis)
- JTAG / OpenOCD integration
- radare2 / Ghidra headless firmware analysis
- Async pipeline for parallel extraction
- U-Boot automated memory dump (md.b commands)

## [Unreleased] — Phase 3 (planned)

- Tauri GUI frontend
- Ollama local LLM co-pilot for firmware analysis
- Neo4j attack graph database
- Vulnerability dashboard
- Attack path generation
