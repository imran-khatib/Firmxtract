# CLAUDE.md — FirmXtract Project Conventions

**Last Updated:** April 2026  
**Purpose:** This file contains non-negotiable rules for all contributors (humans and AI). Read it before writing or modifying any code.

FirmXtract is an early-stage, production-bound IoT firmware extraction & red-teaming framework. We aim for clean, secure, extensible, and safe hardware interaction.

---

## 1. Language & Runtime

- **Python**: 3.11+ only. Use modern features (`match/case`, `tomllib`, `ExceptionGroup`, `pathlib`).
- **Rust**: 1.75+ for performance-critical modules (planned for baud-rate scanning, entropy analysis, binary parsing).
- Type hints are **mandatory** for all public APIs and class methods.
- Never use `shell=True` in `subprocess` unless explicitly documented and security-reviewed.

---

## 2. Code Style & Quality

### Python
- **Linter & Formatter**: `ruff` (linting) + `black --line-length 100` (formatting).
- **Docstrings**: Google style for all public classes, functions, and modules.
- Prefer `dataclasses` or Pydantic v2 models over raw dicts for configuration and results.
- No bare `except:` — always catch specific exceptions.

### Rust
- Run `cargo clippy --all-targets -- -D warnings` before every commit (zero warnings policy).
- Use `thiserror` for custom errors and `anyhow` for application-level error handling.
- All public items must have `///` documentation comments.

**Enforcement**: CI must pass `ruff check`, `black --check`, and `cargo clippy`.

---

## 3. Error Handling & Safety Philosophy

- **Hardware Safety First** (non-negotiable):
  - All operations are **read-only by default**.
  - Any write/flash operation requires `--write` flag + explicit user confirmation.
  - Always warn about voltage (3.3V vs 5V) and pinouts before hardware connection.
  - Verify chip ID / signature before destructive operations.
  - Every hardware I/O must have configurable timeouts.

- **General Rules**:
  - Hardware errors → `WARNING` + graceful fallback when possible.
  - Unrecoverable errors → `CRITICAL` + clean exit with code `1`.
  - Never silently swallow exceptions.
  - Every subprocess must check `returncode` and capture `stderr`.

---

## 4. Logging Standards

Use the centralized logger in `src/firmxtract/utils/logger.py` — **never** use `print()` in production paths.

Log levels:
- **DEBUG**: Internal details (raw bytes, subprocess output, timing).
- **INFO**: User-facing progress ("UART detected on /dev/ttyUSB0 @ 115200", "Extraction completed").
- **WARNING**: Recoverable issues ("Baud rate timeout, falling back...").
- **ERROR**: Operation failed but session can continue.
- **CRITICAL**: Fatal error, session aborts.

Never log credentials, passwords, or raw memory dumps at INFO level or higher.

---

## 5. Architecture & Module Boundaries (Strict)

- `cli/` → Only handles argument parsing and user interaction. Calls `core/` only.
- `core/` → Orchestration, pipeline, session management. Coordinates other layers.
- `hardware/` → Pure hardware I/O (UART, SPI, future JTAG). No business logic.
- `extraction/` → Firmware dumping and unpacking (binwalk, flashrom wrappers).
- `analysis/` → Static analysis, secrets scanning, filesystem inspection.
- `plugins/` → Extensible modules (must implement `Plugin` interface).
- `utils/` → Pure utilities with **zero** internal dependencies.

All layers must respect **strict separation of concerns**.

---

## 6. Testing Strategy

- Every new feature or bug fix must include tests.
- Unit tests: Fast, no hardware required.
- Hardware tests: Marked with `@pytest.mark.hardware`.
- Run `pytest -m "not hardware"` in CI.
- Mocks belong in `tests/mocks/` — never mock inside the module being tested.

---

## 7. Git & Commit Conventions

- One logical change per commit.
- Commit message format: `[area] Short imperative description`
  - Examples: `[core] Fix session directory auto-creation`, `[uart] Add baud-rate auto-sweep`
- After significant changes, update `ARCHITECTURE.md`, `CHANGELOG.md`, and `TODO.md`.
- Branch naming: `feature/*`, `fix/*`, `refactor/*`, `plugin/*`.

---

## 8. Dependencies & Security

- Prefer Python standard library where reasonable.
- Every new dependency requires justification in the PR.
- Pin major versions in `pyproject.toml` (no `*`).
- Audit new dependencies for supply-chain risks.
- Session directories must be created with `mode=0o700`.
- All user-supplied paths must be sanitized and validated.

---

## 9. Development Workflow

- Always work on a feature branch.
- Run full lint + test suite before pushing.
- Update this `CLAUDE.md` only when conventions actually change (and reference the change in the commit).

---

**Remember**: This is a **hardware security tool**. A single mistake can brick devices or expose sensitive data. Prioritize safety, clarity, and extensibility over cleverness.

When in doubt — ask: "Is this change safe, modular, and well-tested?"