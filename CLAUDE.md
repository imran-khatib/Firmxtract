# CLAUDE.md — FirmXtract Project Conventions

This file defines non-negotiable conventions for all contributors (human and AI).
Read this before touching any code.

---

## Language & Runtime

- Python **3.11+** only. Use match/case, `tomllib`, `ExceptionGroup` where appropriate.
- Rust **1.75+** for native modules. Always run `cargo clippy` before commit.
- No shell=True in subprocess calls unless there is a documented, audited reason.
- Type hints are **mandatory** on all public functions and class methods.

---

## Code Style

### Python
- Follow **PEP8** strictly. Use `ruff` for linting, `black` for formatting (line length: 100).
- Docstrings: Google style on all public classes and functions.
- No bare `except:` — always catch specific exceptions.
- Use `pathlib.Path` everywhere, never raw string paths.
- Prefer `dataclasses` or `pydantic` models over plain dicts for structured data.

### Rust
- Run `cargo clippy -- -D warnings` — zero warnings policy.
- Use `thiserror` for error types, `anyhow` for application-level errors.
- Document all public items with `///` doc comments.

---

## Error Handling Philosophy

- Hardware errors → log WARNING + attempt fallback → log fallback result
- Unrecoverable errors → log CRITICAL + clean exit with code 1
- NEVER silently swallow exceptions
- Every subprocess call must check returncode and capture stderr

---

## Hardware Safety Rules (CRITICAL)

1. **Read-only by default.** Never write to a device without `--write` flag + interactive confirmation.
2. **Voltage warnings.** Always warn user before connecting to unknown hardware.
3. **No assumptions about chip state.** Verify chip ID before any flash operation.
4. **Timeout everything.** All hardware I/O must have explicit timeouts.

---

## Logging Standards

- Use `src/utils/logger.py` — never print() in production code.
- DEBUG: fine-grained internal state (hardware bytes, subprocess output)
- INFO: user-visible progress ("Detected UART on /dev/ttyUSB0 @ 115200")
- WARNING: recoverable issues ("UART read timeout, retrying...")
- ERROR: operation failed but session continues
- CRITICAL: unrecoverable, session must abort

---

## File & Commit Conventions

- One logical change per commit.
- Commit message format: `[module] Short description` (e.g., `[uart] Add baud rate sweep`)
- After major changes: update both `TODO.md` and `ARCHITECTURE.md`.
- New hardware interface? → Update HAL + add stub test in `tests/`.

---

## Testing

- All new code must have a corresponding test.
- Hardware-dependent tests: decorate with `@pytest.mark.hardware`.
- Run `pytest -m "not hardware"` for CI (no physical device needed).
- Mocks live in `tests/mocks/` — never mock inside the module under test.

---

## Module Boundaries (Strict)

- `cli/` → calls `core/` only. Never imports from `hardware/` directly.
- `core/` → orchestrates `hardware/`, `extraction/`, `analysis/`. No I/O logic here.
- `hardware/` → only hardware I/O. No business logic.
- `utils/` → zero dependencies on other internal modules.

---

## Dependency Policy

- Prefer stdlib over third-party where reasonable.
- Every new dependency must be justified in the PR description.
- Pin major versions in `pyproject.toml`. No floating `*` versions.
- Audit new deps for supply chain risk before adding.

---

## Security

- Never log credentials, keys, or raw memory dumps at INFO or above.
- Session output dirs: created with mode 0o700.
- All user-supplied paths must be validated/sanitized before use.
- Subprocess args always passed as lists, never formatted strings with user input.
