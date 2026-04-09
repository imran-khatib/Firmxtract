# Contributing to FirmXtract

Thank you for your interest in contributing. This document explains how to
get set up, the standards we follow, and how to submit changes.

---

## Before You Start

- Read [CLAUDE.md](CLAUDE.md) — it defines all coding conventions, module
  boundary rules, and hardware safety requirements. Non-negotiable.
- Check [TODO.md](TODO.md) for planned work before starting something new.
- Open an issue first for large changes — discuss before implementing.

---

## Development Setup

```bash
git clone https://github.com/imran-khatib/Firmxtract
cd Firmxtract
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Verify everything works:
```bash
pytest -m "not hardware"
ruff check src/ tests/
mypy src/
```

---

## Running Tests

```bash
# All tests — no hardware needed
pytest -m "not hardware"

# With coverage
pytest -m "not hardware" --cov=src/firmxtract --cov-report=term-missing

# Hardware tests (physical device required)
pytest -m hardware -v
```

New code must include tests. Hardware-dependent tests must be marked
`@pytest.mark.hardware`.

---

## Code Standards (summary — full detail in CLAUDE.md)

- **Python 3.10+** — type hints on all public functions
- **`from __future__ import annotations`** — required in every source file
- **PEP8** — enforced by `ruff` (line length: 100)
- **Formatting** — `black` (line length: 100)
- **No bare `except:`** — always catch specific exceptions
- **No `shell=True`** in subprocess calls
- **No `print()`** outside `cli/` — use `log = get_logger(__name__)`
- **Google-style docstrings** on all public classes and functions

Run the full check before submitting:
```bash
ruff check src/ tests/ && black --check src/ tests/ && mypy src/ && pytest -m "not hardware"
```

---

## Module Boundaries (strict)

| Module | Can import from | Cannot import from |
|--------|----------------|--------------------|
| `cli/` | `core/` only | `hardware/`, `analysis/` directly |
| `core/` | `hardware/`, `extraction/`, `analysis/`, `utils/` | — |
| `hardware/` | `utils/`, `core/session` | `cli/`, `extraction/`, `analysis/` |
| `utils/` | stdlib only | anything internal |

---

## Hardware Safety Rules

1. Never write to a device without an explicit `--write` flag + confirmation
2. Always verify chip ID before a full SPI dump
3. Always warn about voltage before connecting
4. All hardware I/O must have explicit timeouts
5. New hardware modules must include a mock for testing

---

## Submitting a Pull Request

1. Fork the repo and create a branch: `git checkout -b feature/my-feature`
2. Make your changes with tests
3. Run the full check (see above) — must pass with zero issues
4. Update `CHANGELOG.md` under `[Unreleased]`
5. Update `TODO.md` if completing a tracked task
6. Submit the PR with a clear description of what and why

---

## Reporting Bugs

Open a GitHub issue with:
- FirmXtract version (`firmxtract version`)
- OS and Python version
- Hardware being used (adapter type, target device if known)
- Full command run and full output (redact any sensitive data)
- Steps to reproduce

---

## Security Issues

Do not open public issues for security vulnerabilities.
Email the maintainers directly. Include a proof-of-concept if possible.
