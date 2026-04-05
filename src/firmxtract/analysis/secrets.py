"""
FirmXtract Secrets Hunter.

Walks an extracted firmware filesystem (or raw binary) and applies
regex patterns to find credentials, keys, tokens, and other secrets.

Strategy:
  1. Walk all files in extracted_dir (or raw firmware if no extraction)
  2. Skip high-entropy binary blobs (images, compressed data)
  3. Apply SECRET_PATTERNS regex set to each readable file
  4. Deduplicate and rank findings by severity
  5. Return structured AnalysisResult

Phase 3: LLM-assisted triage via Ollama for false-positive reduction.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from firmxtract.core.session import AnalysisResult
from firmxtract.utils.logger import get_logger

if TYPE_CHECKING:
    from firmxtract.core.session import Session

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Files larger than this are read in chunks / skipped for pattern matching
_MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

# Entropy threshold: files above this are mostly binary/compressed — skip
_ENTROPY_SKIP_THRESHOLD = 7.2  # bits per byte (max theoretical = 8.0)

# Extensions we always skip (binary formats with no readable secrets)
_SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".wav", ".ogg",
    ".gz", ".xz", ".bz2", ".lzma", ".zst",
    ".zip", ".tar", ".rar", ".7z",
    ".squashfs", ".jffs2", ".ubifs",
    ".elf", ".so", ".ko", ".a",
    ".bin",  # raw binaries — handled separately
    ".dtb",  # device tree blobs
}

# Extensions we always include (known text formats)
_TEXT_EXTENSIONS = {
    ".conf", ".config", ".cfg", ".ini", ".toml", ".yaml", ".yml", ".json",
    ".txt", ".log", ".sh", ".py", ".lua", ".rb", ".pl",
    ".xml", ".html", ".htm",
    ".env", ".properties",
    "",  # no extension — often scripts or config files
}

# ---------------------------------------------------------------------------
# Secret patterns
# ---------------------------------------------------------------------------

@dataclass
class PatternDef:
    """One secret detection pattern."""
    name: str
    severity: str              # CRITICAL | HIGH | MEDIUM | LOW
    pattern: re.Pattern[bytes]
    description: str


SECRET_PATTERNS: list[PatternDef] = [
    PatternDef(
        name="private_key",
        severity="CRITICAL",
        pattern=re.compile(
            rb"-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            re.IGNORECASE,
        ),
        description="Private cryptographic key (RSA/EC/DSA/OpenSSH)",
    ),
    PatternDef(
        name="hardcoded_password",
        severity="HIGH",
        pattern=re.compile(
            rb'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?(?!\s)([\w!@#$%^&*()\-+]{6,})',
        ),
        description="Hardcoded password field",
    ),
    PatternDef(
        name="aws_access_key",
        severity="HIGH",
        pattern=re.compile(rb"AKIA[0-9A-Z]{16}"),
        description="AWS Access Key ID",
    ),
    PatternDef(
        name="aws_secret_key",
        severity="CRITICAL",
        pattern=re.compile(
            rb'(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})',
        ),
        description="AWS Secret Access Key",
    ),
    PatternDef(
        name="generic_api_key",
        severity="MEDIUM",
        pattern=re.compile(
            rb'(?i)(?:api[_\-]?key|apikey|api[_\-]?token)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})',
        ),
        description="Generic API key or token",
    ),
    PatternDef(
        name="wifi_psk",
        severity="HIGH",
        pattern=re.compile(
            rb'(?i)(?:wpa[_\-]?passphrase|psk|wifi[_\-]?password)\s*[=:]\s*["\']?(.{8,})',
        ),
        description="WiFi PSK / passphrase",
    ),
    PatternDef(
        name="default_credentials",
        severity="HIGH",
        pattern=re.compile(
            rb'(?i)(?:telnet|ftp|ssh)[_\-]?(?:user|pass|login|password)\s*[=:]\s*["\']?(\w+)',
        ),
        description="Default service credentials (telnet/ftp/ssh)",
    ),
    PatternDef(
        name="jwt_token",
        severity="MEDIUM",
        pattern=re.compile(
            rb"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        ),
        description="JSON Web Token (JWT)",
    ),
    PatternDef(
        name="rsa_public_key",
        severity="LOW",
        pattern=re.compile(
            rb"-----BEGIN (?:RSA )?PUBLIC KEY-----",
            re.IGNORECASE,
        ),
        description="Public key material (informational)",
    ),
    PatternDef(
        name="certificate",
        severity="LOW",
        pattern=re.compile(rb"-----BEGIN CERTIFICATE-----", re.IGNORECASE),
        description="X.509 certificate",
    ),
    PatternDef(
        name="url_with_credentials",
        severity="HIGH",
        pattern=re.compile(
            rb'(?i)(?:https?|ftp)://([^:@\s]+):([^@\s/]+)@[^\s"\']+',
        ),
        description="URL containing embedded credentials",
    ),
    PatternDef(
        name="private_ip_config",
        severity="LOW",
        pattern=re.compile(
            rb'(?i)(?:server|host|ip[_\-]?addr(?:ess)?)\s*[=:]\s*"?(10\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.|192\.168\.)[\d.]+',
        ),
        description="Hardcoded private IP address",
    ),
]

# Severity ordering for sorting
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# ---------------------------------------------------------------------------
# Entropy helpers
# ---------------------------------------------------------------------------

def _byte_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy of a byte sequence in bits-per-byte.

    Args:
        data: Input bytes (at least 64 bytes for meaningful result).

    Returns:
        Entropy value 0.0 (constant) to 8.0 (perfectly random).
    """
    if len(data) < 64:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _is_likely_binary(data: bytes, sample_size: int = 4096) -> bool:
    """
    Return True if data is likely a binary blob (not worth scanning for text secrets).

    Uses a combination of entropy check and null-byte / non-printable ratio.
    """
    sample = data[:sample_size]
    if not sample:
        return False

    # High entropy = compressed / encrypted — skip
    if _byte_entropy(sample) > _ENTROPY_SKIP_THRESHOLD:
        return True

    # High null-byte ratio = binary
    null_count = sample.count(0)
    if null_count / len(sample) > 0.10:
        return True

    return False


# ---------------------------------------------------------------------------
# File selection
# ---------------------------------------------------------------------------

def _should_scan_file(path: Path) -> bool:
    """
    Return True if this file should be scanned for secrets.

    Decision order:
      1. Skip known binary extensions unconditionally
      2. Skip files over size limit
      3. Always include known text extensions
      4. For unknown extensions: check entropy
    """
    ext = path.suffix.lower()

    if ext in _SKIP_EXTENSIONS:
        return False

    try:
        size = path.stat().st_size
    except OSError:
        return False

    if size == 0:
        return False

    if size > _MAX_FILE_SIZE:
        log.debug(f"  Skipping (too large): {path}")
        return False

    if ext in _TEXT_EXTENSIONS:
        return True

    # Unknown extension — read a sample and check entropy
    try:
        with open(path, "rb") as f:
            sample = f.read(4096)
        return not _is_likely_binary(sample)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Pattern matching
# ---------------------------------------------------------------------------

@dataclass
class SecretFinding:
    """One discovered secret or sensitive value."""
    pattern_name: str
    severity: str
    description: str
    file_path: str        # relative to scan root
    line_number: int
    matched_text: str     # truncated match preview (no full secret logged)


def _scan_file(
    path: Path,
    root: Path,
    patterns: list[PatternDef],
) -> list[SecretFinding]:
    """
    Scan one file against all patterns.

    Args:
        path: Absolute path to file.
        root: Scan root for computing relative paths.
        patterns: List of PatternDef to apply.

    Returns:
        List of SecretFinding (may be empty).
    """
    findings: list[SecretFinding] = []
    try:
        data = path.read_bytes()
    except OSError as exc:
        log.debug(f"  Cannot read {path}: {exc}")
        return findings

    if _is_likely_binary(data):
        return findings

    rel = str(path.relative_to(root))
    lines = data.split(b"\n")

    for pat_def in patterns:
        for line_no, line in enumerate(lines, start=1):
            for match in pat_def.pattern.finditer(line):
                raw = match.group(0)
                # Truncate displayed match to avoid logging full secrets
                preview = raw[:60].decode(errors="replace")
                if len(raw) > 60:
                    preview += "..."
                findings.append(SecretFinding(
                    pattern_name=pat_def.name,
                    severity=pat_def.severity,
                    description=pat_def.description,
                    file_path=rel,
                    line_number=line_no,
                    matched_text=preview,
                ))

    return findings


def _deduplicate(findings: list[SecretFinding]) -> list[SecretFinding]:
    """Remove exact duplicates (same file + line + pattern)."""
    seen: set[tuple[str, int, str]] = set()
    result: list[SecretFinding] = []
    for f in findings:
        key = (f.file_path, f.line_number, f.pattern_name)
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


# ---------------------------------------------------------------------------
# SecretsHunter
# ---------------------------------------------------------------------------

class SecretsHunter:
    """
    Scans an extracted firmware filesystem for credentials and secrets.

    Skips high-entropy binary blobs to reduce false positives and
    scanning time. Results are ranked by severity.

    Usage:
        hunter = SecretsHunter(session)
        result = hunter.analyze(extracted_dir)
    """

    def __init__(self, session: "Session") -> None:
        self.session = session

    def analyze(self, target: Path) -> AnalysisResult:
        """
        Scan target directory (or single file) for secrets.

        Args:
            target: Directory to walk, or single firmware/capture file.

        Returns:
            AnalysisResult with findings list (each finding is a dict).
        """
        if not target.exists():
            msg = f"Secrets scan target not found: {target}"
            log.warning(msg)
            return AnalysisResult(tool="secrets", success=False, error_message=msg)

        log.info(f"Secrets scan: {target}")

        files_to_scan: list[Path] = []
        root = target

        if target.is_dir():
            files_to_scan = [f for f in target.rglob("*") if f.is_file()]
            log.info(f"  {len(files_to_scan)} files in directory")
        else:
            files_to_scan = [target]
            root = target.parent

        scannable = [f for f in files_to_scan if _should_scan_file(f)]
        skipped = len(files_to_scan) - len(scannable)
        log.info(f"  Scanning {len(scannable)} files ({skipped} skipped — binary/large)")

        all_findings: list[SecretFinding] = []
        for file_path in scannable:
            file_findings = _scan_file(file_path, root, SECRET_PATTERNS)
            all_findings.extend(file_findings)

        all_findings = _deduplicate(all_findings)
        all_findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.file_path))

        # Log summary
        counts: dict[str, int] = {}
        for f in all_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        if all_findings:
            summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
            log.info(f"  [yellow]Secrets found: {len(all_findings)} ({summary})[/yellow]")
            for finding in all_findings[:20]:  # Log first 20
                icon = {
                    "CRITICAL": "[red bold]CRIT[/red bold]",
                    "HIGH": "[red]HIGH[/red]",
                    "MEDIUM": "[yellow]MED [/yellow]",
                    "LOW": "[dim]LOW [/dim]",
                }.get(finding.severity, "    ")
                log.info(
                    f"  {icon}  {finding.file_path}:{finding.line_number}"
                    f"  [{finding.pattern_name}]  {finding.matched_text}"
                )
            if len(all_findings) > 20:
                log.info(f"  ... and {len(all_findings) - 20} more (see report.json)")
        else:
            log.info("  [green]No secrets detected.[/green]")

        self.session.add_note(
            f"Secrets scan: {len(scannable)} files scanned, "
            f"{len(all_findings)} finding(s)"
        )

        # Serialize findings as dicts for the AnalysisResult
        findings_dicts = [
            {
                "pattern": f.pattern_name,
                "severity": f.severity,
                "description": f.description,
                "file": f.file_path,
                "line": f.line_number,
                "preview": f.matched_text,
            }
            for f in all_findings
        ]

        return AnalysisResult(
            tool="secrets",
            success=True,
            findings=findings_dicts,
            extracted_dir=target if target.is_dir() else None,
        )
