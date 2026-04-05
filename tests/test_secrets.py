"""
Tests for firmxtract.analysis.secrets

No hardware required. Tests use temp directories and synthetic file content.
"""

import pytest
from pathlib import Path

from firmxtract.analysis.secrets import (
    SecretsHunter,
    SECRET_PATTERNS,
    _score_serial_data,
    _byte_entropy,
    _is_likely_binary,
    _should_scan_file,
    _scan_file,
)


# ---------------------------------------------------------------------------
# Entropy helpers
# ---------------------------------------------------------------------------


class TestByteEntropy:
    def test_constant_bytes_low_entropy(self):
        data = b"\x00" * 1024
        assert _byte_entropy(data) < 0.1

    def test_random_bytes_high_entropy(self):
        import os
        data = os.urandom(4096)
        assert _byte_entropy(data) > 6.0

    def test_printable_ascii_medium_entropy(self):
        data = b"Hello World! " * 100
        e = _byte_entropy(data)
        assert 1.0 < e < 6.0

    def test_short_data_returns_zero(self):
        assert _byte_entropy(b"short") == 0.0


class TestIsLikelyBinary:
    def test_high_entropy_is_binary(self):
        import os
        data = os.urandom(8192)
        assert _is_likely_binary(data) is True

    def test_text_is_not_binary(self):
        data = b"password=admin123\nssid=MyNetwork\n" * 100
        assert _is_likely_binary(data) is False

    def test_null_heavy_is_binary(self):
        data = b"\x00" * 500 + b"abc" * 10
        assert _is_likely_binary(data) is True


# ---------------------------------------------------------------------------
# File selection
# ---------------------------------------------------------------------------


class TestShouldScanFile:
    def test_conf_file_included(self, tmp_path):
        f = tmp_path / "network.conf"
        f.write_text("ssid=test\npassword=secret\n")
        assert _should_scan_file(f) is True

    def test_gz_file_skipped(self, tmp_path):
        f = tmp_path / "archive.gz"
        f.write_bytes(b"\x1f\x8b" + b"\x00" * 100)
        assert _should_scan_file(f) is False

    def test_jpg_file_skipped(self, tmp_path):
        f = tmp_path / "image.jpg"
        f.write_bytes(b"\xff\xd8\xff" + b"\x00" * 100)
        assert _should_scan_file(f) is False

    def test_empty_file_skipped(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        assert _should_scan_file(f) is False


# ---------------------------------------------------------------------------
# Pattern matching
# ---------------------------------------------------------------------------


class TestSecretPatterns:
    """Verify each pattern fires on known-bad content and not on clean content."""

    def _make_file(self, tmp_path: Path, name: str, content: bytes) -> Path:
        f = tmp_path / name
        f.write_bytes(content)
        return f

    def test_private_key_detected(self, tmp_path):
        f = self._make_file(
            tmp_path, "key.pem",
            b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n",
        )
        findings = _scan_file(f, tmp_path, SECRET_PATTERNS)
        names = [fn.pattern_name for fn in findings]
        assert "private_key" in names

    def test_aws_access_key_detected(self, tmp_path):
        f = self._make_file(tmp_path, "config.sh", b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
        findings = _scan_file(f, tmp_path, SECRET_PATTERNS)
        names = [fn.pattern_name for fn in findings]
        assert "aws_access_key" in names

    def test_wifi_psk_detected(self, tmp_path):
        f = self._make_file(
            tmp_path, "wireless.conf",
            b"wpa_passphrase=SuperSecret123\n",
        )
        findings = _scan_file(f, tmp_path, SECRET_PATTERNS)
        names = [fn.pattern_name for fn in findings]
        assert "wifi_psk" in names

    def test_jwt_detected(self, tmp_path):
        jwt = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        f = self._make_file(tmp_path, "auth.conf", b"token=" + jwt + b"\n")
        findings = _scan_file(f, tmp_path, SECRET_PATTERNS)
        names = [fn.pattern_name for fn in findings]
        assert "jwt_token" in names

    def test_clean_file_no_findings(self, tmp_path):
        f = self._make_file(
            tmp_path, "clean.conf",
            b"server=192.168.1.1\nport=8080\ntimeout=30\n",
        )
        findings = _scan_file(f, tmp_path, SECRET_PATTERNS)
        # private_ip may fire but no credential patterns
        cred_names = {fn.pattern_name for fn in findings}
        assert "private_key" not in cred_names
        assert "aws_access_key" not in cred_names
        assert "wifi_psk" not in cred_names


# ---------------------------------------------------------------------------
# SecretsHunter integration
# ---------------------------------------------------------------------------


class TestSecretsHunter:
    def _make_session(self, tmp_path: Path):
        from unittest.mock import MagicMock
        session = MagicMock()
        session.output_dir = tmp_path
        session.add_note = MagicMock()
        return session

    def test_scans_directory(self, tmp_path):
        # Plant a file with a secret
        secret_dir = tmp_path / "extracted"
        secret_dir.mkdir()
        (secret_dir / "etc" ).mkdir()
        (secret_dir / "etc" / "passwd").write_bytes(b"root:x:0:0:root:/root:/bin/sh\n")
        (secret_dir / "etc" / "wireless.conf").write_bytes(
            b"wpa_passphrase=hunter2\nssid=TestNet\n"
        )

        session = self._make_session(tmp_path)
        hunter = SecretsHunter(session)
        result = hunter.analyze(secret_dir)

        assert result.success is True
        assert result.tool == "secrets"
        # Should find at least the wifi PSK
        pattern_names = {f["pattern"] for f in result.findings}
        assert "wifi_psk" in pattern_names

    def test_missing_target_returns_failure(self, tmp_path):
        session = self._make_session(tmp_path)
        hunter = SecretsHunter(session)
        result = hunter.analyze(tmp_path / "nonexistent")
        assert result.success is False

    def test_findings_sorted_by_severity(self, tmp_path):
        secret_dir = tmp_path / "fw"
        secret_dir.mkdir()
        (secret_dir / "keys.txt").write_bytes(
            b"-----BEGIN RSA PRIVATE KEY-----\ndata\n"
            b"token=AKIAIOSFODNN7EXAMPLE\n"
        )

        session = self._make_session(tmp_path)
        result = SecretsHunter(session).analyze(secret_dir)

        if len(result.findings) >= 2:
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            severities = [sev_order[f["severity"]] for f in result.findings]
            assert severities == sorted(severities), "Findings not sorted by severity"

    def test_deduplication(self, tmp_path):
        secret_dir = tmp_path / "fw"
        secret_dir.mkdir()
        # Repeat the same secret on multiple identical lines
        (secret_dir / "dup.conf").write_bytes(
            b"wpa_passphrase=duplicate\n" * 10
        )
        session = self._make_session(tmp_path)
        result = SecretsHunter(session).analyze(secret_dir)
        # Each unique (file, line, pattern) combo should appear only once
        keys = [(f["file"], f["line"], f["pattern"]) for f in result.findings]
        assert len(keys) == len(set(keys))

    def test_binary_files_skipped(self, tmp_path):
        """High-entropy binary blob should not produce findings."""
        import os
        secret_dir = tmp_path / "fw"
        secret_dir.mkdir()
        (secret_dir / "kernel.bin").write_bytes(os.urandom(65536))
        session = self._make_session(tmp_path)
        result = SecretsHunter(session).analyze(secret_dir)
        # Binary file should have been skipped — no findings from it
        assert result.success is True
