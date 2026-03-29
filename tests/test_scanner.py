"""
Tests for Secrets Scanner CLI
"""

import pytest
import tempfile
import os
from pathlib import Path

from secrets_scanner.scanner import SecretsScanner
from secrets_scanner.entropy import shannon_entropy, find_high_entropy_strings
from secrets_scanner.patterns import SECRET_PATTERNS


class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_uniform_string(self):
        # All same chars = 0 entropy
        assert shannon_entropy("aaaaaaa") == 0.0

    def test_high_entropy(self):
        # Random-looking string should have high entropy
        result = shannon_entropy("aB3kZ9mP2xQwRtYuIoLsdfghj")
        assert result > 3.0

    def test_low_entropy(self):
        result = shannon_entropy("aaabbbccc")
        assert result < 2.0


class TestPatterns:
    def test_aws_key_pattern(self):
        import re
        aws_pattern = next(p for p in SECRET_PATTERNS if p["name"] == "AWS Access Key ID")
        match = re.search(aws_pattern["pattern"], "AKIAIOSFODNN7EXAMPLE")
        assert match is not None

    def test_github_token_pattern(self):
        import re
        gh_pattern = next(p for p in SECRET_PATTERNS if p["name"] == "GitHub Personal Access Token")
        match = re.search(gh_pattern["pattern"], "ghp_" + "a" * 36)
        assert match is not None

    def test_jwt_pattern(self):
        import re
        jwt_pattern = next(p for p in SECRET_PATTERNS if p["name"] == "JWT Token")
        fake_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        match = re.search(jwt_pattern["pattern"], fake_jwt)
        assert match is not None

    def test_all_patterns_have_required_fields(self):
        for pattern in SECRET_PATTERNS:
            assert "name" in pattern
            assert "pattern" in pattern
            assert "severity" in pattern
            assert "description" in pattern
            assert pattern["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


class TestScanner:
    def test_scan_clean_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            clean_file = Path(tmpdir) / "clean.py"
            clean_file.write_text("x = 1 + 1\nprint('hello world')\n")
            scanner = SecretsScanner(tmpdir, entropy=False)
            findings = scanner.run()
            assert len(findings) == 0

    def test_scan_file_with_aws_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_file = Path(tmpdir) / "config.py"
            secret_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
            scanner = SecretsScanner(tmpdir, entropy=False)
            findings = scanner.run()
            assert any(f["name"] == "AWS Access Key ID" for f in findings)

    def test_scan_file_with_github_token(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_file = Path(tmpdir) / "deploy.py"
            secret_file.write_text(f'TOKEN = "ghp_{"a" * 36}"\n')
            scanner = SecretsScanner(tmpdir, entropy=False)
            findings = scanner.run()
            assert any(f["name"] == "GitHub Personal Access Token" for f in findings)

    def test_secretsignore(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create ignore file
            ignore_file = Path(tmpdir) / ".secretsignore"
            ignore_file.write_text("*.py\n")
            # Create file that would otherwise trigger
            secret_file = Path(tmpdir) / "config.py"
            secret_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
            scanner = SecretsScanner(tmpdir, entropy=False)
            findings = scanner.run()
            assert len(findings) == 0

    def test_severity_filter(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_file = Path(tmpdir) / "config.py"
            secret_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
            scanner = SecretsScanner(tmpdir, entropy=False, severity_filter="critical")
            findings = scanner.run()
            assert all(f["severity"] == "CRITICAL" for f in findings)
