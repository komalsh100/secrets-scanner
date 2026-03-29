"""
Core scanning engine for the Secrets Scanner CLI.
Handles file scanning, git history scanning, and .secretsignore support.
"""

import os
import re
import subprocess
import fnmatch
from pathlib import Path
from typing import List, Dict, Optional

from .patterns import SECRET_PATTERNS, SCANNABLE_EXTENSIONS, BINARY_EXTENSIONS
from .entropy import find_high_entropy_strings


class SecretsScanner:
    def __init__(
        self,
        path: str,
        scan_git_history: bool = False,
        entropy: bool = True,
        severity_filter: Optional[str] = None,
        exclude_patterns: Optional[List[str]] = None,
    ):
        self.path = Path(path).resolve()
        self.scan_git_history = scan_git_history
        self.entropy = entropy
        self.severity_filter = severity_filter
        self.exclude_patterns = exclude_patterns or []
        self.ignore_patterns = self._load_ignore_file()
        self.findings: List[Dict] = []
        self.scanned_files = 0
        self.skipped_files = 0

    def _load_ignore_file(self) -> List[str]:
        """Load patterns from .secretsignore file."""
        ignore_file = self.path / ".secretsignore"
        patterns = []
        if ignore_file.exists():
            with open(ignore_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        patterns.append(line)
        return patterns

    def _is_ignored(self, file_path: Path) -> bool:
        """Check if a file matches any ignore pattern."""
        rel_path = str(file_path.relative_to(self.path))
        for pattern in self.ignore_patterns + self.exclude_patterns:
            if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(file_path.name, pattern):
                return True
        # Always skip common non-secret dirs
        parts = file_path.parts
        skip_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv',
                     'dist', 'build', '.tox', '.eggs', 'vendor'}
        if any(part in skip_dirs for part in parts):
            return True
        return False

    def _is_scannable(self, file_path: Path) -> bool:
        """Check if a file should be scanned."""
        suffix = file_path.suffix.lower()
        if suffix in BINARY_EXTENSIONS:
            return False
        if suffix in SCANNABLE_EXTENSIONS:
            return True
        # Scan extensionless files (Dockerfile, Makefile, etc.)
        if suffix == "":
            return True
        return False

    def _scan_line(self, line: str, line_number: int, file_path: str) -> List[Dict]:
        """Scan a single line for secrets using regex patterns."""
        findings = []
        for pattern_def in SECRET_PATTERNS:
            matches = re.finditer(pattern_def["pattern"], line)
            for match in matches:
                matched_text = match.group(0)
                # Redact most of the secret in output
                redacted = matched_text[:6] + "..." + matched_text[-4:] if len(matched_text) > 12 else "***"
                findings.append({
                    "type": "regex",
                    "name": pattern_def["name"],
                    "severity": pattern_def["severity"],
                    "description": pattern_def["description"],
                    "file": file_path,
                    "line": line_number,
                    "match": redacted,
                    "entropy": None
                })
        return findings

    def _scan_file(self, file_path: Path) -> List[Dict]:
        """Scan a single file for secrets."""
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_number, line in enumerate(f, 1):
                    # Regex scanning
                    findings.extend(self._scan_line(line, line_number, str(file_path)))
                    # Entropy scanning
                    if self.entropy:
                        findings.extend(find_high_entropy_strings(line, line_number, str(file_path)))
        except (OSError, PermissionError):
            pass
        return findings

    def scan_files(self) -> List[Dict]:
        """Scan all files in the target path."""
        if self.path.is_file():
            files = [self.path]
        else:
            files = list(self.path.rglob("*"))

        for file_path in files:
            if not file_path.is_file():
                continue
            if self._is_ignored(file_path):
                self.skipped_files += 1
                continue
            if not self._is_scannable(file_path):
                self.skipped_files += 1
                continue
            self.scanned_files += 1
            self.findings.extend(self._scan_file(file_path))

        return self.findings

    def scan_git_history_commits(self) -> List[Dict]:
        """Scan git commit history for secrets."""
        git_findings = []
        try:
            # Get list of commits
            result = subprocess.run(
                ["git", "log", "--all", "--oneline"],
                cwd=self.path,
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                return []

            commits = [line.split()[0] for line in result.stdout.strip().split("\n") if line]

            for commit in commits[:100]:  # Limit to last 100 commits
                diff_result = subprocess.run(
                    ["git", "show", commit, "--no-color"],
                    cwd=self.path,
                    capture_output=True, text=True, timeout=30
                )
                if diff_result.returncode != 0:
                    continue

                for line_number, line in enumerate(diff_result.stdout.split("\n"), 1):
                    if line.startswith("+") and not line.startswith("+++"):
                        findings = self._scan_line(line[1:], line_number, f"git:commit:{commit}")
                        for f in findings:
                            f["commit"] = commit
                            git_findings.append(f)

        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass

        return git_findings

    def run(self) -> List[Dict]:
        """Run the full scan."""
        self.scan_files()
        if self.scan_git_history:
            self.findings.extend(self.scan_git_history_commits())

        # Apply severity filter
        if self.severity_filter:
            severity_levels = {"critical": ["CRITICAL"],
                               "high": ["CRITICAL", "HIGH"],
                               "medium": ["CRITICAL", "HIGH", "MEDIUM"],
                               "low": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
            allowed = severity_levels.get(self.severity_filter.lower(), ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
            self.findings = [f for f in self.findings if f["severity"] in allowed]

        # Deduplicate
        seen = set()
        deduped = []
        for f in self.findings:
            key = (f["file"], f["line"], f["name"])
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        self.findings = deduped

        return self.findings
