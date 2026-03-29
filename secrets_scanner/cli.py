#!/usr/bin/env python3
"""
Secrets Scanner CLI
-------------------
Detects hardcoded secrets, API keys, tokens, and high-entropy strings
across codebases and Git history.

Usage:
    python -m secrets_scanner.cli <path> [options]
    secrets-scanner <path> [options]
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

from .scanner import SecretsScanner
from .reporter import generate_json_report, generate_html_report
from .patterns import SEVERITY_ORDER

# ANSI color codes
RED     = "\033[91m"
ORANGE  = "\033[93m"
YELLOW  = "\033[33m"
GREEN   = "\033[92m"
BLUE    = "\033[94m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

SEVERITY_COLORS = {
    "CRITICAL": f"{BOLD}{RED}",
    "HIGH":     f"{BOLD}{ORANGE}",
    "MEDIUM":   f"{BOLD}{YELLOW}",
    "LOW":      f"{BOLD}{GREEN}",
}

BANNER = f"""
{BLUE}{BOLD}╔══════════════════════════════════════════════╗
║          🔍  Secrets Scanner CLI  v1.0.0      ║
║     Detect hardcoded secrets & high-entropy   ║
║     strings across codebases & git history    ║
╚══════════════════════════════════════════════╝{RESET}
"""


def print_finding(finding: dict, index: int):
    """Print a single finding to the terminal."""
    sev = finding["severity"]
    color = SEVERITY_COLORS.get(sev, BOLD)
    sev_badge = f"{color}[{sev}]{RESET}"

    print(f"\n  {BOLD}#{index}{RESET} {sev_badge} {CYAN}{finding['name']}{RESET}")
    print(f"     {DIM}File:{RESET}  {finding['file']}")
    print(f"     {DIM}Line:{RESET}  {finding['line']}")
    print(f"     {DIM}Match:{RESET} {GREEN}{finding['match']}{RESET}", end="")
    if finding.get("entropy"):
        print(f"  {DIM}(entropy: {finding['entropy']}){RESET}", end="")
    print()
    if finding.get("commit"):
        print(f"     {DIM}Commit:{RESET} {finding['commit']}")
    print(f"     {DIM}Info:{RESET}  {finding['description']}")


def print_summary(findings: list, scanned: int, skipped: int, elapsed: float):
    """Print scan summary."""
    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high     = sum(1 for f in findings if f["severity"] == "HIGH")
    medium   = sum(1 for f in findings if f["severity"] == "MEDIUM")

    print(f"\n{BOLD}{'─'*50}{RESET}")
    print(f"{BOLD}  Scan Summary{RESET}")
    print(f"{'─'*50}")
    print(f"  Files scanned : {scanned}")
    print(f"  Files skipped : {skipped}")
    print(f"  Scan duration : {elapsed:.2f}s")
    print(f"  Total findings: {BOLD}{len(findings)}{RESET}")
    print(f"  ├─ {SEVERITY_COLORS['CRITICAL']}CRITICAL{RESET}: {critical}")
    print(f"  ├─ {SEVERITY_COLORS['HIGH']}HIGH    {RESET}: {high}")
    print(f"  └─ {SEVERITY_COLORS['MEDIUM']}MEDIUM  {RESET}: {medium}")
    print(f"{'─'*50}\n")


def main():
    parser = argparse.ArgumentParser(
        prog="secrets-scanner",
        description="Detect hardcoded secrets and high-entropy strings in codebases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  secrets-scanner .                          Scan current directory
  secrets-scanner ./src --git-history        Include git commit history
  secrets-scanner . --severity critical      Show only critical findings
  secrets-scanner . --output report.json     Save JSON report
  secrets-scanner . --html report.html       Save HTML report
  secrets-scanner . --no-entropy             Skip entropy analysis
  secrets-scanner . --exclude "*.test.js"    Exclude test files
        """
    )
    parser.add_argument("path", nargs="?", default=".", help="Path to scan (default: current directory)")
    parser.add_argument("--git-history", action="store_true", help="Scan git commit history")
    parser.add_argument("--no-entropy", action="store_true", help="Disable Shannon entropy analysis")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low"], help="Minimum severity to report")
    parser.add_argument("--output", "-o", help="Save JSON report to file")
    parser.add_argument("--html", help="Save HTML report to file")
    parser.add_argument("--exclude", action="append", default=[], help="Exclude file patterns (can use multiple times)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress banner and progress output")
    parser.add_argument("--fail-on-critical", action="store_true", help="Exit with code 1 if critical findings found")
    parser.add_argument("--fail-on-high", action="store_true", help="Exit with code 1 if high/critical findings found")

    args = parser.parse_args()

    if not args.quiet:
        print(BANNER)

    # Validate path
    scan_path = Path(args.path).resolve()
    if not scan_path.exists():
        print(f"{RED}Error: Path '{args.path}' does not exist.{RESET}")
        sys.exit(2)

    if not args.quiet:
        print(f"  {DIM}Target:{RESET}  {scan_path}")
        print(f"  {DIM}Entropy:{RESET} {'Disabled' if args.no_entropy else 'Enabled (Shannon)'}")
        print(f"  {DIM}Git History:{RESET} {'Yes' if args.git_history else 'No'}")
        if args.severity:
            print(f"  {DIM}Min Severity:{RESET} {args.severity.upper()}")
        print()

    # Run scan
    start = time.time()
    scanner = SecretsScanner(
        path=str(scan_path),
        scan_git_history=args.git_history,
        entropy=not args.no_entropy,
        severity_filter=args.severity,
        exclude_patterns=args.exclude,
    )

    if not args.quiet:
        print(f"  {DIM}Scanning...{RESET}", end="\r")

    findings = scanner.run()
    elapsed = time.time() - start

    # Sort by severity
    findings = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

    # Print findings
    if not args.quiet:
        if findings:
            print(f"\n{BOLD}  Findings:{RESET}")
            for i, finding in enumerate(findings, 1):
                print_finding(finding, i)
        else:
            print(f"\n  {GREEN}{BOLD}✅ No secrets detected.{RESET} Your codebase looks clean!\n")

    # Print summary
    if not args.quiet:
        print_summary(findings, scanner.scanned_files, scanner.skipped_files, elapsed)

    # Generate reports
    meta = {
        "target": str(scan_path),
        "scanned_files": scanner.scanned_files,
        "skipped_files": scanner.skipped_files,
    }

    if args.output:
        path = generate_json_report(findings, args.output, meta)
        if not args.quiet:
            print(f"  {GREEN}JSON report saved:{RESET} {path}")

    if args.html:
        path = generate_html_report(findings, args.html, meta)
        if not args.quiet:
            print(f"  {GREEN}HTML report saved:{RESET} {path}\n")

    # Exit codes for CI/CD integration
    if args.fail_on_critical and any(f["severity"] == "CRITICAL" for f in findings):
        sys.exit(1)
    if args.fail_on_high and any(f["severity"] in ("CRITICAL", "HIGH") for f in findings):
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
