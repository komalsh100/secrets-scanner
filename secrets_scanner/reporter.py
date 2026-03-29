"""
Report generation for Secrets Scanner CLI.
Supports JSON and HTML output formats.
"""

import json
import os
from datetime import datetime
from typing import List, Dict
from .patterns import SEVERITY_ORDER


def generate_json_report(findings: List[Dict], output_path: str, meta: dict) -> str:
    """Generate a JSON report of findings."""
    report = {
        "scan_metadata": {
            "tool": "Secrets Scanner CLI",
            "version": "1.0.0",
            "scan_time": datetime.utcnow().isoformat() + "Z",
            "target": meta.get("target", ""),
            "scanned_files": meta.get("scanned_files", 0),
            "skipped_files": meta.get("skipped_files", 0),
            "total_findings": len(findings),
            "findings_by_severity": {
                "CRITICAL": sum(1 for f in findings if f["severity"] == "CRITICAL"),
                "HIGH": sum(1 for f in findings if f["severity"] == "HIGH"),
                "MEDIUM": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            }
        },
        "findings": sorted(findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    }
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    return output_path


def generate_html_report(findings: List[Dict], output_path: str, meta: dict) -> str:
    """Generate an HTML report of findings."""
    severity_colors = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#d97706",
        "LOW": "#65a30d"
    }
    severity_bg = {
        "CRITICAL": "#fef2f2",
        "HIGH": "#fff7ed",
        "MEDIUM": "#fffbeb",
        "LOW": "#f7fee7"
    }

    total = len(findings)
    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    scan_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    rows = ""
    for i, f in enumerate(sorted(findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99)), 1):
        color = severity_colors.get(f["severity"], "#6b7280")
        bg = severity_bg.get(f["severity"], "#f9fafb")
        entropy_info = f" (entropy: {f['entropy']})" if f.get("entropy") else ""
        commit_info = f"<br><small style='color:#6b7280'>Commit: {f.get('commit', '')}</small>" if f.get("commit") else ""
        rows += f"""
        <tr style="background:{bg}">
            <td style="padding:10px;border-bottom:1px solid #e5e7eb;font-weight:bold;color:#374151">{i}</td>
            <td style="padding:10px;border-bottom:1px solid #e5e7eb">
                <span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold">{f['severity']}</span>
            </td>
            <td style="padding:10px;border-bottom:1px solid #e5e7eb;font-weight:600;color:#111827">{f['name']}</td>
            <td style="padding:10px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:12px;color:#374151;word-break:break-all">
                {f['file']}{commit_info}
            </td>
            <td style="padding:10px;border-bottom:1px solid #e5e7eb;text-align:center;color:#374151">{f['line']}</td>
            <td style="padding:10px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:12px;background:#1f2937;color:#10b981;border-radius:4px">{f['match']}{entropy_info}</td>
            <td style="padding:10px;border-bottom:1px solid #e5e7eb;font-size:13px;color:#6b7280">{f['description']}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secrets Scanner Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f3f4f6; color: #111827; }}
        .header {{ background: linear-gradient(135deg, #1e3a5f, #1A4E8C); color: white; padding: 30px; border-radius: 12px; margin-bottom: 24px; }}
        .header h1 {{ margin: 0 0 8px 0; font-size: 28px; }}
        .header p {{ margin: 0; opacity: 0.8; font-size: 14px; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
        .stat {{ background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .stat .number {{ font-size: 36px; font-weight: bold; }}
        .stat .label {{ font-size: 13px; color: #6b7280; margin-top: 4px; }}
        .table-container {{ background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #1f2937; color: white; padding: 12px 10px; text-align: left; font-size: 13px; font-weight: 600; }}
        .no-findings {{ text-align: center; padding: 60px; color: #6b7280; }}
        .no-findings .icon {{ font-size: 48px; margin-bottom: 16px; }}
        .footer {{ text-align: center; margin-top: 24px; color: #9ca3af; font-size: 13px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Secrets Scanner Report</h1>
        <p>Target: {meta.get('target', 'N/A')} &nbsp;|&nbsp; Scan Time: {scan_time} &nbsp;|&nbsp; Files Scanned: {meta.get('scanned_files', 0)}</p>
    </div>
    <div class="stats">
        <div class="stat"><div class="number" style="color:#374151">{total}</div><div class="label">Total Findings</div></div>
        <div class="stat"><div class="number" style="color:#dc2626">{critical}</div><div class="label">Critical</div></div>
        <div class="stat"><div class="number" style="color:#ea580c">{high}</div><div class="label">High</div></div>
        <div class="stat"><div class="number" style="color:#d97706">{medium}</div><div class="label">Medium</div></div>
    </div>
    {"<div class='table-container'><table><thead><tr><th>#</th><th>Severity</th><th>Type</th><th>File</th><th>Line</th><th>Match (Redacted)</th><th>Description</th></tr></thead><tbody>" + rows + "</tbody></table></div>" if total > 0 else "<div class='table-container'><div class='no-findings'><div class='icon'>✅</div><h2>No secrets detected</h2><p>Your codebase appears to be clean.</p></div></div>"}
    <div class="footer">Generated by Secrets Scanner CLI v1.0.0 &nbsp;|&nbsp; github.com/komal-sharma</div>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)
    return output_path
