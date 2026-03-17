"""
ClawGuard report generators.

Three reporters are provided:

* ``TextReporter`` – plain-text, suitable for log files and CI artefacts.
* ``JSONReporter``  – machine-readable JSON, compatible with SIEM / ticketing pipelines.
* ``HTMLReporter``  – self-contained HTML with embedded CSS, ready to send to management.
"""
from __future__ import annotations

import json
from datetime import timezone
from pathlib import Path
from string import Template
from typing import Any

from clawguard.models import Finding, ScanResult, Severity

# ---------------------------------------------------------------------------
# Severity colour palette (shared across reporters)
# ---------------------------------------------------------------------------

_SEV_CSS: dict[Severity, str] = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#0891b2",
    Severity.INFO: "#64748b",
}

_SEV_BG: dict[Severity, str] = {
    Severity.CRITICAL: "#fef2f2",
    Severity.HIGH: "#fff7ed",
    Severity.MEDIUM: "#fefce8",
    Severity.LOW: "#ecfeff",
    Severity.INFO: "#f8fafc",
}


# ---------------------------------------------------------------------------
# TextReporter
# ---------------------------------------------------------------------------

class TextReporter:
    """Generate a plain-text security audit report."""

    def generate(self, result: ScanResult) -> str:
        lines: list[str] = []
        sep = "=" * 72
        thin = "-" * 72

        lines += [
            sep,
            "  ClawGuard Security Audit Report",
            sep,
            f"  Target   : {result.target}",
            f"  Scanned  : {result.scan_time.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"  Duration : {result.duration_seconds:.1f}s",
            f"  Checkers : {', '.join(result.checkers_run)}",
            f"  Version  : ClawGuard {result.scanner_version}",
            sep,
            "",
        ]

        s = result.stats
        lines += [
            "  EXECUTIVE SUMMARY",
            thin,
            f"  CRITICAL : {s.critical:>4}",
            f"  HIGH     : {s.high:>4}",
            f"  MEDIUM   : {s.medium:>4}",
            f"  LOW      : {s.low:>4}",
            f"  INFO     : {s.info:>4}",
            thin,
            f"  Risk Score: {s.risk_score}/100",
            "",
        ]

        if not result.findings:
            lines.append("  No findings – scan clean.\n")
        else:
            lines.append(f"  FINDINGS ({len(result.findings)} total)")
            lines.append(thin)
            for i, f in enumerate(result.findings, 1):
                lines += [
                    f"",
                    f"  [{i}] [{f.severity.value}] {f.title}",
                    f"      Checker     : {f.checker_name}",
                    f"      Description : {f.description}",
                    f"      Remediation : {f.remediation}",
                ]
                if f.cve_ids:
                    lines.append(f"      CVEs        : {', '.join(f.cve_ids)}")
                if f.references:
                    lines.append(f"      References  : {f.references[0]}")
                if f.evidence:
                    lines.append(f"      Evidence    : {json.dumps(f.evidence)}")

        if result.errors:
            lines += ["", thin, "  SCAN ERRORS"]
            for err in result.errors:
                lines.append(f"  ! {err}")

        lines += ["", sep, "  End of report", sep, ""]
        return "\n".join(lines)

    def write(self, result: ScanResult, path: str | Path) -> None:
        Path(path).write_text(self.generate(result), encoding="utf-8")


# ---------------------------------------------------------------------------
# JSONReporter
# ---------------------------------------------------------------------------

class JSONReporter:
    """Generate a machine-readable JSON report."""

    def generate(self, result: ScanResult) -> str:
        return result.model_dump_json(indent=2)

    def write(self, result: ScanResult, path: str | Path) -> None:
        Path(path).write_text(self.generate(result), encoding="utf-8")


# ---------------------------------------------------------------------------
# HTMLReporter
# ---------------------------------------------------------------------------

_HTML_CSS = """\
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #f1f5f9;
    color: #1e293b;
    font-size: 14px;
    line-height: 1.6;
}

/* ---- Layout ---- */
.page { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }

/* ---- Header ---- */
.report-header {
    background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
    color: #fff;
    border-radius: 12px;
    padding: 32px 40px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
}
.report-header h1 { font-size: 28px; font-weight: 700; letter-spacing: -0.5px; }
.report-header .subtitle { color: #94a3b8; font-size: 13px; margin-top: 4px; }
.header-meta { text-align: right; font-size: 13px; color: #cbd5e1; line-height: 1.8; }
.header-meta strong { color: #fff; }

/* ---- Cards ---- */
.card {
    background: #fff;
    border-radius: 10px;
    box-shadow: 0 1px 4px rgba(0,0,0,.08);
    margin-bottom: 24px;
    overflow: hidden;
}
.card-header {
    padding: 16px 24px;
    border-bottom: 1px solid #e2e8f0;
    font-weight: 600;
    font-size: 15px;
    display: flex;
    align-items: center;
    gap: 8px;
}
.card-body { padding: 24px; }

/* ---- Stat grid ---- */
.stat-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}
.stat-card {
    background: #fff;
    border-radius: 10px;
    padding: 20px;
    text-align: center;
    box-shadow: 0 1px 4px rgba(0,0,0,.08);
    border-top: 4px solid;
}
.stat-card .stat-num { font-size: 36px; font-weight: 700; line-height: 1; }
.stat-card .stat-label { font-size: 12px; font-weight: 600; text-transform: uppercase;
    letter-spacing: .5px; color: #64748b; margin-top: 6px; }
.stat-critical { border-color: #dc2626; }
.stat-critical .stat-num { color: #dc2626; }
.stat-high     { border-color: #ea580c; }
.stat-high     .stat-num { color: #ea580c; }
.stat-medium   { border-color: #ca8a04; }
.stat-medium   .stat-num { color: #ca8a04; }
.stat-low      { border-color: #0891b2; }
.stat-low      .stat-num { color: #0891b2; }
.stat-info     { border-color: #64748b; }
.stat-info     .stat-num { color: #64748b; }

/* ---- Risk score gauge ---- */
.risk-row { display: flex; gap: 32px; align-items: center; flex-wrap: wrap; }
.risk-gauge-wrap { display: flex; flex-direction: column; align-items: center; gap: 8px; }
.risk-gauge {
    width: 120px; height: 120px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 28px; font-weight: 700; color: #fff;
    position: relative;
}
.risk-gauge-label { font-size: 12px; font-weight: 600; text-transform: uppercase;
    letter-spacing: .5px; color: #64748b; }
.risk-bar-wrap { flex: 1; min-width: 200px; }
.risk-bar-track { height: 10px; background: #e2e8f0; border-radius: 5px; overflow: hidden; }
.risk-bar-fill  { height: 100%; border-radius: 5px; transition: width .5s; }

/* ---- Pie chart (CSS conic-gradient) ---- */
.chart-row { display: flex; gap: 32px; align-items: flex-start; flex-wrap: wrap; }
.donut-wrap { position: relative; width: 200px; height: 200px; flex-shrink: 0; }
.donut {
    width: 200px; height: 200px; border-radius: 50%;
}
.donut-hole {
    position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
    width: 100px; height: 100px; background: #fff; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 13px; font-weight: 600; color: #475569; text-align: center;
    line-height: 1.3;
}
.legend { display: flex; flex-direction: column; gap: 10px; justify-content: center; }
.legend-item { display: flex; align-items: center; gap: 10px; font-size: 13px; }
.legend-dot { width: 12px; height: 12px; border-radius: 50%; flex-shrink: 0; }
.legend-pct { margin-left: auto; font-weight: 600; color: #475569; }

/* ---- Severity badge ---- */
.badge {
    display: inline-block; padding: 2px 10px; border-radius: 100px;
    font-size: 11px; font-weight: 700; text-transform: uppercase;
    letter-spacing: .4px;
}
.badge-CRITICAL { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
.badge-HIGH     { background: #fff7ed; color: #ea580c; border: 1px solid #fed7aa; }
.badge-MEDIUM   { background: #fefce8; color: #ca8a04; border: 1px solid #fef08a; }
.badge-LOW      { background: #ecfeff; color: #0891b2; border: 1px solid #a5f3fc; }
.badge-INFO     { background: #f8fafc; color: #64748b; border: 1px solid #e2e8f0; }

/* ---- Findings table ---- */
.findings-table { width: 100%; border-collapse: collapse; }
.findings-table th {
    text-align: left; padding: 10px 14px;
    background: #f8fafc; border-bottom: 2px solid #e2e8f0;
    font-size: 12px; font-weight: 600; text-transform: uppercase;
    letter-spacing: .4px; color: #64748b;
}
.findings-table td { padding: 12px 14px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
.findings-table tr:last-child td { border-bottom: none; }
.findings-table tr:hover td { background: #f8fafc; }
.finding-title { font-weight: 600; margin-bottom: 4px; }
.finding-checker { font-size: 11px; color: #94a3b8; }

/* ---- Finding detail ---- */
.finding-detail {
    border-radius: 8px; border: 1px solid #e2e8f0;
    margin-bottom: 16px; overflow: hidden;
}
.finding-detail-header {
    display: flex; align-items: center; gap: 12px;
    padding: 14px 18px;
    cursor: pointer;
    background: #f8fafc;
    user-select: none;
}
.finding-detail-header:hover { background: #f1f5f9; }
.finding-detail-body { padding: 18px; border-top: 1px solid #e2e8f0; background: #fff; }
.detail-row { display: flex; gap: 12px; margin-bottom: 10px; }
.detail-row:last-child { margin-bottom: 0; }
.detail-key { min-width: 110px; font-size: 12px; font-weight: 600; text-transform: uppercase;
    letter-spacing: .3px; color: #94a3b8; padding-top: 1px; }
.detail-val { flex: 1; font-size: 13px; color: #334155; }
.detail-val code {
    background: #f1f5f9; padding: 1px 6px; border-radius: 4px;
    font-family: 'SF Mono', Consolas, monospace; font-size: 12px;
}
.cve-tag {
    display: inline-block; background: #eff6ff; color: #1d4ed8;
    border: 1px solid #bfdbfe; border-radius: 4px; padding: 1px 7px;
    font-size: 11px; font-weight: 600; margin-right: 4px;
}
.evidence-block {
    background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px;
    padding: 10px 14px; font-family: 'SF Mono', Consolas, monospace;
    font-size: 12px; white-space: pre-wrap; word-break: break-all; color: #475569;
}
.remediation-box {
    background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px;
    padding: 10px 14px; color: #166534; font-size: 13px;
}

/* ---- Toggle chevron ---- */
details > summary { list-style: none; }
details > summary::-webkit-details-marker { display: none; }
.chevron { margin-left: auto; font-size: 16px; color: #94a3b8; transition: transform .2s; }
details[open] .chevron { transform: rotate(180deg); }

/* ---- Footer ---- */
.footer {
    text-align: center; color: #94a3b8; font-size: 12px;
    padding: 24px 0 8px;
}

/* ---- Clean print ---- */
@media print {
    body { background: #fff; }
    .page { padding: 0; }
    .card { box-shadow: none; border: 1px solid #e2e8f0; }
    .finding-detail-body { display: block !important; }
}
"""


def _safe_pct(n: int, total: int) -> float:
    return round(n / total * 100, 1) if total else 0.0


def _build_conic(stats: Any) -> str:
    """Return CSS conic-gradient string from SummaryStats."""
    total = stats.total or 1
    segments = [
        (stats.critical, "#dc2626"),
        (stats.high, "#ea580c"),
        (stats.medium, "#ca8a04"),
        (stats.low, "#0891b2"),
        (stats.info, "#64748b"),
    ]
    parts: list[str] = []
    acc = 0.0
    for count, colour in segments:
        deg = count / total * 360
        if deg == 0:
            continue
        parts.append(f"{colour} {acc:.1f}deg {acc + deg:.1f}deg")
        acc += deg
    if not parts:
        return "#e2e8f0"
    return f"conic-gradient({', '.join(parts)})"


def _risk_colour(score: int) -> str:
    if score >= 70:
        return "#dc2626"
    if score >= 40:
        return "#ea580c"
    if score >= 15:
        return "#ca8a04"
    return "#16a34a"


def _escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
    )


def _finding_detail_html(idx: int, f: Finding) -> str:
    sev = f.severity.value
    cves_html = ""
    if f.cve_ids:
        cves_html = "".join(f'<span class="cve-tag">{_escape(c)}</span>' for c in f.cve_ids)

    evidence_html = ""
    if f.evidence:
        evidence_html = f"""
        <div class="detail-row">
            <div class="detail-key">Evidence</div>
            <div class="detail-val">
                <div class="evidence-block">{_escape(json.dumps(f.evidence, indent=2))}</div>
            </div>
        </div>"""

    refs_html = ""
    if f.references:
        links = " ".join(
            f'<a href="{_escape(r)}" target="_blank" rel="noopener">{_escape(r)}</a>'
            for r in f.references[:3]
        )
        refs_html = f"""
        <div class="detail-row">
            <div class="detail-key">References</div>
            <div class="detail-val" style="font-size:12px">{links}</div>
        </div>"""

    cves_row = ""
    if cves_html:
        cves_row = f"""
        <div class="detail-row">
            <div class="detail-key">CVEs</div>
            <div class="detail-val">{cves_html}</div>
        </div>"""

    return f"""
    <details class="finding-detail">
        <summary class="finding-detail-header">
            <span class="badge badge-{sev}">{sev}</span>
            <span style="font-weight:600;flex:1">{_escape(f.title)}</span>
            <span style="font-size:12px;color:#94a3b8;margin-right:12px">{_escape(f.checker_name)}</span>
            <span class="chevron">&#9660;</span>
        </summary>
        <div class="finding-detail-body">
            <div class="detail-row">
                <div class="detail-key">Description</div>
                <div class="detail-val">{_escape(f.description)}</div>
            </div>
            <div class="detail-row">
                <div class="detail-key">Remediation</div>
                <div class="detail-val">
                    <div class="remediation-box">{_escape(f.remediation)}</div>
                </div>
            </div>
            {cves_row}
            {evidence_html}
            {refs_html}
        </div>
    </details>"""


class HTMLReporter:
    """Generate a self-contained HTML report suitable for executive review."""

    def generate(self, result: ScanResult) -> str:
        s = result.stats
        ts = result.scan_time.strftime("%Y-%m-%d %H:%M:%S UTC")
        score = s.risk_score
        risk_col = _risk_colour(score)
        total = s.total or 1

        # ---- stat cards ----
        stat_cards_html = "".join(
            f"""<div class="stat-card stat-{sev_name}">
                <div class="stat-num">{count}</div>
                <div class="stat-label">{sev_name.capitalize()}</div>
            </div>"""
            for sev_name, count in [
                ("critical", s.critical),
                ("high", s.high),
                ("medium", s.medium),
                ("low", s.low),
                ("info", s.info),
            ]
        )

        # ---- risk bar ----
        risk_section = f"""
        <div class="risk-row">
            <div class="risk-gauge-wrap">
                <div class="risk-gauge" style="background:{risk_col};">{score}</div>
                <div class="risk-gauge-label">Risk Score / 100</div>
            </div>
            <div class="risk-bar-wrap">
                <p style="margin-bottom:8px;font-size:13px;color:#64748b">
                    Overall risk score: <strong style="color:{risk_col}">{score}/100</strong>
                    &nbsp;·&nbsp; {s.total} finding(s) across {len(result.checkers_run)} checker(s)
                </p>
                <div class="risk-bar-track">
                    <div class="risk-bar-fill" style="width:{score}%;background:{risk_col};"></div>
                </div>
            </div>
        </div>"""

        # ---- donut chart ----
        conic = _build_conic(s)
        legend_items = [
            ("CRITICAL", s.critical, "#dc2626"),
            ("HIGH",     s.high,     "#ea580c"),
            ("MEDIUM",   s.medium,   "#ca8a04"),
            ("LOW",      s.low,      "#0891b2"),
            ("INFO",     s.info,     "#64748b"),
        ]
        legend_html = "".join(
            f"""<div class="legend-item">
                <span class="legend-dot" style="background:{col}"></span>
                <span>{label}</span>
                <span class="legend-pct">{_safe_pct(cnt, s.total)}%</span>
            </div>"""
            for label, cnt, col in legend_items
            if cnt > 0
        )
        if not legend_html:
            legend_html = '<div class="legend-item" style="color:#16a34a">✓ No findings</div>'

        chart_section = f"""
        <div class="chart-row">
            <div class="donut-wrap">
                <div class="donut" style="background:{conic}"></div>
                <div class="donut-hole">{s.total}<br>finding{'' if s.total == 1 else 's'}</div>
            </div>
            <div class="legend">{legend_html}</div>
        </div>"""

        # ---- findings ----
        if not result.findings:
            findings_html = '<p style="color:#16a34a;font-weight:600;padding:16px 0">✓ No findings – scan clean!</p>'
        else:
            findings_html = "".join(
                _finding_detail_html(i, f) for i, f in enumerate(result.findings, 1)
            )

        # ---- errors ----
        errors_section = ""
        if result.errors:
            error_items = "".join(
                f'<li style="color:#dc2626;margin-bottom:4px">{_escape(e)}</li>'
                for e in result.errors
            )
            errors_section = f"""
            <div class="card" style="border-left:4px solid #dc2626;">
                <div class="card-header" style="color:#dc2626">⚠ Scan Errors</div>
                <div class="card-body"><ul style="padding-left:18px">{error_items}</ul></div>
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ClawGuard Security Report – {_escape(result.target)}</title>
<style>
{_HTML_CSS}
</style>
</head>
<body>
<div class="page">

    <!-- Header -->
    <div class="report-header">
        <div>
            <h1>🛡 ClawGuard</h1>
            <div class="subtitle">Security Audit Report &nbsp;·&nbsp; OpenClaw Deployment Scanner</div>
        </div>
        <div class="header-meta">
            <div><strong>Target</strong> &nbsp;{_escape(result.target)}</div>
            <div><strong>Scanned</strong> &nbsp;{ts}</div>
            <div><strong>Duration</strong> &nbsp;{result.duration_seconds:.1f}s</div>
            <div><strong>Checkers</strong> &nbsp;{_escape(', '.join(result.checkers_run))}</div>
            <div><strong>Version</strong> &nbsp;ClawGuard {_escape(result.scanner_version)}</div>
        </div>
    </div>

    <!-- Stat cards -->
    <div class="stat-grid">
        {stat_cards_html}
    </div>

    <!-- Executive Summary -->
    <div class="card">
        <div class="card-header">📊 Executive Summary</div>
        <div class="card-body">
            {risk_section}
        </div>
    </div>

    <!-- Risk Distribution -->
    <div class="card">
        <div class="card-header">🥧 Risk Distribution</div>
        <div class="card-body">
            {chart_section}
        </div>
    </div>

    <!-- Findings -->
    <div class="card">
        <div class="card-header">🔍 Findings
            <span style="font-size:12px;font-weight:400;color:#64748b;margin-left:8px">
                ({s.total} total · click to expand)
            </span>
        </div>
        <div class="card-body">
            {findings_html}
        </div>
    </div>

    {errors_section}

    <!-- Footer -->
    <div class="footer">
        Generated by <strong>ClawGuard {_escape(result.scanner_version)}</strong>
        &nbsp;·&nbsp; <a href="https://github.com/hidearmoon/clawguard" target="_blank">github.com/hidearmoon/clawguard</a>
        &nbsp;·&nbsp; {ts}
    </div>

</div>
</body>
</html>"""
        return html

    def write(self, result: ScanResult, path: str | Path) -> None:
        Path(path).write_text(self.generate(result), encoding="utf-8")
