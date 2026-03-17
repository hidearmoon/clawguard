"""
Shared utility functions for ClawGuard.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from clawguard.models import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)

console = Console()
err_console = Console(stderr=True)

# Severity → Rich style
_SEV_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        level=level,
    )


def print_result(result: ScanResult, show_evidence: bool = False) -> None:
    """Render a ScanResult to the terminal using Rich."""
    _print_header(result)
    if not result.findings:
        console.print("\n[bold green]No findings – scan clean![/bold green]\n")
        return
    _print_findings_table(result.findings, show_evidence)
    _print_summary(result)


def _print_header(result: ScanResult) -> None:
    ts = result.scan_time.strftime("%Y-%m-%d %H:%M:%S UTC")
    console.print(
        Panel(
            f"[bold]Target:[/bold]  {result.target}\n"
            f"[bold]Scanned:[/bold] {ts}\n"
            f"[bold]Checkers:[/bold] {', '.join(result.checkers_run)}\n"
            f"[bold]Duration:[/bold] {result.duration_seconds:.1f}s",
            title="[bold blue]ClawGuard Security Scan[/bold blue]",
            border_style="blue",
        )
    )


def _print_findings_table(findings: list[Finding], show_evidence: bool) -> None:
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold",
        title=f"[bold]Findings ({len(findings)} total)[/bold]",
    )
    table.add_column("Sev", style="bold", width=8)
    table.add_column("Checker", width=12)
    table.add_column("Title")
    if show_evidence:
        table.add_column("Evidence", width=30)

    for f in findings:
        sev_cell = f"[{_SEV_STYLE[f.severity]}]{f.severity.value}[/{_SEV_STYLE[f.severity]}]"
        row: list[Any] = [sev_cell, f.checker_name, f.title]
        if show_evidence:
            evidence_str = ", ".join(f"{k}={v}" for k, v in f.evidence.items())
            row.append(evidence_str[:80])
        table.add_row(*row)

    console.print(table)


def _print_summary(result: ScanResult) -> None:
    s = result.stats
    score = s.risk_score
    score_color = "red" if score >= 70 else "yellow" if score >= 30 else "green"

    console.print(
        Panel(
            f"CRITICAL: [bold red]{s.critical}[/bold red]  "
            f"HIGH: [red]{s.high}[/red]  "
            f"MEDIUM: [yellow]{s.medium}[/yellow]  "
            f"LOW: [cyan]{s.low}[/cyan]  "
            f"INFO: [dim]{s.info}[/dim]\n"
            f"Risk Score: [{score_color}]{score}/100[/{score_color}]",
            title="[bold]Summary[/bold]",
            border_style=score_color,
        )
    )

    if result.errors:
        console.print("[bold red]Errors during scan:[/bold red]")
        for err in result.errors:
            console.print(f"  • {err}")


def export_json(result: ScanResult, path: str | Path) -> None:
    """Write the ScanResult as formatted JSON."""
    out = Path(path)
    out.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    logger.info("JSON report written to %s", out)


def export_text(result: ScanResult, path: str | Path) -> None:
    """Write a plain-text report."""
    out = Path(path)
    lines: list[str] = [
        "=" * 72,
        "ClawGuard Security Audit Report",
        f"Target:   {result.target}",
        f"Scanned:  {result.scan_time.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Duration: {result.duration_seconds:.1f}s",
        "=" * 72,
        "",
    ]
    if not result.findings:
        lines.append("No findings – scan clean.")
    else:
        for i, f in enumerate(result.findings, 1):
            lines += [
                f"[{i}] [{f.severity.value}] {f.title}",
                f"    Checker:     {f.checker_name}",
                f"    Description: {f.description}",
                f"    Remediation: {f.remediation}",
            ]
            if f.cve_ids:
                lines.append(f"    CVEs:        {', '.join(f.cve_ids)}")
            if f.evidence:
                lines.append(f"    Evidence:    {json.dumps(f.evidence)}")
            lines.append("")

    s = result.stats
    lines += [
        "-" * 72,
        f"CRITICAL: {s.critical}  HIGH: {s.high}  MEDIUM: {s.medium}  LOW: {s.low}  INFO: {s.info}",
        f"Risk Score: {s.risk_score}/100",
        "",
    ]
    out.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Text report written to %s", out)
