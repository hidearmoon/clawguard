"""
ClawGuard CLI – entry point for the `clawguard` command.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer

from clawguard.scanner import Scanner
from clawguard.utils import export_json, export_text, print_result, setup_logging

app = typer.Typer(
    name="clawguard",
    help="Security audit and vulnerability scanner for OpenClaw deployments.",
    add_completion=False,
)


@app.command()
def scan(
    target_url: Optional[str] = typer.Option(
        None, "--url", "-u", help="OpenClaw instance URL (e.g. http://localhost:3000)"
    ),
    config_path: Optional[str] = typer.Option(
        None, "--config", "-c", help="Path to OpenClaw config directory or file"
    ),
    api_key: Optional[str] = typer.Option(
        None, "--api-key", "-k", help="Admin API key for authenticated remote checks"
    ),
    timeout: float = typer.Option(15.0, "--timeout", "-t", help="Per-request timeout (seconds)"),
    output_json: Optional[str] = typer.Option(
        None, "--json", "-j", help="Save JSON report to this path"
    ),
    output_text: Optional[str] = typer.Option(
        None, "--report", "-r", help="Save text report to this path"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging"),
    show_evidence: bool = typer.Option(False, "--evidence", "-e", help="Show evidence in terminal output"),
    fail_on: str = typer.Option(
        "critical",
        "--fail-on",
        help="Exit with non-zero code when findings of this severity or above exist (critical|high|medium|low|any|none)",
    ),
    no_brute: bool = typer.Option(
        False,
        "--no-brute",
        help="Skip default-credential probing (use in environments with account lockout policies)",
    ),
) -> None:
    """Run a ClawGuard security audit against an OpenClaw instance."""
    setup_logging(verbose)

    if not target_url and not config_path:
        typer.echo("Error: provide at least --url or --config", err=True)
        raise typer.Exit(2)

    result = asyncio.run(
        Scanner(
            target_url=target_url,
            config_path=config_path,
            api_key=api_key,
            timeout=timeout,
            options={"no_brute": no_brute},
        ).run()
    )

    print_result(result, show_evidence=show_evidence)

    if output_json:
        export_json(result, output_json)
        typer.echo(f"JSON report saved to {output_json}")

    if output_text:
        export_text(result, output_text)
        typer.echo(f"Text report saved to {output_text}")

    exit_code = _compute_exit_code(result, fail_on)
    raise typer.Exit(exit_code)


def _compute_exit_code(result, fail_on: str) -> int:
    from clawguard.models import Severity

    fail_on = fail_on.lower()
    if fail_on == "none":
        return 0
    if fail_on == "any":
        return 1 if result.stats.total > 0 else 0

    sev_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    threshold = sev_map.get(fail_on, Severity.CRITICAL)
    for finding in result.findings:
        if finding.severity.weight >= threshold.weight:
            return 1
    return 0


if __name__ == "__main__":
    app()
