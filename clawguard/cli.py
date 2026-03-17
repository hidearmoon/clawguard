"""
ClawGuard CLI – entry point for the `clawguard` command.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich import box

from clawguard.scanner import Scanner
from clawguard.utils import print_result, setup_logging
from clawguard.reporter import HTMLReporter, JSONReporter, TextReporter

# All built-in checker metadata (name → description)
_BUILTIN_CHECKER_INFO: list[tuple[str, str]] = [
    ("config",      "Configuration security: TLS, default credentials, CORS, debug mode, weak secrets"),
    ("dependency",  "Dependency CVE scan via OSV API (requirements.txt, package.json, go.mod)"),
    ("permission",  "API key hygiene, over-privilege detection, file permission audit"),
]

app = typer.Typer(
    name="clawguard",
    help="Security audit and vulnerability scanner for OpenClaw deployments.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

@app.command("scan")
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
    checkers: Optional[str] = typer.Option(
        None, "--checkers",
        help="Comma-separated list of checkers to run (default: all). "
             "Available: config, dependency, permission",
    ),
    output_json: Optional[str] = typer.Option(
        None, "--json", "-j", help="Save JSON report to this path"
    ),
    output_html: Optional[str] = typer.Option(
        None, "--html", help="Save HTML report to this path"
    ),
    output_text: Optional[str] = typer.Option(
        None, "--report", "-r", help="Save text report to this path"
    ),
    fmt: Optional[str] = typer.Option(
        None, "--format", "-f",
        help="Print format to stdout: text (default, uses rich) | json | none",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging"),
    show_evidence: bool = typer.Option(False, "--evidence", "-e", help="Show evidence in terminal output"),
    fail_on: str = typer.Option(
        "critical",
        "--fail-on",
        help="Exit with non-zero code when findings of this severity or above exist "
             "(critical|high|medium|low|any|none)",
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
        err_console.print("[bold red]Error:[/bold red] provide at least --url or --config")
        raise typer.Exit(2)

    # Parse checker filter
    enabled: list[str] | None = None
    if checkers:
        enabled = [c.strip().lower() for c in checkers.split(",") if c.strip()]
        known = {name for name, _ in _BUILTIN_CHECKER_INFO}
        unknown = [n for n in enabled if n not in known]
        if unknown:
            err_console.print(
                f"[bold red]Error:[/bold red] Unknown checker(s): {', '.join(unknown)}. "
                f"Run [bold]clawguard list-checkers[/bold] to see available checkers."
            )
            raise typer.Exit(2)

    # Run scan with a Rich spinner
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}[/bold blue]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(
            f"Scanning [cyan]{target_url or config_path}[/cyan] …", total=None
        )
        result = asyncio.run(
            Scanner(
                target_url=target_url,
                config_path=config_path,
                api_key=api_key,
                timeout=timeout,
                options={"no_brute": no_brute},
                enabled_checkers=enabled,
            ).run()
        )
        progress.update(task, description="Scan complete")

    # Terminal output
    stdout_fmt = (fmt or "text").lower()
    if stdout_fmt == "json":
        console.print_json(JSONReporter().generate(result))
    elif stdout_fmt != "none":
        print_result(result, show_evidence=show_evidence)

    # File outputs
    if output_json:
        JSONReporter().write(result, output_json)
        console.print(f"[dim]JSON report saved → [underline]{output_json}[/underline][/dim]")

    if output_html:
        HTMLReporter().write(result, output_html)
        console.print(f"[dim]HTML report saved → [underline]{output_html}[/underline][/dim]")

    if output_text:
        TextReporter().write(result, output_text)
        console.print(f"[dim]Text report saved → [underline]{output_text}[/underline][/dim]")

    exit_code = _compute_exit_code(result, fail_on)
    raise typer.Exit(exit_code)


# ---------------------------------------------------------------------------
# list-checkers command
# ---------------------------------------------------------------------------

@app.command("list-checkers")
def list_checkers() -> None:
    """List all available built-in checkers."""
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold",
        title="[bold blue]Available Checkers[/bold blue]",
    )
    table.add_column("Name", style="bold cyan", width=14)
    table.add_column("Description")

    for name, description in _BUILTIN_CHECKER_INFO:
        table.add_row(name, description)

    console.print(table)
    console.print(
        "\n[dim]Use [bold]--checkers config,dependency[/bold] to run only specific checkers.[/dim]"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _compute_exit_code(result: object, fail_on: str) -> int:
    from clawguard.models import Severity

    fail_on = fail_on.lower()
    if fail_on == "none":
        return 0
    if fail_on == "any":
        return 1 if result.stats.total > 0 else 0  # type: ignore[attr-defined]

    sev_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    threshold = sev_map.get(fail_on, Severity.CRITICAL)
    for finding in result.findings:  # type: ignore[attr-defined]
        if finding.severity.weight >= threshold.weight:
            return 1
    return 0


if __name__ == "__main__":
    app()
