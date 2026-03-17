"""Tests for the ClawGuard CLI – exit code logic, argument handling, and commands."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from clawguard.cli import app, _compute_exit_code
from clawguard.models import Finding, ScanResult, Severity


runner = CliRunner()


# ---------------------------------------------------------------------------
# Unit: _compute_exit_code
# ---------------------------------------------------------------------------

def _make_result(*severities: Severity) -> ScanResult:
    findings = [
        Finding(
            checker_name="test",
            title=f"Finding {i}",
            description="",
            severity=sev,
            remediation="",
            evidence={},
        )
        for i, sev in enumerate(severities)
    ]
    return ScanResult(target="test", findings=findings)


def test_exit_code_none_always_zero():
    result = _make_result(Severity.CRITICAL)
    assert _compute_exit_code(result, "none") == 0


def test_exit_code_any_with_findings():
    result = _make_result(Severity.INFO)
    assert _compute_exit_code(result, "any") == 1


def test_exit_code_any_no_findings():
    result = _make_result()
    assert _compute_exit_code(result, "any") == 0


def test_exit_code_critical_threshold_with_critical():
    result = _make_result(Severity.CRITICAL)
    assert _compute_exit_code(result, "critical") == 1


def test_exit_code_critical_threshold_only_high():
    result = _make_result(Severity.HIGH)
    assert _compute_exit_code(result, "critical") == 0


def test_exit_code_high_threshold_with_high():
    result = _make_result(Severity.HIGH)
    assert _compute_exit_code(result, "high") == 1


def test_exit_code_high_threshold_only_medium():
    result = _make_result(Severity.MEDIUM)
    assert _compute_exit_code(result, "high") == 0


def test_exit_code_medium_threshold_with_medium():
    result = _make_result(Severity.MEDIUM)
    assert _compute_exit_code(result, "medium") == 1


def test_exit_code_low_threshold_with_low():
    result = _make_result(Severity.LOW)
    assert _compute_exit_code(result, "low") == 1


def test_exit_code_no_findings_always_zero():
    result = _make_result()
    for level in ("critical", "high", "medium", "low", "any"):
        assert _compute_exit_code(result, level) == 0


# ---------------------------------------------------------------------------
# CLI: argument validation (scan subcommand)
# ---------------------------------------------------------------------------

def test_cli_scan_requires_url_or_config():
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 2
    assert "provide at least" in result.output


def test_cli_unknown_checker_exits_with_error():
    result = runner.invoke(app, ["scan", "--config", "/tmp", "--checkers", "unknown_checker"])
    assert result.exit_code == 2
    assert "Unknown checker" in result.output


# ---------------------------------------------------------------------------
# CLI: --json output
# ---------------------------------------------------------------------------

def test_cli_json_output_written(tmp_path):
    """scan --config --json should write a valid JSON file."""
    json_out = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["scan", "--config", str(tmp_path), "--json", str(json_out), "--fail-on", "none"],
    )
    assert json_out.exists(), "JSON report file should have been created"
    data = json.loads(json_out.read_text())
    assert "findings" in data
    assert "stats" in data


# ---------------------------------------------------------------------------
# CLI: --html output
# ---------------------------------------------------------------------------

def test_cli_html_output_written(tmp_path):
    """scan --config --html should write an HTML file."""
    html_out = tmp_path / "report.html"
    result = runner.invoke(
        app,
        ["scan", "--config", str(tmp_path), "--html", str(html_out), "--fail-on", "none"],
    )
    assert html_out.exists(), "HTML report file should have been created"
    content = html_out.read_text()
    assert "<!DOCTYPE html>" in content
    assert "ClawGuard" in content


# ---------------------------------------------------------------------------
# CLI: --report (text) output
# ---------------------------------------------------------------------------

def test_cli_text_report_written(tmp_path):
    """scan --config --report should write a text file."""
    txt_out = tmp_path / "report.txt"
    result = runner.invoke(
        app,
        ["scan", "--config", str(tmp_path), "--report", str(txt_out), "--fail-on", "none"],
    )
    assert txt_out.exists()
    content = txt_out.read_text()
    assert "ClawGuard" in content


# ---------------------------------------------------------------------------
# CLI: --no-brute and --checkers flags
# ---------------------------------------------------------------------------

def test_cli_no_brute_flag_accepted(tmp_path):
    """--no-brute flag should be accepted without error."""
    result = runner.invoke(
        app,
        ["scan", "--config", str(tmp_path), "--no-brute", "--fail-on", "none"],
    )
    assert result.exit_code == 0, f"Unexpected exit: {result.exit_code}\n{result.output}"


def test_cli_checkers_filter(tmp_path):
    """--checkers config should run only config checker (no dep/permission errors)."""
    result = runner.invoke(
        app,
        ["scan", "--config", str(tmp_path), "--checkers", "config", "--fail-on", "none"],
    )
    assert result.exit_code == 0, f"Unexpected exit: {result.exit_code}\n{result.output}"


def test_cli_checkers_multiple(tmp_path):
    """--checkers config,permission should be accepted."""
    result = runner.invoke(
        app,
        ["scan", "--config", str(tmp_path), "--checkers", "config,permission", "--fail-on", "none"],
    )
    assert result.exit_code == 0, f"Unexpected exit: {result.exit_code}\n{result.output}"


# ---------------------------------------------------------------------------
# CLI: list-checkers command
# ---------------------------------------------------------------------------

def test_cli_list_checkers():
    """list-checkers should print checker table and exit 0."""
    result = runner.invoke(app, ["list-checkers"])
    assert result.exit_code == 0
    assert "config" in result.output
    assert "dependency" in result.output
    assert "permission" in result.output


# ---------------------------------------------------------------------------
# CLI: --format json
# ---------------------------------------------------------------------------

def test_cli_format_json(tmp_path):
    """--format json should produce JSON output to stdout."""
    result = runner.invoke(
        app,
        ["scan", "--config", str(tmp_path), "--format", "json", "--fail-on", "none"],
    )
    assert result.exit_code == 0
    # Output should contain parseable JSON fragment
    assert '"findings"' in result.output
