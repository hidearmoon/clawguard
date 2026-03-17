"""Tests for the ClawGuard CLI – exit code logic and argument handling."""
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
# CLI: argument validation
# ---------------------------------------------------------------------------

def test_cli_no_args_exits_nonzero():
    result = runner.invoke(app, [])
    assert result.exit_code != 0


def test_cli_requires_url_or_config():
    result = runner.invoke(app, [])
    assert result.exit_code == 2
    assert "provide at least" in result.output


# ---------------------------------------------------------------------------
# CLI: --json output (using a real tmp dir as config_path)
# ---------------------------------------------------------------------------

def test_cli_json_output_written(tmp_path):
    """Running scan with --config and --json should write a valid JSON file."""
    json_out = tmp_path / "report.json"
    # Run against the tmp_path config dir (empty dir → no findings expected)
    result = runner.invoke(
        app,
        ["--config", str(tmp_path), "--json", str(json_out), "--fail-on", "none"],
    )
    assert json_out.exists(), "JSON report file should have been created"
    data = json.loads(json_out.read_text())
    assert "findings" in data
    assert "stats" in data


def test_cli_no_brute_flag_accepted(tmp_path):
    """--no-brute flag should be accepted without error."""
    result = runner.invoke(
        app,
        ["--config", str(tmp_path), "--no-brute", "--fail-on", "none"],
    )
    # Exit code 0 expected (no findings in empty dir with fail-on=none)
    assert result.exit_code == 0, f"Unexpected exit code: {result.exit_code}\n{result.output}"
