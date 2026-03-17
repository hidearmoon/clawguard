"""Tests for the Scanner orchestration layer."""
from __future__ import annotations

import pytest
import respx
import httpx

from clawguard.checkers.base import BaseChecker, CheckContext, CheckerMode
from clawguard.models import Finding, Severity, ScanResult
from clawguard.scanner import Scanner


# ---------------------------------------------------------------------------
# Minimal stub checker
# ---------------------------------------------------------------------------

class _AlwaysFindingChecker(BaseChecker):
    name = "stub"
    description = "Always returns one HIGH finding"
    mode = CheckerMode.BOTH

    async def check(self, context: CheckContext) -> list[Finding]:
        return [
            Finding(
                checker_name=self.name,
                title="Stub finding",
                description="This is a stub.",
                severity=Severity.HIGH,
                remediation="Fix it.",
                evidence={},
            )
        ]


class _CrashingChecker(BaseChecker):
    name = "crasher"
    description = "Always raises an exception"
    mode = CheckerMode.BOTH

    async def check(self, context: CheckContext) -> list[Finding]:
        raise RuntimeError("intentional crash in test")


class _NoFindingChecker(BaseChecker):
    name = "clean"
    description = "Returns no findings"
    mode = CheckerMode.BOTH

    async def check(self, context: CheckContext) -> list[Finding]:
        return []


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_scanner_requires_url_or_config():
    with pytest.raises(ValueError, match="At least one"):
        Scanner()


@pytest.mark.asyncio
async def test_scanner_runs_extra_checker(tmp_path):
    scanner = Scanner(
        config_path=str(tmp_path),
        extra_checkers=[_AlwaysFindingChecker()],
    )
    # Disable built-in checkers to isolate stub
    scanner._extra_checkers = [_AlwaysFindingChecker()]
    # Patch built-ins to clean stubs too
    from clawguard import scanner as scanner_module
    original = scanner_module._BUILTIN_CHECKERS
    scanner_module._BUILTIN_CHECKERS = []
    try:
        result = await scanner.run()
    finally:
        scanner_module._BUILTIN_CHECKERS = original

    assert result.stats.total >= 1
    assert any(f.checker_name == "stub" for f in result.findings)


@pytest.mark.asyncio
async def test_scanner_crashing_checker_recorded_in_errors(tmp_path):
    """A checker that raises should not crash the whole scan; error is logged."""
    from clawguard import scanner as scanner_module
    original = scanner_module._BUILTIN_CHECKERS
    scanner_module._BUILTIN_CHECKERS = []
    try:
        scanner = Scanner(
            config_path=str(tmp_path),
            extra_checkers=[_CrashingChecker()],
        )
        result = await scanner.run()
    finally:
        scanner_module._BUILTIN_CHECKERS = original

    assert "crasher" in result.checkers_run
    assert any("crasher" in e for e in result.errors)


@pytest.mark.asyncio
async def test_scanner_findings_sorted_by_severity(tmp_path):
    """ScanResult.findings must be sorted most-severe first."""

    class _MultiSeverityChecker(BaseChecker):
        name = "multi"
        description = "Returns findings of various severities"
        mode = CheckerMode.BOTH

        async def check(self, ctx: CheckContext) -> list[Finding]:
            return [
                Finding(checker_name="multi", title="Low", description="", severity=Severity.LOW, remediation="", evidence={}),
                Finding(checker_name="multi", title="Critical", description="", severity=Severity.CRITICAL, remediation="", evidence={}),
                Finding(checker_name="multi", title="Medium", description="", severity=Severity.MEDIUM, remediation="", evidence={}),
            ]

    from clawguard import scanner as scanner_module
    original = scanner_module._BUILTIN_CHECKERS
    scanner_module._BUILTIN_CHECKERS = []
    try:
        scanner = Scanner(
            config_path=str(tmp_path),
            extra_checkers=[_MultiSeverityChecker()],
        )
        result = await scanner.run()
    finally:
        scanner_module._BUILTIN_CHECKERS = original

    severities = [f.severity for f in result.findings]
    weights = [s.weight for s in severities]
    assert weights == sorted(weights, reverse=True), "Findings not sorted by severity descending"


@pytest.mark.asyncio
async def test_scanner_summary_stats_accurate(tmp_path):
    """SummaryStats should accurately count findings per severity."""

    class _KnownChecker(BaseChecker):
        name = "known"
        description = "Returns 1 CRITICAL, 2 HIGH"
        mode = CheckerMode.BOTH

        async def check(self, ctx: CheckContext) -> list[Finding]:
            return [
                Finding(checker_name="known", title="C1", description="", severity=Severity.CRITICAL, remediation="", evidence={}),
                Finding(checker_name="known", title="H1", description="", severity=Severity.HIGH, remediation="", evidence={}),
                Finding(checker_name="known", title="H2", description="", severity=Severity.HIGH, remediation="", evidence={}),
            ]

    from clawguard import scanner as scanner_module
    original = scanner_module._BUILTIN_CHECKERS
    scanner_module._BUILTIN_CHECKERS = []
    try:
        scanner = Scanner(config_path=str(tmp_path), extra_checkers=[_KnownChecker()])
        result = await scanner.run()
    finally:
        scanner_module._BUILTIN_CHECKERS = original

    assert result.stats.critical == 1
    assert result.stats.high == 2
    assert result.stats.total == 3


@pytest.mark.asyncio
async def test_scanner_clean_result(tmp_path):
    """Scanner with no-finding checker should report total=0 and exit_code=0."""
    from clawguard import scanner as scanner_module
    original = scanner_module._BUILTIN_CHECKERS
    scanner_module._BUILTIN_CHECKERS = []
    try:
        scanner = Scanner(config_path=str(tmp_path), extra_checkers=[_NoFindingChecker()])
        result = await scanner.run()
    finally:
        scanner_module._BUILTIN_CHECKERS = original

    assert result.stats.total == 0
    assert result.exit_code() == 0
