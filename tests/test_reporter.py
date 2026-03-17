"""Tests for TextReporter, JSONReporter, and HTMLReporter."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from clawguard.models import Finding, ScanResult, Severity
from clawguard.reporter import HTMLReporter, JSONReporter, TextReporter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_result(*severities: Severity, errors: list[str] | None = None) -> ScanResult:
    findings = [
        Finding(
            checker_name="test",
            title=f"Finding {sev.value}",
            description=f"Description for {sev.value}",
            severity=sev,
            remediation=f"Fix {sev.value}",
            evidence={"key": "val"},
            references=["https://example.com/ref"],
            cve_ids=["CVE-2024-0001"] if sev == Severity.CRITICAL else [],
        )
        for sev in severities
    ]
    return ScanResult(
        target="http://test.example.com",
        findings=findings,
        duration_seconds=2.5,
        checkers_run=["config", "dependency"],
        errors=errors or [],
        scan_time=datetime(2026, 3, 17, 9, 0, 0, tzinfo=timezone.utc),
    )


@pytest.fixture
def empty_result() -> ScanResult:
    return _make_result()


@pytest.fixture
def rich_result() -> ScanResult:
    return _make_result(
        Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
    )


# ---------------------------------------------------------------------------
# TextReporter
# ---------------------------------------------------------------------------

class TestTextReporter:
    def test_generate_returns_string(self, rich_result: ScanResult) -> None:
        text = TextReporter().generate(rich_result)
        assert isinstance(text, str)
        assert len(text) > 0

    def test_contains_target(self, rich_result: ScanResult) -> None:
        text = TextReporter().generate(rich_result)
        assert "http://test.example.com" in text

    def test_contains_severity_labels(self, rich_result: ScanResult) -> None:
        text = TextReporter().generate(rich_result)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert sev in text

    def test_contains_remediation(self, rich_result: ScanResult) -> None:
        text = TextReporter().generate(rich_result)
        assert "Fix CRITICAL" in text

    def test_contains_cve(self, rich_result: ScanResult) -> None:
        text = TextReporter().generate(rich_result)
        assert "CVE-2024-0001" in text

    def test_clean_scan_message(self, empty_result: ScanResult) -> None:
        text = TextReporter().generate(empty_result)
        assert "clean" in text.lower()

    def test_risk_score_present(self, rich_result: ScanResult) -> None:
        text = TextReporter().generate(rich_result)
        assert "Risk Score" in text

    def test_errors_included(self) -> None:
        result = _make_result(errors=["checker x: timeout"])
        text = TextReporter().generate(result)
        assert "checker x: timeout" in text

    def test_write_creates_file(self, rich_result: ScanResult, tmp_path: Path) -> None:
        out = tmp_path / "report.txt"
        TextReporter().write(rich_result, out)
        assert out.exists()
        assert len(out.read_text()) > 100


# ---------------------------------------------------------------------------
# JSONReporter
# ---------------------------------------------------------------------------

class TestJSONReporter:
    def test_generate_valid_json(self, rich_result: ScanResult) -> None:
        raw = JSONReporter().generate(rich_result)
        data = json.loads(raw)
        assert "findings" in data
        assert "stats" in data

    def test_findings_count_matches(self, rich_result: ScanResult) -> None:
        data = json.loads(JSONReporter().generate(rich_result))
        assert data["stats"]["total"] == 5

    def test_target_in_output(self, rich_result: ScanResult) -> None:
        data = json.loads(JSONReporter().generate(rich_result))
        assert data["target"] == "http://test.example.com"

    def test_severity_values(self, rich_result: ScanResult) -> None:
        data = json.loads(JSONReporter().generate(rich_result))
        sevs = {f["severity"] for f in data["findings"]}
        assert sevs == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def test_empty_result(self, empty_result: ScanResult) -> None:
        data = json.loads(JSONReporter().generate(empty_result))
        assert data["findings"] == []
        assert data["stats"]["total"] == 0

    def test_write_creates_valid_json_file(self, rich_result: ScanResult, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        JSONReporter().write(rich_result, out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert "findings" in data


# ---------------------------------------------------------------------------
# HTMLReporter
# ---------------------------------------------------------------------------

class TestHTMLReporter:
    def test_generate_returns_html_string(self, rich_result: ScanResult) -> None:
        html = HTMLReporter().generate(rich_result)
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html

    def test_contains_target(self, rich_result: ScanResult) -> None:
        html = HTMLReporter().generate(rich_result)
        assert "http://test.example.com" in html

    def test_contains_severity_badges(self, rich_result: ScanResult) -> None:
        html = HTMLReporter().generate(rich_result)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert f"badge-{sev}" in html

    def test_contains_finding_titles(self, rich_result: ScanResult) -> None:
        html = HTMLReporter().generate(rich_result)
        assert "Finding CRITICAL" in html
        assert "Finding HIGH" in html

    def test_cve_rendered(self, rich_result: ScanResult) -> None:
        html = HTMLReporter().generate(rich_result)
        assert "CVE-2024-0001" in html

    def test_remediation_box(self, rich_result: ScanResult) -> None:
        html = HTMLReporter().generate(rich_result)
        assert "remediation-box" in html

    def test_donut_chart_present(self, rich_result: ScanResult) -> None:
        html = HTMLReporter().generate(rich_result)
        assert "conic-gradient" in html
        assert "donut" in html

    def test_clean_scan_no_conic_gradient_with_no_findings(self, empty_result: ScanResult) -> None:
        html = HTMLReporter().generate(empty_result)
        # With no findings, chart shows clean state
        assert "No findings" in html

    def test_risk_score_in_html(self, rich_result: ScanResult) -> None:
        html = HTMLReporter().generate(rich_result)
        score = rich_result.stats.risk_score
        assert str(score) in html

    def test_self_contained_no_external_resources(self, rich_result: ScanResult) -> None:
        html = HTMLReporter().generate(rich_result)
        # Should not reference external CDN/scripts
        assert "cdn.jsdelivr.net" not in html
        assert "unpkg.com" not in html
        assert "<script src" not in html

    def test_errors_section(self) -> None:
        result = _make_result(Severity.HIGH, errors=["dep: OSV timeout"])
        html = HTMLReporter().generate(result)
        assert "Scan Errors" in html
        assert "dep: OSV timeout" in html

    def test_write_creates_html_file(self, rich_result: ScanResult, tmp_path: Path) -> None:
        out = tmp_path / "report.html"
        HTMLReporter().write(rich_result, out)
        assert out.exists()
        content = out.read_text()
        assert "<!DOCTYPE html>" in content

    def test_xss_escape_in_title(self) -> None:
        result = ScanResult(
            target='<script>alert(1)</script>',
            findings=[
                Finding(
                    checker_name="test",
                    title='<img src=x onerror=alert(1)>',
                    description="xss test",
                    severity=Severity.HIGH,
                    remediation="fix it",
                )
            ],
            checkers_run=["test"],
        )
        html = HTMLReporter().generate(result)
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html
        assert "<img src=x" not in html
