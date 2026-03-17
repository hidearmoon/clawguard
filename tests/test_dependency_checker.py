"""Tests for DependencyChecker – manifest parsing and OSV querying."""
from __future__ import annotations

import json

import pytest
import respx
import httpx

from clawguard.checkers.base import CheckContext
from clawguard.checkers.dependency_checker import (
    DependencyChecker,
    _parse_go_mod,
    _parse_package_json,
    _parse_requirements_txt,
    _severity_from_osv,
)
from clawguard.models import Severity


# ---------------------------------------------------------------------------
# Manifest parsers
# ---------------------------------------------------------------------------

def test_parse_requirements_txt_pinned():
    text = "requests==2.28.0\nflask==2.3.0\n# comment\n-r other.txt\n"
    result = _parse_requirements_txt(text)
    assert ("requests", "2.28.0") in result
    assert ("flask", "2.3.0") in result


def test_parse_requirements_txt_unpinned():
    text = "requests\nflask>=2.0\n"
    result = _parse_requirements_txt(text)
    names = [n for n, _ in result]
    assert "requests" in names
    assert "flask" in names


def test_parse_package_json_basic():
    data = {"dependencies": {"express": "^4.18.0", "axios": "1.4.0"}}
    result = _parse_package_json(json.dumps(data))
    assert ("express", "4.18.0") in result
    assert ("axios", "1.4.0") in result


def test_parse_package_json_dev_deps():
    data = {"devDependencies": {"jest": "^29.0.0"}}
    result = _parse_package_json(json.dumps(data))
    names = [n for n, _ in result]
    assert "jest" in names


def test_parse_package_json_invalid_json():
    result = _parse_package_json("not json {{")
    assert result == []


# ---------------------------------------------------------------------------
# go.mod parser – single-line and multi-line block
# ---------------------------------------------------------------------------

def test_parse_go_mod_single_line():
    text = "require github.com/foo/bar v1.2.3\n"
    result = _parse_go_mod(text)
    assert ("github.com/foo/bar", "1.2.3") in result


def test_parse_go_mod_multiline_block():
    text = (
        "module example.com/myapp\n\n"
        "go 1.21\n\n"
        "require (\n"
        "\tgithub.com/foo/bar v1.2.3\n"
        "\tgithub.com/baz/qux v2.0.0 // indirect\n"
        ")\n"
    )
    result = _parse_go_mod(text)
    assert ("github.com/foo/bar", "1.2.3") in result
    assert ("github.com/baz/qux", "2.0.0") in result


def test_parse_go_mod_indirect_stripped():
    """Indirect comment should not end up in the version string."""
    text = "require github.com/pkg/errors v0.9.1 // indirect\n"
    result = _parse_go_mod(text)
    assert ("github.com/pkg/errors", "0.9.1") in result


def test_parse_go_mod_empty():
    assert _parse_go_mod("module example.com/app\ngo 1.21\n") == []


# ---------------------------------------------------------------------------
# CVSS severity mapping (the fixed logic)
# ---------------------------------------------------------------------------

def test_severity_from_osv_cvss_critical():
    """CVSS v3.1 vector with base score ≥ 9.0 → CRITICAL."""
    vuln = {
        "severity": [
            {
                "type": "CVSS_V3",
                # AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            }
        ]
    }
    assert _severity_from_osv(vuln) == Severity.CRITICAL


def test_severity_from_osv_cvss_high():
    """CVSS v3.1 vector with base score 7.0–8.9 → HIGH."""
    vuln = {
        "severity": [
            {
                "type": "CVSS_V3",
                # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            }
        ]
    }
    assert _severity_from_osv(vuln) == Severity.HIGH


def test_severity_from_osv_database_specific_numeric():
    """Fallback to database_specific.cvss_score when no CVSS vector."""
    vuln = {"severity": [], "database_specific": {"cvss_score": "8.1"}}
    assert _severity_from_osv(vuln) == Severity.HIGH


def test_severity_from_osv_database_specific_label():
    """Fallback to database_specific.severity string label."""
    vuln = {"severity": [], "database_specific": {"severity": "MODERATE"}}
    assert _severity_from_osv(vuln) == Severity.MEDIUM


def test_severity_from_osv_unknown_defaults_medium():
    """Completely empty severity info defaults to MEDIUM (safe default)."""
    vuln = {"severity": [], "database_specific": {}}
    assert _severity_from_osv(vuln) == Severity.MEDIUM


# ---------------------------------------------------------------------------
# OSV integration: mocked HTTP responses
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dependency_checker_detects_vuln(tmp_path):
    """DependencyChecker should return a finding when OSV reports a vulnerability."""
    req_txt = tmp_path / "requirements.txt"
    req_txt.write_text("requests==2.27.0\n")

    osv_response = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-j8r2-6x86-q33q",
                        "summary": "SSRF via crafted proxy URL",
                        "aliases": ["CVE-2023-32681"],
                        "severity": [
                            {
                                "type": "CVSS_V3",
                                "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N",
                            }
                        ],
                        "affected": [
                            {
                                "ranges": [
                                    {
                                        "events": [
                                            {"introduced": "0"},
                                            {"fixed": "2.31.0"},
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                ]
            }
        ]
    }

    checker = DependencyChecker()
    with respx.mock:
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            return_value=httpx.Response(200, json=osv_response)
        )
        async with httpx.AsyncClient() as client:
            ctx = CheckContext(config_path=str(tmp_path), http_client=client)
            findings = await checker.check(ctx)

    assert findings, "Expected at least one finding for a known-vulnerable package"
    assert any("requests" in f.title for f in findings)
    assert any("CVE-2023-32681" in f.cve_ids for f in findings)


@pytest.mark.asyncio
async def test_dependency_checker_no_manifests(tmp_path):
    """No manifests found → no findings, no crash."""
    checker = DependencyChecker()
    ctx = CheckContext(config_path=str(tmp_path))
    findings = await checker.check(ctx)
    assert findings == []


@pytest.mark.asyncio
async def test_dependency_checker_osv_error_handled(tmp_path):
    """OSV network error should not crash the checker – returns empty findings."""
    req_txt = tmp_path / "requirements.txt"
    req_txt.write_text("requests==2.27.0\n")

    checker = DependencyChecker()
    with respx.mock:
        respx.post("https://api.osv.dev/v1/querybatch").mock(
            side_effect=httpx.RequestError("connection refused")
        )
        async with httpx.AsyncClient() as client:
            ctx = CheckContext(config_path=str(tmp_path), http_client=client)
            findings = await checker.check(ctx)

    assert findings == [], "Network error should result in empty findings, not exception"


@pytest.mark.asyncio
async def test_dependency_checker_no_config_path():
    """Should skip gracefully when no config_path is provided."""
    checker = DependencyChecker()
    ctx = CheckContext(target_url="http://localhost:3000")
    findings = await checker.check(ctx)
    assert findings == []
