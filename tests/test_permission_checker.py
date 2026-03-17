"""Tests for PermissionChecker – API key hygiene and file-system permissions."""
from __future__ import annotations

import os
import stat
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import respx
import httpx

from clawguard.checkers.base import CheckContext
from clawguard.checkers.permission_checker import PermissionChecker
from clawguard.models import Severity

NOW = datetime.now(timezone.utc)


def _ts(days_ago: int) -> int:
    """Return a Unix timestamp for N days ago."""
    return int((NOW - timedelta(days=days_ago)).timestamp())


# ---------------------------------------------------------------------------
# Remote: token rotation age
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stale_token_triggers_high_finding():
    """Token older than 365 days should yield a HIGH finding."""
    tokens = [{"id": 1, "name": "old-key", "created_time": _ts(400), "status": 1, "used_quota": 100}]
    checker = PermissionChecker()
    with respx.mock:
        respx.get("http://target:3000/api/token/?p=0&size=500").mock(
            return_value=httpx.Response(200, json={"success": True, "data": tokens})
        )
        async with httpx.AsyncClient() as client:
            ctx = CheckContext(target_url="http://target:3000", api_key="admin-key", http_client=client)
            findings = await checker.check(ctx)

    rotation_findings = [f for f in findings if "rotated" in f.title.lower() or "rotation" in f.title.lower()]
    assert rotation_findings, "Expected a rotation-overdue finding"
    assert rotation_findings[0].severity in (Severity.HIGH, Severity.CRITICAL)


@pytest.mark.asyncio
async def test_medium_rotation_warning():
    """Token between 90 and 364 days should yield a MEDIUM warning."""
    tokens = [{"id": 2, "name": "aging-key", "created_time": _ts(100), "status": 1, "used_quota": 50}]
    checker = PermissionChecker()
    with respx.mock:
        respx.get("http://target:3000/api/token/?p=0&size=500").mock(
            return_value=httpx.Response(200, json={"success": True, "data": tokens})
        )
        async with httpx.AsyncClient() as client:
            ctx = CheckContext(target_url="http://target:3000", api_key="admin-key", http_client=client)
            findings = await checker.check(ctx)

    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM and "rotation" in f.title.lower()]
    assert medium_findings, "Expected a MEDIUM rotation warning"


@pytest.mark.asyncio
async def test_fresh_token_no_rotation_finding():
    """Token only 10 days old should not trigger any rotation finding."""
    tokens = [{"id": 3, "name": "fresh-key", "created_time": _ts(10), "status": 1, "used_quota": 5}]
    checker = PermissionChecker()
    with respx.mock:
        respx.get("http://target:3000/api/token/?p=0&size=500").mock(
            return_value=httpx.Response(200, json={"success": True, "data": tokens})
        )
        async with httpx.AsyncClient() as client:
            ctx = CheckContext(target_url="http://target:3000", api_key="admin-key", http_client=client)
            findings = await checker.check(ctx)

    rotation_findings = [f for f in findings if "rotated" in f.title.lower() or "rotation" in f.title.lower()]
    assert not rotation_findings, "No rotation finding expected for a fresh token"


# ---------------------------------------------------------------------------
# Remote: over-privileged key
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_overprivileged_key_detected():
    """Admin key assigned to a regular (non-admin) user should be flagged HIGH."""
    tokens = [
        {
            "id": 4,
            "name": "power-user-key",
            "created_time": _ts(30),
            "status": 1,
            "unlimited_quota": True,
            "user_role": "user",  # non-admin user
            "used_quota": 10,
        }
    ]
    checker = PermissionChecker()
    with respx.mock:
        respx.get("http://target:3000/api/token/?p=0&size=500").mock(
            return_value=httpx.Response(200, json={"success": True, "data": tokens})
        )
        async with httpx.AsyncClient() as client:
            ctx = CheckContext(target_url="http://target:3000", api_key="admin-key", http_client=client)
            findings = await checker.check(ctx)

    priv_findings = [f for f in findings if "privileged" in f.title.lower() or "over-priv" in f.title.lower()]
    assert priv_findings, "Expected an over-privileged key finding"
    assert priv_findings[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Remote: unused active key
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unused_active_key_detected():
    """Active key with zero usage should be flagged as LOW finding."""
    tokens = [
        {
            "id": 5,
            "name": "never-used-key",
            "created_time": _ts(60),
            "status": 1,
            "used_quota": 0,
        }
    ]
    checker = PermissionChecker()
    with respx.mock:
        respx.get("http://target:3000/api/token/?p=0&size=500").mock(
            return_value=httpx.Response(200, json={"success": True, "data": tokens})
        )
        async with httpx.AsyncClient() as client:
            ctx = CheckContext(target_url="http://target:3000", api_key="admin-key", http_client=client)
            findings = await checker.check(ctx)

    unused_findings = [f for f in findings if "unused" in f.title.lower() or "never used" in f.title.lower()]
    assert unused_findings, "Expected an unused-key finding"
    assert unused_findings[0].severity == Severity.LOW


# ---------------------------------------------------------------------------
# Remote: no API key → INFO finding
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_api_key_produces_info_finding():
    """Without --api-key, remote permission checks should emit an INFO finding."""
    checker = PermissionChecker()
    async with httpx.AsyncClient() as client:
        ctx = CheckContext(target_url="http://target:3000", http_client=client)
        findings = await checker.check(ctx)

    info_findings = [f for f in findings if f.severity == Severity.INFO]
    assert info_findings, "Expected an INFO finding when no API key is provided"


# ---------------------------------------------------------------------------
# Remote: 401 response → no crash
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_invalid_api_key_returns_empty():
    """401 from the token endpoint should be handled gracefully."""
    checker = PermissionChecker()
    with respx.mock:
        respx.get("http://target:3000/api/token/?p=0&size=500").mock(
            return_value=httpx.Response(401)
        )
        async with httpx.AsyncClient() as client:
            ctx = CheckContext(target_url="http://target:3000", api_key="bad-key", http_client=client)
            findings = await checker.check(ctx)

    # Should not crash; may return zero remote findings (no INFO either as key was provided)
    remote_findings = [f for f in findings if "privileged" in f.title.lower() or "rotated" in f.title.lower()]
    assert not remote_findings


# ---------------------------------------------------------------------------
# Local: file-system permission checks
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_world_readable_key_file_detected(tmp_path):
    """A world-readable .pem file should trigger a HIGH finding."""
    key_file = tmp_path / "server.pem"
    key_file.write_text("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
    key_file.chmod(0o644)  # world-readable

    checker = PermissionChecker()
    ctx = CheckContext(config_path=str(tmp_path))
    findings = await checker.check(ctx)

    perm_findings = [f for f in findings if "world-readable" in f.title.lower()]
    assert perm_findings, "Expected a world-readable finding for .pem file"
    assert perm_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_private_key_file_600_no_finding(tmp_path):
    """A key file with 600 permissions should not trigger any permission finding."""
    key_file = tmp_path / "server.key"
    key_file.write_text("PRIVATE KEY CONTENT")
    key_file.chmod(0o600)  # owner-only

    checker = PermissionChecker()
    ctx = CheckContext(config_path=str(tmp_path))
    findings = await checker.check(ctx)

    world_readable = [f for f in findings if "world-readable" in f.title.lower() and "server.key" in f.title]
    assert not world_readable, "600-permission key file should not trigger world-readable finding"
