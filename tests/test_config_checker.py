"""Tests for ConfigChecker – covers HTTP probing and local file auditing."""
from __future__ import annotations

import json
import stat
import tempfile
from pathlib import Path

import pytest
import respx
import httpx

from clawguard.checkers.base import CheckContext
from clawguard.checkers.config_checker import ConfigChecker
from clawguard.models import Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_context(**kwargs) -> CheckContext:
    client = kwargs.pop("http_client", httpx.AsyncClient())
    return CheckContext(http_client=client, **kwargs)


# ---------------------------------------------------------------------------
# Remote: TLS check
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_http_url_triggers_tls_finding():
    checker = ConfigChecker()
    async with httpx.AsyncClient() as client:
        ctx = make_context(target_url="http://localhost:3000", http_client=client)
        with respx.mock:
            # Mock the /api/status endpoint for rate-limit and CORS probes
            respx.get("http://localhost:3000/api/status").mock(return_value=httpx.Response(200))
            respx.options("http://localhost:3000/api/status").mock(return_value=httpx.Response(200))
            # Block credential probe (connection refused)
            respx.post("http://localhost:3000/api/user/login").mock(side_effect=httpx.RequestError("refused"))
            # Block debug endpoint probes
            for path in ["/debug/pprof", "/debug/vars", "/_debug", "/metrics"]:
                respx.get(f"http://localhost:3000{path}").mock(return_value=httpx.Response(404))

            findings = await checker.check(ctx)

    tls_findings = [f for f in findings if "plain HTTP" in f.title or "TLS" in f.title]
    assert tls_findings, "Expected a TLS finding for http:// URL"
    assert tls_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_https_url_no_tls_finding():
    checker = ConfigChecker()
    async with httpx.AsyncClient() as client:
        ctx = make_context(target_url="https://secure.example.com", http_client=client)
        with respx.mock:
            respx.get("https://secure.example.com/api/status").mock(return_value=httpx.Response(200))
            respx.options("https://secure.example.com/api/status").mock(return_value=httpx.Response(200))
            respx.post("https://secure.example.com/api/user/login").mock(side_effect=httpx.RequestError("refused"))
            for path in ["/debug/pprof", "/debug/vars", "/_debug", "/metrics"]:
                respx.get(f"https://secure.example.com{path}").mock(return_value=httpx.Response(404))

            findings = await checker.check(ctx)

    tls_findings = [f for f in findings if "plain HTTP" in f.title or "TLS" in f.title]
    assert not tls_findings, "No TLS finding expected for https:// URL"


# ---------------------------------------------------------------------------
# Remote: Default credential detection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_default_credentials_detected():
    checker = ConfigChecker()
    async with httpx.AsyncClient() as client:
        ctx = make_context(target_url="http://target:3000", http_client=client)
        with respx.mock:
            # First pair (root/123456) succeeds
            respx.post("http://target:3000/api/user/login").mock(
                return_value=httpx.Response(200, json={"success": True, "data": {"token": "abc"}})
            )
            respx.get("http://target:3000/api/status").mock(return_value=httpx.Response(200))
            respx.options("http://target:3000/api/status").mock(return_value=httpx.Response(200))
            for path in ["/debug/pprof", "/debug/vars", "/_debug", "/metrics"]:
                respx.get(f"http://target:3000{path}").mock(return_value=httpx.Response(404))

            findings = await checker.check(ctx)

    cred_findings = [f for f in findings if "default" in f.title.lower() and "credential" in f.title.lower()]
    assert cred_findings, "Expected a default credentials finding"
    assert cred_findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_no_brute_skips_credential_probe():
    checker = ConfigChecker()
    async with httpx.AsyncClient() as client:
        ctx = make_context(
            target_url="http://target:3000",
            http_client=client,
            options={"no_brute": True},
        )
        with respx.mock:
            respx.get("http://target:3000/api/status").mock(return_value=httpx.Response(200))
            respx.options("http://target:3000/api/status").mock(return_value=httpx.Response(200))
            for path in ["/debug/pprof", "/debug/vars", "/_debug", "/metrics"]:
                respx.get(f"http://target:3000{path}").mock(return_value=httpx.Response(404))
            # Login endpoint is NOT mocked — any call would raise an error
            findings = await checker.check(ctx)

    cred_findings = [f for f in findings if "credential" in f.title.lower()]
    assert not cred_findings, "Credential probe should be skipped with no_brute=True"


# ---------------------------------------------------------------------------
# Remote: CORS wildcard
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cors_wildcard_detected():
    checker = ConfigChecker()
    async with httpx.AsyncClient() as client:
        ctx = make_context(target_url="https://target:3000", http_client=client)
        with respx.mock:
            respx.post("https://target:3000/api/user/login").mock(side_effect=httpx.RequestError("refused"))
            respx.get("https://target:3000/api/status").mock(return_value=httpx.Response(200))
            respx.options("https://target:3000/api/status").mock(
                return_value=httpx.Response(
                    200,
                    headers={"access-control-allow-origin": "*"},
                )
            )
            for path in ["/debug/pprof", "/debug/vars", "/_debug", "/metrics"]:
                respx.get(f"https://target:3000{path}").mock(return_value=httpx.Response(404))

            findings = await checker.check(ctx)

    cors_findings = [f for f in findings if "CORS" in f.title and "wildcard" in f.title.lower()]
    assert cors_findings, "Expected CORS wildcard finding"
    assert cors_findings[0].severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Local: JSON config checks
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_local_json_debug_mode():
    checker = ConfigChecker()
    cfg = {"debug": True, "port": 3000}
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        json.dump(cfg, f)
        tmp_path = Path(f.name)
    try:
        ctx = make_context(config_path=str(tmp_path))
        findings = await checker.check(ctx)
    finally:
        tmp_path.unlink(missing_ok=True)

    debug_findings = [f for f in findings if "debug" in f.title.lower()]
    assert debug_findings, "Expected a debug-mode finding for JSON config"


@pytest.mark.asyncio
async def test_local_json_bind_all_interfaces():
    checker = ConfigChecker()
    cfg = {"bind_address": "0.0.0.0", "port": 3000}
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        json.dump(cfg, f)
        tmp_path = Path(f.name)
    try:
        ctx = make_context(config_path=str(tmp_path))
        findings = await checker.check(ctx)
    finally:
        tmp_path.unlink(missing_ok=True)

    bind_findings = [f for f in findings if "0.0.0.0" in f.title]
    assert bind_findings, "Expected a bind-all-interfaces finding"
    assert bind_findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_local_json_weak_secret():
    checker = ConfigChecker()
    cfg = {"jwt_secret": "short"}
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
        json.dump(cfg, f)
        tmp_path = Path(f.name)
    try:
        ctx = make_context(config_path=str(tmp_path))
        findings = await checker.check(ctx)
    finally:
        tmp_path.unlink(missing_ok=True)

    secret_findings = [f for f in findings if "secret" in f.title.lower() or "JWT" in f.title]
    assert secret_findings, "Expected a weak secret finding"
    assert secret_findings[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Local: YAML config checks (the missing feature)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_local_yaml_bind_all_interfaces():
    checker = ConfigChecker()
    yaml_content = "bind_address: '0.0.0.0'\nport: 3000\n"
    with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
        f.write(yaml_content)
        tmp_path = Path(f.name)
    try:
        ctx = make_context(config_path=str(tmp_path))
        findings = await checker.check(ctx)
    finally:
        tmp_path.unlink(missing_ok=True)

    bind_findings = [f for f in findings if "0.0.0.0" in f.title]
    assert bind_findings, "Expected a bind-all-interfaces finding from YAML config"


@pytest.mark.asyncio
async def test_local_yaml_cors_wildcard():
    checker = ConfigChecker()
    yaml_content = "allowed_origins: '*'\nport: 3000\n"
    with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
        f.write(yaml_content)
        tmp_path = Path(f.name)
    try:
        ctx = make_context(config_path=str(tmp_path))
        findings = await checker.check(ctx)
    finally:
        tmp_path.unlink(missing_ok=True)

    cors_findings = [f for f in findings if "CORS" in f.title]
    assert cors_findings, "Expected a CORS wildcard finding from YAML config"


@pytest.mark.asyncio
async def test_local_yaml_debug_mode():
    checker = ConfigChecker()
    yaml_content = "debug: true\nport: 3000\n"
    with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
        f.write(yaml_content)
        tmp_path = Path(f.name)
    try:
        ctx = make_context(config_path=str(tmp_path))
        findings = await checker.check(ctx)
    finally:
        tmp_path.unlink(missing_ok=True)

    debug_findings = [f for f in findings if "debug" in f.title.lower()]
    assert debug_findings, "Expected a debug-mode finding from YAML config"


@pytest.mark.asyncio
async def test_local_yml_extension_parsed():
    """Ensure .yml extension (not just .yaml) is parsed as YAML."""
    checker = ConfigChecker()
    yaml_content = "bind_address: '0.0.0.0'\n"
    with tempfile.NamedTemporaryFile(suffix=".yml", mode="w", delete=False) as f:
        f.write(yaml_content)
        tmp_path = Path(f.name)
    try:
        ctx = make_context(config_path=str(tmp_path))
        findings = await checker.check(ctx)
    finally:
        tmp_path.unlink(missing_ok=True)

    bind_findings = [f for f in findings if "0.0.0.0" in f.title]
    assert bind_findings, "Expected a bind-all-interfaces finding from .yml config"


@pytest.mark.asyncio
async def test_malformed_yaml_does_not_crash():
    """A broken YAML file should produce zero findings (not an exception)."""
    checker = ConfigChecker()
    with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
        f.write("key: [unclosed\nnot: valid: yaml: :\n")
        tmp_path = Path(f.name)
    try:
        ctx = make_context(config_path=str(tmp_path))
        findings = await checker.check(ctx)  # must not raise
    finally:
        tmp_path.unlink(missing_ok=True)
    # No assertion on findings – just confirming no exception is raised
