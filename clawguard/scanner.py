"""
ClawGuard Scanner – orchestrates all checkers and produces a unified ScanResult.

Usage
-----
    import asyncio
    from clawguard.scanner import Scanner

    result = asyncio.run(
        Scanner(
            target_url="http://localhost:3000",
            config_path="/opt/openclaw",
            api_key="sk-...",
        ).run()
    )
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from clawguard.checkers.base import BaseChecker, CheckContext
from clawguard.checkers.config_checker import ConfigChecker
from clawguard.checkers.dependency_checker import DependencyChecker
from clawguard.checkers.permission_checker import PermissionChecker
from clawguard.models import Finding, ScanResult

logger = logging.getLogger(__name__)

# All built-in checkers, in discovery order
_BUILTIN_CHECKERS: list[type[BaseChecker]] = [
    ConfigChecker,
    DependencyChecker,
    PermissionChecker,
]


class Scanner:
    """
    Async scan orchestrator.

    Parameters
    ----------
    target_url : str | None
        HTTP(S) base URL of the OpenClaw instance, e.g. ``http://localhost:3000``.
    config_path : str | None
        Local path to the OpenClaw installation / config directory or file.
    api_key : str | None
        Admin API key for authenticated remote checks.
    timeout : float
        Per-request timeout passed to all checkers (seconds).
    concurrency : int
        Maximum number of checkers running concurrently.
    extra_checkers : list[BaseChecker]
        Additional checker instances to run alongside the built-ins.
    http_client : httpx.AsyncClient | None
        Custom HTTP client; if None, a default client is created and closed after the scan.
    options : dict | None
        Arbitrary options forwarded to every checker via CheckContext.
    """

    def __init__(
        self,
        target_url: str | None = None,
        config_path: str | None = None,
        api_key: str | None = None,
        timeout: float = 15.0,
        concurrency: int = 8,
        extra_checkers: list[BaseChecker] | None = None,
        http_client: httpx.AsyncClient | None = None,
        options: dict[str, Any] | None = None,
        enabled_checkers: list[str] | None = None,
    ) -> None:
        if not target_url and not config_path:
            raise ValueError("At least one of target_url or config_path must be provided.")

        self.target_url = target_url
        self.config_path = config_path
        self.api_key = api_key
        self.timeout = timeout
        self.concurrency = concurrency
        self.options = options or {}
        self._external_client = http_client
        self._extra_checkers: list[BaseChecker] = extra_checkers or []
        self._enabled_checkers: list[str] | None = enabled_checkers

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> ScanResult:
        """Execute all checkers and return a consolidated ScanResult."""
        target = self.target_url or self.config_path or "unknown"
        start = time.monotonic()

        checkers = self._load_checkers()
        own_client, http_client = await self._build_http_client()

        context = CheckContext(
            target_url=self.target_url,
            config_path=self.config_path,
            api_key=self.api_key,
            http_client=http_client,
            timeout=self.timeout,
            options=self.options,
        )

        all_findings: list[Finding] = []
        errors: list[str] = []
        checkers_run: list[str] = []

        try:
            sem = asyncio.Semaphore(self.concurrency)

            async def _run_checker(checker: BaseChecker) -> tuple[str, list[Finding], str | None]:
                async with sem:
                    try:
                        logger.info("[scanner] running checker: %s", checker.name)
                        findings = await checker.check(context)
                        return checker.name, findings, None
                    except Exception as exc:  # noqa: BLE001
                        logger.exception("[scanner] checker %s raised an unhandled exception", checker.name)
                        return checker.name, [], str(exc)

            tasks = [asyncio.create_task(_run_checker(c)) for c in checkers]
            results = await asyncio.gather(*tasks, return_exceptions=False)

            for checker_name, findings, error in results:
                checkers_run.append(checker_name)
                all_findings.extend(findings)
                if error:
                    errors.append(f"{checker_name}: {error}")
                logger.info(
                    "[scanner] %s finished: %d finding(s)%s",
                    checker_name,
                    len(findings),
                    f", error: {error}" if error else "",
                )
        finally:
            if own_client:
                await http_client.aclose()

        duration = time.monotonic() - start

        result = ScanResult(
            target=str(target),
            findings=all_findings,
            duration_seconds=round(duration, 2),
            checkers_run=checkers_run,
            errors=errors,
        )
        logger.info(
            "[scanner] scan complete in %.1fs — %d finding(s) (%d critical, %d high)",
            duration,
            result.stats.total,
            result.stats.critical,
            result.stats.high,
        )
        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load_checkers(self) -> list[BaseChecker]:
        checkers: list[BaseChecker] = [cls() for cls in _BUILTIN_CHECKERS]
        checkers.extend(self._extra_checkers)
        if self._enabled_checkers is not None:
            allowed = {n.lower() for n in self._enabled_checkers}
            checkers = [c for c in checkers if c.name.lower() in allowed]
        logger.debug("[scanner] loaded %d checker(s): %s", len(checkers), [c.name for c in checkers])
        return checkers

    async def _build_http_client(self) -> tuple[bool, httpx.AsyncClient]:
        """Return (own_client, client). own_client=True means we must close it."""
        if self._external_client is not None:
            return False, self._external_client
        client = httpx.AsyncClient(
            follow_redirects=True,
            headers={
                "User-Agent": "ClawGuard/0.3.0 (security-scanner; +https://github.com/hidearmoon/clawguard)"
            },
            verify=True,  # enforce SSL verification by default
        )
        return True, client
