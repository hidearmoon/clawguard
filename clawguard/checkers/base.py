"""
BaseChecker – abstract base class that every ClawGuard checker must implement.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx

from clawguard.models import Finding

logger = logging.getLogger(__name__)


class CheckerMode(str, Enum):
    """Describes what kind of target a checker can operate on."""

    REMOTE = "remote"   # needs a reachable HTTP(S) endpoint
    LOCAL = "local"     # needs access to local config / file-system
    BOTH = "both"       # works in either mode


class CheckContext:
    """
    Shared context object passed to every checker.

    Attributes
    ----------
    target_url : str | None
        Base URL of the OpenClaw instance (e.g. ``http://localhost:3000``).
    config_path : str | None
        Local path to the OpenClaw config file or directory.
    api_key : str | None
        Admin API key used for authenticated remote checks.
    http_client : httpx.AsyncClient | None
        Shared async HTTP client; created by the Scanner, closed after scan.
    timeout : float
        Per-request / per-check timeout in seconds.
    options : dict
        Arbitrary extra options that individual checkers may consume.
    """

    def __init__(
        self,
        target_url: str | None = None,
        config_path: str | None = None,
        api_key: str | None = None,
        http_client: "httpx.AsyncClient | None" = None,
        timeout: float = 10.0,
        options: dict | None = None,
    ) -> None:
        self.target_url = target_url.rstrip("/") if target_url else None
        self.config_path = config_path
        self.api_key = api_key
        self.http_client = http_client
        self.timeout = timeout
        self.options: dict = options or {}

    @property
    def is_remote(self) -> bool:
        return self.target_url is not None

    @property
    def is_local(self) -> bool:
        return self.config_path is not None

    def auth_headers(self) -> dict[str, str]:
        if self.api_key:
            return {"Authorization": f"Bearer {self.api_key}"}
        return {}


class BaseChecker(ABC):
    """
    Abstract base class for all ClawGuard security checkers.

    Sub-classes must:
    1. Set ``name`` to a unique short identifier (e.g. ``"config"``)
    2. Set ``description`` to a human-readable summary
    3. Set ``mode`` to indicate whether local / remote / both context is needed
    4. Implement ``async def check(context) -> list[Finding]``
    """

    #: Unique machine-readable name used in findings and logging.
    name: str = "base"
    #: One-line description shown in verbose output.
    description: str = "Base checker (not for direct use)"
    #: What context type this checker requires.
    mode: CheckerMode = CheckerMode.BOTH

    @abstractmethod
    async def check(self, context: CheckContext) -> list[Finding]:
        """
        Execute all checks and return a (possibly empty) list of findings.

        Implementations MUST:
        - Catch all exceptions internally and either log them or append an
          INFO-level Finding rather than propagating to the scanner.
        - Respect ``context.timeout`` for any network I/O.
        - Never mutate ``context``.
        """

    # ------------------------------------------------------------------
    # Helpers available to sub-classes
    # ------------------------------------------------------------------

    def _skip_reason(self, context: CheckContext) -> str | None:
        """Return a human-readable reason to skip, or None if OK to proceed."""
        if self.mode == CheckerMode.REMOTE and not context.is_remote:
            return "no target_url provided; skipping remote check"
        if self.mode == CheckerMode.LOCAL and not context.is_local:
            return "no config_path provided; skipping local check"
        return None

    def should_skip(self, context: CheckContext) -> bool:
        reason = self._skip_reason(context)
        if reason:
            logger.debug("[%s] %s", self.name, reason)
            return True
        return False
