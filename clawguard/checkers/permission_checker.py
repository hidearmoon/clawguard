"""
PermissionChecker – audits API key hygiene and file-system permissions.

Remote checks (require target_url + api_key):
- API keys not rotated for > N days
- API keys with admin/root privileges assigned to ordinary users
- Enabled but completely unused API keys

Local checks (require config_path):
- Config file / directory world-readable or group-writable
- Private key / certificate files with loose permissions
"""
from __future__ import annotations

import logging
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

from clawguard.checkers.base import BaseChecker, CheckContext, CheckerMode
from clawguard.models import Finding, Severity

logger = logging.getLogger(__name__)

# How many days without rotation before flagging
_ROTATION_WARN_DAYS = 90
_ROTATION_CRITICAL_DAYS = 365

# Roles considered "admin-level" in One-API / New-API / OpenClaw
_ADMIN_ROLES = frozenset({"root", "admin", "10", "100"})

# File patterns that should always be private
_SENSITIVE_FILE_PATTERNS = [
    "*.key", "*.pem", "*.p12", "*.pfx", "*.jks",
    ".env", ".env.*", "id_rsa", "id_ecdsa", "id_ed25519",
]


class PermissionChecker(BaseChecker):
    name = "permission"
    description = "Checks API key hygiene and file-system permission issues"
    mode = CheckerMode.BOTH

    async def check(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []

        if context.is_remote and context.api_key:
            findings.extend(await self._check_remote(context))
        elif context.is_remote and not context.api_key:
            findings.append(
                Finding(
                    checker_name=self.name,
                    title="API key not provided – remote permission checks skipped",
                    description=(
                        "ClawGuard needs an admin API key (--api-key) to query the OpenClaw "
                        "token list. Remote permission checks were skipped."
                    ),
                    severity=Severity.INFO,
                    remediation="Re-run with --api-key <admin_key> to enable remote permission auditing.",
                    evidence={},
                )
            )

        if context.is_local:
            findings.extend(self._check_local(context))

        return findings

    # ------------------------------------------------------------------
    # Remote checks
    # ------------------------------------------------------------------

    async def _check_remote(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        tokens = await self._fetch_tokens(context)
        if tokens is None:
            return []

        now = datetime.now(timezone.utc)

        for token in tokens:
            token_name = token.get("name") or token.get("key", "")[:8] + "..."
            token_id = token.get("id") or token.get("key", "")

            # --- Rotation age check ---
            created_at = self._parse_ts(token.get("created_time") or token.get("createdAt"))
            if created_at:
                age_days = (now - created_at).days
                if age_days >= _ROTATION_CRITICAL_DAYS:
                    findings.append(
                        Finding(
                            checker_name=self.name,
                            title=f"API key not rotated for over {age_days} days: '{token_name}'",
                            description=(
                                f"The API key '{token_name}' (id={token_id}) was created "
                                f"{age_days} days ago and has never been rotated. Long-lived "
                                "credentials increase the blast radius of a breach."
                            ),
                            severity=Severity.HIGH,
                            remediation=(
                                "Rotate all API keys older than 90 days. Use short-lived keys "
                                "where possible and enforce rotation policies in the admin panel."
                            ),
                            evidence={"token_name": token_name, "age_days": age_days},
                        )
                    )
                elif age_days >= _ROTATION_WARN_DAYS:
                    findings.append(
                        Finding(
                            checker_name=self.name,
                            title=f"API key rotation overdue ({age_days} days): '{token_name}'",
                            description=(
                                f"The API key '{token_name}' (id={token_id}) has not been "
                                f"rotated in {age_days} days (recommended: every 90 days)."
                            ),
                            severity=Severity.MEDIUM,
                            remediation="Establish and follow a key rotation policy (≤90 days).",
                            evidence={"token_name": token_name, "age_days": age_days},
                        )
                    )

            # --- Privilege escalation: admin key on a regular user ---
            role = str(token.get("role") or token.get("group") or "")
            user_role = str(token.get("user_role") or "")
            is_admin_key = token.get("unlimited_quota") or token.get("is_admin") or role in _ADMIN_ROLES
            is_regular_user = user_role not in _ADMIN_ROLES and user_role not in ("", "0")

            if is_admin_key and is_regular_user:
                findings.append(
                    Finding(
                        checker_name=self.name,
                        title=f"Over-privileged API key assigned to regular user: '{token_name}'",
                        description=(
                            f"API key '{token_name}' has admin-level or unlimited-quota "
                            "privileges but is associated with a non-admin user account. "
                            "Principle of least privilege is violated."
                        ),
                        severity=Severity.HIGH,
                        remediation=(
                            "Review and restrict the quota and role of this key. Only root/admin "
                            "users should hold keys with unlimited quota or admin permissions."
                        ),
                        evidence={
                            "token_name": token_name,
                            "token_role": role,
                            "user_role": user_role,
                        },
                    )
                )

            # --- Unused but active keys ---
            used_quota = token.get("used_quota", token.get("usedQuota", -1))
            remain_quota = token.get("remain_quota", token.get("remainQuota", -1))
            status = token.get("status", 1)
            last_used = self._parse_ts(token.get("accessed_time") or token.get("lastUsedAt"))

            key_is_active = status in (1, "1", True, "enabled")
            never_used = (used_quota == 0 or used_quota is None) and last_used is None
            stale_used = (
                last_used is not None
                and (now - last_used).days > _ROTATION_CRITICAL_DAYS
            )

            if key_is_active and (never_used or stale_used):
                age_desc = "never used" if never_used else f"unused for {(now - last_used).days} days"  # type: ignore[operator]
                findings.append(
                    Finding(
                        checker_name=self.name,
                        title=f"Active but {age_desc} API key: '{token_name}'",
                        description=(
                            f"API key '{token_name}' (id={token_id}) is enabled but {age_desc}. "
                            "Dormant keys are an unnecessary attack surface — if compromised, "
                            "the breach may go undetected."
                        ),
                        severity=Severity.LOW,
                        remediation=(
                            "Disable or delete API keys that have not been used within 365 days. "
                            "Audit token list regularly via the admin panel."
                        ),
                        evidence={
                            "token_name": token_name,
                            "used_quota": used_quota,
                            "last_used": str(last_used),
                        },
                    )
                )

        return findings

    async def _fetch_tokens(self, context: CheckContext) -> list[dict[str, Any]] | None:
        """Fetch all API tokens from the OpenClaw admin endpoint."""
        assert context.http_client is not None
        endpoints = [
            "/api/token/?p=0&size=500",
            "/api/tokens?page=0&pageSize=500",
        ]
        for path in endpoints:
            url = f"{context.target_url}{path}"
            try:
                resp = await context.http_client.get(
                    url,
                    headers=context.auth_headers(),
                    timeout=context.timeout,
                )
                if resp.status_code == 401:
                    logger.warning("[permission] API key rejected (401) at %s", url)
                    return None
                if resp.status_code == 404:
                    continue
                resp.raise_for_status()
                data = resp.json()
                # One-API format: {"success": true, "data": [...]}
                if isinstance(data, dict):
                    items = data.get("data") or data.get("tokens") or data.get("items") or []
                    return list(items)
                if isinstance(data, list):
                    return data
            except httpx.TimeoutException:
                logger.warning("[permission] token fetch timed out at %s", url)
                return None
            except httpx.RequestError as exc:
                logger.debug("[permission] token fetch error at %s: %s", url, exc)
        logger.info("[permission] could not locate token list endpoint")
        return None

    @staticmethod
    def _parse_ts(value: Any) -> datetime | None:
        if value is None:
            return None
        try:
            if isinstance(value, (int, float)):
                # Unix timestamp (seconds)
                return datetime.fromtimestamp(float(value), tz=timezone.utc)
            if isinstance(value, str):
                # ISO 8601 or RFC 3339
                value = value.rstrip("Z") + "+00:00"
                return datetime.fromisoformat(value)
        except (ValueError, OSError):
            pass
        return None

    # ------------------------------------------------------------------
    # Local file-system checks
    # ------------------------------------------------------------------

    def _check_local(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        base = Path(context.config_path)  # type: ignore[arg-type]
        search_root = base if base.is_dir() else base.parent

        findings.extend(self._check_dir_permissions(search_root))
        findings.extend(self._check_sensitive_files(search_root))
        return findings

    def _check_dir_permissions(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            mode = root.stat().st_mode
            if mode & 0o002:  # world-writable
                findings.append(
                    Finding(
                        checker_name=self.name,
                        title=f"Config directory is world-writable: {root}",
                        description=(
                            f"The directory {root} can be written by any user on the system. "
                            "An attacker with local access could replace config files or inject "
                            "malicious content."
                        ),
                        severity=Severity.HIGH,
                        remediation=(
                            f"Run: chmod 750 {root}  "
                            "Ensure only the service account has write access."
                        ),
                        evidence={"path": str(root), "mode": oct(mode)},
                    )
                )
        except OSError as exc:
            logger.debug("[permission] cannot stat %s: %s", root, exc)
        return findings

    def _check_sensitive_files(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in _SENSITIVE_FILE_PATTERNS:
            for path in root.rglob(pattern):
                if any(p in path.parts for p in ("node_modules", ".git")):
                    continue
                try:
                    mode = path.stat().st_mode
                    world_readable = bool(mode & stat.S_IROTH)
                    group_readable = bool(mode & stat.S_IRGRP)

                    if world_readable:
                        findings.append(
                            Finding(
                                checker_name=self.name,
                                title=f"Sensitive file is world-readable: {path.name}",
                                description=(
                                    f"The file {path} contains potentially sensitive data "
                                    "(private key / certificate / env secrets) and is readable "
                                    "by all users on the system."
                                ),
                                severity=Severity.HIGH,
                                remediation=(
                                    f"Run: chmod 600 {path}  "
                                    "Private keys and secret files must be readable only by the "
                                    "owning service account."
                                ),
                                evidence={"path": str(path), "mode": oct(mode)},
                            )
                        )
                    elif group_readable and path.suffix in (".key", ".pem", ".p12", ".pfx"):
                        findings.append(
                            Finding(
                                checker_name=self.name,
                                title=f"Private key file is group-readable: {path.name}",
                                description=(
                                    f"The private key {path} is readable by all members of its "
                                    "group, which may include unrelated service accounts."
                                ),
                                severity=Severity.MEDIUM,
                                remediation=f"Run: chmod 600 {path}",
                                evidence={"path": str(path), "mode": oct(mode)},
                            )
                        )
                except OSError as exc:
                    logger.debug("[permission] cannot stat %s: %s", path, exc)
        return findings
