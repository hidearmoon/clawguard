"""
ConfigChecker – audits the OpenClaw instance for configuration security issues.

Supports both remote (HTTP probing) and local (config file parsing) modes.
"""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

import httpx
import yaml

from clawguard.checkers.base import BaseChecker, CheckContext, CheckerMode
from clawguard.models import Finding, Severity

logger = logging.getLogger(__name__)

# Common weak / default passwords used by One API / New API forks
_WEAK_PASSWORDS = frozenset(
    {
        "123456", "password", "admin", "root", "oneapi", "newapi",
        "openclaw", "changeme", "test", "123456789", "qwerty", "0",
        "",
    }
)

# Minimum acceptable token / JWT secret byte length
_MIN_SECRET_BYTES = 32

# Patterns that indicate debug mode is on
_DEBUG_PATTERNS = [
    re.compile(r'"debug"\s*:\s*true', re.I),
    re.compile(r'GIN_MODE\s*=\s*debug', re.I),
    re.compile(r'DEBUG\s*=\s*true', re.I),
    re.compile(r'debug\s*=\s*1', re.I),
]

# Wildcard CORS origins
_CORS_WILDCARD = re.compile(r'"?\*"?\s*$', re.M)


class ConfigChecker(BaseChecker):
    name = "config"
    description = "Detects misconfigured OpenClaw deployment settings"
    mode = CheckerMode.BOTH

    async def check(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []

        if context.is_remote:
            findings.extend(await self._check_remote(context))

        if context.is_local:
            findings.extend(self._check_local(context))

        return findings

    # ------------------------------------------------------------------
    # Remote checks (HTTP probing)
    # ------------------------------------------------------------------

    async def _check_remote(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        assert context.http_client is not None
        base = context.target_url

        # 1. HTTPS / TLS check
        if base and base.startswith("http://"):
            findings.append(
                Finding(
                    checker_name=self.name,
                    title="Service exposed over plain HTTP (no TLS)",
                    description=(
                        f"The OpenClaw instance at {base} is accessible over unencrypted HTTP. "
                        "API keys and tokens transmitted to the service are visible in transit."
                    ),
                    severity=Severity.HIGH,
                    remediation=(
                        "Configure a TLS terminating reverse proxy (nginx, Caddy, Traefik) in "
                        "front of OpenClaw and redirect all HTTP traffic to HTTPS."
                    ),
                    evidence={"url": base},
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
                    ],
                )
            )

        # 2. Default admin credentials probe
        findings.extend(await self._probe_default_credentials(context))

        # 3. Debug / diagnostic endpoints exposed
        findings.extend(await self._probe_debug_endpoints(context))

        # 4. Rate-limit header probe
        findings.extend(await self._probe_rate_limiting(context))

        # 5. CORS header check
        findings.extend(await self._probe_cors(context))

        return findings

    async def _probe_default_credentials(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        assert context.http_client is not None

        if context.options.get("no_brute"):
            logger.info("[config] credential probe skipped (--no-brute)")
            return findings

        login_url = f"{context.target_url}/api/user/login"
        logger.warning(
            "[config] probing default credentials at %s — use --no-brute to skip this check "
            "if the target has account lockout policies",
            login_url,
        )
        common_pairs = [
            ("root", "123456"),
            ("admin", "admin"),
            ("admin", "123456"),
            ("root", "root"),
        ]
        for username, password in common_pairs:
            try:
                resp = await context.http_client.post(
                    login_url,
                    json={"username": username, "password": password},
                    timeout=context.timeout,
                )
                data: dict[str, Any] = {}
                try:
                    data = resp.json()
                except Exception:
                    pass

                # One API / New API return {"success": true, "data": {"token": ...}} on success
                if resp.status_code == 200 and data.get("success"):
                    findings.append(
                        Finding(
                            checker_name=self.name,
                            title="Default admin credentials are still active",
                            description=(
                                f"Successfully authenticated with default credentials "
                                f"username='{username}' / password='{password}'. "
                                "Any attacker with network access can take over the instance."
                            ),
                            severity=Severity.CRITICAL,
                            remediation=(
                                "Change the default admin password immediately via Settings → "
                                "Personal Settings or the API. Enforce a strong password policy."
                            ),
                            evidence={"username": username, "http_status": resp.status_code},
                            references=[
                                "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
                            ],
                        )
                    )
                    break  # no need to try more pairs
            except httpx.TimeoutException:
                logger.debug("[config] login endpoint timed out, skipping credential probe")
                break
            except httpx.RequestError as exc:
                logger.debug("[config] login probe failed: %s", exc)
                break
        return findings

    async def _probe_debug_endpoints(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        assert context.http_client is not None
        debug_paths = ["/debug/pprof", "/debug/vars", "/_debug", "/metrics"]
        for path in debug_paths:
            url = f"{context.target_url}{path}"
            try:
                resp = await context.http_client.get(url, timeout=context.timeout)
                if resp.status_code == 200:
                    findings.append(
                        Finding(
                            checker_name=self.name,
                            title=f"Debug/diagnostic endpoint publicly accessible: {path}",
                            description=(
                                f"The endpoint {url} returned HTTP 200 without authentication. "
                                "Debug endpoints can leak internal state, goroutine dumps, "
                                "memory profiles, or environment variables."
                            ),
                            severity=Severity.HIGH,
                            remediation=(
                                "Restrict access to debug endpoints via firewall rules or "
                                "reverse-proxy authentication. Set GIN_MODE=release in production."
                            ),
                            evidence={"url": url, "http_status": resp.status_code},
                        )
                    )
            except httpx.RequestError:
                pass
        return findings

    async def _probe_rate_limiting(self, context: CheckContext) -> list[Finding]:
        """Check for presence of rate-limit response headers."""
        findings: list[Finding] = []
        assert context.http_client is not None
        try:
            resp = await context.http_client.get(
                f"{context.target_url}/api/status", timeout=context.timeout
            )
            rl_headers = {
                k: v
                for k, v in resp.headers.items()
                if "ratelimit" in k.lower() or "x-rate" in k.lower() or "retry-after" in k.lower()
            }
            if not rl_headers:
                findings.append(
                    Finding(
                        checker_name=self.name,
                        title="No rate-limiting headers detected",
                        description=(
                            "The OpenClaw API did not return rate-limit response headers "
                            "(RateLimit-Limit, X-RateLimit-*, etc.). Without rate limiting, "
                            "the instance is vulnerable to API key brute-forcing and DoS."
                        ),
                        severity=Severity.MEDIUM,
                        remediation=(
                            "Enable rate limiting in OpenClaw's configuration or configure "
                            "rate limiting on the reverse proxy (nginx limit_req, Traefik "
                            "middleware, Cloudflare WAF)."
                        ),
                        evidence={"checked_url": f"{context.target_url}/api/status"},
                    )
                )
        except httpx.RequestError as exc:
            logger.debug("[config] rate-limit probe failed: %s", exc)
        return findings

    async def _probe_cors(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        assert context.http_client is not None
        try:
            resp = await context.http_client.options(
                f"{context.target_url}/api/status",
                headers={"Origin": "https://evil.example.com"},
                timeout=context.timeout,
            )
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")
            if acao == "*":
                findings.append(
                    Finding(
                        checker_name=self.name,
                        title="CORS policy allows all origins (wildcard)",
                        description=(
                            "The server responds with Access-Control-Allow-Origin: * which allows "
                            "any website to make cross-origin requests. Combined with sensitive "
                            "endpoints, this may lead to cross-site request forgery or data leakage."
                        ),
                        severity=Severity.MEDIUM,
                        remediation=(
                            "Restrict the CORS allowed origins to your frontend domain(s) in "
                            "OpenClaw's configuration. Never combine wildcard with "
                            "Access-Control-Allow-Credentials: true."
                        ),
                        evidence={"access-control-allow-origin": acao},
                    )
                )
            if acao == "*" and acac.lower() == "true":
                findings.append(
                    Finding(
                        checker_name=self.name,
                        title="CORS: wildcard origin combined with Allow-Credentials (invalid but dangerous config)",
                        description=(
                            "Both Access-Control-Allow-Origin: * and "
                            "Access-Control-Allow-Credentials: true are set. Browsers reject "
                            "this combination, but it signals a misconfigured CORS policy that "
                            "may become exploitable if the wildcard is replaced with a reflected origin."
                        ),
                        severity=Severity.HIGH,
                        remediation=(
                            "Remove the wildcard origin and explicitly list trusted domains. "
                            "Only enable Allow-Credentials when strictly necessary."
                        ),
                        evidence={
                            "access-control-allow-origin": acao,
                            "access-control-allow-credentials": acac,
                        },
                    )
                )
        except httpx.RequestError as exc:
            logger.debug("[config] CORS probe failed: %s", exc)
        return findings

    # ------------------------------------------------------------------
    # Local checks (config file inspection)
    # ------------------------------------------------------------------

    def _check_local(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        config_path = Path(context.config_path)  # type: ignore[arg-type]

        # Resolve candidate config files
        candidates: list[Path] = []
        if config_path.is_file():
            candidates = [config_path]
        elif config_path.is_dir():
            for ext in ("*.env", ".env", "config.json", "config.yaml", "config.yml"):
                candidates.extend(config_path.glob(ext))
            candidates.extend(config_path.glob(".env*"))

        for cfg in candidates:
            try:
                findings.extend(self._audit_file(cfg))
            except OSError as exc:
                logger.warning("[config] cannot read %s: %s", cfg, exc)

        return findings

    def _audit_file(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        raw = path.read_text(errors="replace")

        # --- File permission check ---
        stat = path.stat()
        world_readable = bool(stat.st_mode & 0o004)
        if world_readable:
            findings.append(
                Finding(
                    checker_name=self.name,
                    title=f"Config file is world-readable: {path.name}",
                    description=(
                        f"The file {path} has permissions that allow any user on the system "
                        "to read it. Secrets and API keys stored in this file are exposed."
                    ),
                    severity=Severity.HIGH,
                    remediation=(
                        f"Run: chmod 600 {path}  "
                        "Ensure the file is readable only by the service account."
                    ),
                    evidence={"path": str(path), "mode": oct(stat.st_mode)},
                )
            )

        # --- Debug mode ---
        for pat in _DEBUG_PATTERNS:
            if pat.search(raw):
                findings.append(
                    Finding(
                        checker_name=self.name,
                        title="Debug mode is enabled in configuration",
                        description=(
                            "Debug mode exposes detailed stack traces, internal routes, and "
                            "verbose logging that can help an attacker map the application."
                        ),
                        severity=Severity.MEDIUM,
                        remediation=(
                            "Set GIN_MODE=release (or equivalent) and ensure debug flags "
                            "are disabled before deploying to production."
                        ),
                        evidence={"file": str(path)},
                    )
                )
                break

        # --- Weak JWT / session secret ---
        findings.extend(self._check_secret_strength(raw, path))

        # --- Database default credentials ---
        findings.extend(self._check_db_credentials(raw, path))

        # --- Structured config checks ---
        if path.suffix == ".json":
            findings.extend(self._audit_json(raw, path))
        elif path.suffix in (".yaml", ".yml"):
            findings.extend(self._audit_yaml(raw, path))

        return findings

    def _check_secret_strength(self, raw: str, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        patterns = [
            re.compile(r'(?:JWT_SECRET|SESSION_SECRET|TOKEN_KEY|SECRET_KEY)\s*[=:]\s*["\']?(\S+)["\']?', re.I),
            re.compile(r'"(?:jwt_secret|session_secret|token_key|secret)"\s*:\s*"([^"]+)"', re.I),
        ]
        for pat in patterns:
            for match in pat.finditer(raw):
                secret = match.group(1).strip("'\"")
                if secret in _WEAK_PASSWORDS or len(secret.encode()) < _MIN_SECRET_BYTES:
                    findings.append(
                        Finding(
                            checker_name=self.name,
                            title="Weak JWT/session secret detected",
                            description=(
                                f"A secret key in {path.name} is too short or matches a "
                                "known-weak value. Attackers can forge authentication tokens."
                            ),
                            severity=Severity.CRITICAL,
                            remediation=(
                                "Generate a cryptographically random secret of at least 32 bytes: "
                                "python3 -c \"import secrets; print(secrets.token_hex(32))\""
                            ),
                            evidence={"file": str(path), "key_length": len(secret)},
                        )
                    )
        return findings

    def _check_db_credentials(self, raw: str, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        patterns = [
            re.compile(r'(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD)\s*=\s*["\']?(\S*)["\']?', re.I),
            re.compile(r'"(?:db_password|database_password)"\s*:\s*"([^"]*)"', re.I),
        ]
        for pat in patterns:
            for match in pat.finditer(raw):
                pwd = match.group(1).strip("'\"")
                if pwd in _WEAK_PASSWORDS:
                    findings.append(
                        Finding(
                            checker_name=self.name,
                            title="Weak or default database password in config",
                            description=(
                                f"The database password found in {path.name} is empty or "
                                "matches a common default value, making it trivially guessable."
                            ),
                            severity=Severity.CRITICAL,
                            remediation=(
                                "Set a strong, unique database password and update it in the "
                                "OpenClaw configuration. Rotate immediately if exposed."
                            ),
                            evidence={"file": str(path)},
                        )
                    )
        return findings

    def _audit_structured_config(self, cfg: dict[str, Any], path: Path) -> list[Finding]:
        """Shared structural checks for both JSON and YAML config dicts."""
        findings: list[Finding] = []

        # Binding to 0.0.0.0 without explicit firewall is risky in many deployments
        bind_addr = cfg.get("bind_address") or cfg.get("host") or cfg.get("listen")
        if bind_addr in ("0.0.0.0", "::"):
            findings.append(
                Finding(
                    checker_name=self.name,
                    title="Service binds to all network interfaces (0.0.0.0)",
                    description=(
                        "OpenClaw is configured to listen on all interfaces. "
                        "If the host has a public IP without a firewall, the admin UI and API "
                        "are directly internet-facing."
                    ),
                    severity=Severity.MEDIUM,
                    remediation=(
                        "Bind OpenClaw to 127.0.0.1 (or a private interface) and expose it "
                        "through a reverse proxy that handles TLS and access control."
                    ),
                    evidence={"bind_address": bind_addr},
                )
            )

        # CORS wildcard in config
        cors = cfg.get("cors") or cfg.get("allowed_origins") or cfg.get("cors_allow_origins")
        if cors in ("*", ["*"]):
            findings.append(
                Finding(
                    checker_name=self.name,
                    title="CORS wildcard configured in local config file",
                    description=(
                        f"The cors / allowed_origins setting is set to '*' in {path.name}, "
                        "permitting cross-origin requests from any domain."
                    ),
                    severity=Severity.MEDIUM,
                    remediation="Restrict CORS to specific trusted frontend origins.",
                    evidence={"cors": cors},
                )
            )

        # Debug mode flag in structured config
        debug_val = cfg.get("debug") or cfg.get("gin_mode")
        if debug_val is True or str(debug_val).lower() in ("debug", "true", "1"):
            findings.append(
                Finding(
                    checker_name=self.name,
                    title="Debug mode is enabled in structured config",
                    description=(
                        "The debug flag is set to true in the structured config file. "
                        "Debug mode exposes stack traces and verbose logging in production."
                    ),
                    severity=Severity.MEDIUM,
                    remediation=(
                        "Set debug: false (or gin_mode: release) before deploying to production."
                    ),
                    evidence={"file": str(path), "debug": debug_val},
                )
            )

        return findings

    def _audit_yaml(self, raw: str, path: Path) -> list[Finding]:
        """Parse a YAML config file and run structured security checks."""
        findings: list[Finding] = []
        try:
            cfg = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            logger.debug("[config] failed to parse YAML %s: %s", path, exc)
            return findings

        if not isinstance(cfg, dict):
            return findings

        findings.extend(self._audit_structured_config(cfg, path))
        return findings

    def _audit_json(self, raw: str, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            cfg = json.loads(raw)
        except json.JSONDecodeError:
            return findings

        if not isinstance(cfg, dict):
            return findings

        findings.extend(self._audit_structured_config(cfg, path))
        return findings
