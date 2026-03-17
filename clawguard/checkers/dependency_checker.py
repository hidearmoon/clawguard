"""
DependencyChecker – scans OpenClaw's dependency manifests for known CVEs.

Strategy:
1. Parse dependency manifests found under config_path:
   - requirements.txt  (Python)
   - package.json / package-lock.json  (Node / Go-based forks bundling JS)
   - go.sum / go.mod  (Go)
2. Query the OSV API (https://api.osv.dev/v1/query) for each package.
3. Report findings with CVE IDs and fix versions where available.

Rate-limiting: OSV batch endpoint is used (POST /v1/querybatch) to minimise
round-trips. Falls back to per-package queries on error.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

import httpx

from clawguard.checkers.base import BaseChecker, CheckContext, CheckerMode
from clawguard.models import Finding, Severity

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_SINGLE_URL = "https://api.osv.dev/v1/query"

# Maximum packages per OSV batch call
_BATCH_SIZE = 50


# ---------------------------------------------------------------------------
# Manifest parsers
# ---------------------------------------------------------------------------

def _parse_requirements_txt(text: str) -> list[tuple[str, str]]:
    """Return list of (name, version) from requirements.txt content."""
    results: list[tuple[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+")):
            continue
        # Handle: pkg==1.2.3 / pkg>=1.0,<2.0 / pkg~=1.0
        m = re.match(r'^([A-Za-z0-9_.\-]+)\s*==\s*([^\s,;]+)', line)
        if m:
            results.append((m.group(1), m.group(2)))
        else:
            # Version-less pin – still report the package name without version
            m2 = re.match(r'^([A-Za-z0-9_.\-]+)', line)
            if m2:
                results.append((m2.group(1), ""))
    return results


def _parse_package_json(text: str) -> list[tuple[str, str]]:
    """Return (name, version) from package.json dependencies."""
    results: list[tuple[str, str]] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return results
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, ver in data.get(section, {}).items():
            # Strip semver range operators
            clean = re.sub(r'^[~^>=<v\s]+', '', str(ver))
            results.append((name, clean.split(" ")[0]))
    return results


def _parse_go_mod(text: str) -> list[tuple[str, str]]:
    """Return (module_path, version) from go.mod.

    Handles both single-line and multi-line require blocks:
        require github.com/foo v1.0.0
        require (
            github.com/bar v2.0.0
            github.com/baz v3.1.0 // indirect
        )
    """
    results: list[tuple[str, str]] = []
    in_require_block = False

    for raw_line in text.splitlines():
        line = raw_line.strip()
        # Strip inline comments
        line = re.sub(r'\s*//.*$', '', line).strip()

        if not line:
            continue

        # Enter multi-line require block
        if re.match(r'^require\s*\($', line):
            in_require_block = True
            continue

        # Exit multi-line require block
        if in_require_block and line == ')':
            in_require_block = False
            continue

        # Single-line: require github.com/foo v1.0.0
        single = re.match(r'^require\s+([\w./\-]+)\s+v([\d.]+[^\s]*)', line)
        if single:
            results.append((single.group(1), single.group(2)))
            continue

        # Inside a block or bare dependency line: github.com/foo v1.0.0
        if in_require_block or True:
            m = re.match(r'^([\w./\-]+)\s+v([\d.]+[^\s]*)', line)
            if m:
                results.append((m.group(1), m.group(2)))

    return results


# ---------------------------------------------------------------------------
# OSV querying
# ---------------------------------------------------------------------------

def _make_osv_query(name: str, version: str, ecosystem: str) -> dict[str, Any]:
    q: dict[str, Any] = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        q["version"] = version
    return q


async def _osv_batch_query(
    client: httpx.AsyncClient,
    queries: list[dict[str, Any]],
    timeout: float,
) -> list[dict[str, Any]]:
    """Call OSV batch endpoint. Returns list of result objects (one per query)."""
    try:
        resp = await client.post(
            OSV_BATCH_URL,
            json={"queries": queries},
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp.json().get("results", [])
    except httpx.HTTPStatusError as exc:
        logger.warning("[dependency] OSV batch request failed: %s", exc)
    except httpx.RequestError as exc:
        logger.warning("[dependency] OSV batch request error: %s", exc)
    return []


def _cvss_base_score(vector: str) -> float | None:
    """
    Calculate the CVSS base score from a vector string using the cvss library.

    Supports CVSS v2 and v3/v3.1 vector strings (e.g. "CVSS:3.1/AV:N/AC:L/...").
    Returns None if the vector cannot be parsed.
    """
    try:
        from cvss import CVSS2, CVSS3  # type: ignore[import-untyped]

        if "CVSS:3" in vector or vector.startswith("AV:") and "CVSS:" not in vector:
            c = CVSS3(vector)
        else:
            c = CVSS2(vector)
        return float(c.base_score)
    except Exception:
        return None


def _severity_from_osv(vuln: dict[str, Any]) -> Severity:
    """Map OSV severity / CVSS to ClawGuard Severity.

    Priority order:
    1. Parse CVSS vector string via cvss library (accurate base score).
    2. Numeric score in database_specific.cvss_score / database_specific.cvss.
    3. String label in database_specific.severity (CRITICAL/HIGH/MODERATE/LOW).
    """
    score = 0.0

    # 1. Parse CVSS vector strings via cvss library
    for sev in vuln.get("severity", []):
        val = str(sev.get("score", ""))
        if val:
            parsed = _cvss_base_score(val)
            if parsed is not None:
                score = max(score, parsed)

    # 2. Numeric score from database_specific fields
    if score == 0.0:
        db = vuln.get("database_specific", {})
        for key in ("cvss_score", "cvss", "NVD_CVSS_V3_Score", "NVD_CVSS_V2_Score"):
            raw = db.get(key)
            if raw is not None:
                try:
                    score = float(raw)
                    break
                except (ValueError, TypeError):
                    pass

    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW

    # 3. Fallback: string severity label
    sev_label = vuln.get("database_specific", {}).get("severity", "").upper()
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MODERATE": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    return mapping.get(sev_label, Severity.MEDIUM)


def _extract_fixed_version(vuln: dict[str, Any]) -> str | None:
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def _extract_cve_ids(vuln: dict[str, Any]) -> list[str]:
    cves: list[str] = []
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            cves.append(alias)
    if vuln.get("id", "").startswith("CVE-"):
        cves.append(vuln["id"])
    return cves


# ---------------------------------------------------------------------------
# Main checker
# ---------------------------------------------------------------------------

class DependencyChecker(BaseChecker):
    name = "dependency"
    description = "Scans dependency manifests for known CVEs via OSV API"
    mode = CheckerMode.LOCAL

    async def check(self, context: CheckContext) -> list[Finding]:
        if self.should_skip(context):
            return []

        findings: list[Finding] = []
        config_path = Path(context.config_path)  # type: ignore[arg-type]

        # Discover manifest files
        manifests = self._discover_manifests(config_path)
        if not manifests:
            logger.info("[dependency] no dependency manifests found under %s", config_path)
            return []

        # Collect all packages
        all_packages: list[tuple[str, str, str]] = []  # (name, version, ecosystem)
        for manifest_path, ecosystem in manifests:
            try:
                text = manifest_path.read_text(errors="replace")
                pkgs = self._parse(manifest_path.name, text)
                all_packages.extend((n, v, ecosystem) for n, v in pkgs)
                logger.debug(
                    "[dependency] parsed %d packages from %s", len(pkgs), manifest_path
                )
            except OSError as exc:
                logger.warning("[dependency] cannot read %s: %s", manifest_path, exc)

        if not all_packages:
            return []

        # Query OSV in batches
        findings.extend(await self._query_osv(context, all_packages))
        return findings

    def _discover_manifests(self, base: Path) -> list[tuple[Path, str]]:
        """Return list of (path, ecosystem) for known manifest files."""
        found: list[tuple[Path, str]] = []
        search_root = base if base.is_dir() else base.parent

        manifest_map = {
            "requirements.txt": "PyPI",
            "requirements-dev.txt": "PyPI",
            "requirements_dev.txt": "PyPI",
            "package.json": "npm",
            "go.mod": "Go",
        }
        for filename, ecosystem in manifest_map.items():
            for candidate in search_root.rglob(filename):
                # Skip node_modules and .git
                if any(p in candidate.parts for p in ("node_modules", ".git", ".venv", "venv")):
                    continue
                found.append((candidate, ecosystem))
        return found

    def _parse(self, filename: str, text: str) -> list[tuple[str, str]]:
        if filename in ("requirements.txt", "requirements-dev.txt", "requirements_dev.txt"):
            return _parse_requirements_txt(text)
        if filename == "package.json":
            return _parse_package_json(text)
        if filename == "go.mod":
            return _parse_go_mod(text)
        return []

    async def _query_osv(
        self,
        context: CheckContext,
        packages: list[tuple[str, str, str]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Use a fresh HTTP client if the shared one is closed or not available
        own_client = False
        client = context.http_client
        if client is None:
            client = httpx.AsyncClient(headers={"User-Agent": "clawguard/0.1.0"})
            own_client = True

        try:
            # Build OSV query objects
            queries = [
                _make_osv_query(name, version, ecosystem)
                for name, version, ecosystem in packages
            ]

            # Send in batches
            all_results: list[dict[str, Any]] = []
            for i in range(0, len(queries), _BATCH_SIZE):
                batch = queries[i : i + _BATCH_SIZE]
                batch_results = await _osv_batch_query(client, batch, context.timeout)
                all_results.extend(batch_results)
                # Pad with empty if batch returned fewer results
                while len(all_results) < i + len(batch):
                    all_results.append({})

            for idx, result in enumerate(all_results):
                if idx >= len(packages):
                    break
                name, version, _ = packages[idx]
                vulns = result.get("vulns", [])
                for vuln in vulns:
                    severity = _severity_from_osv(vuln)
                    fixed_ver = _extract_fixed_version(vuln)
                    cve_ids = _extract_cve_ids(vuln)
                    vuln_id = vuln.get("id", "UNKNOWN")
                    summary = vuln.get("summary") or vuln.get("details", "")[:200]

                    remediation = (
                        f"Upgrade {name} to version {fixed_ver} or later."
                        if fixed_ver
                        else f"Check the OSV advisory for {vuln_id} for mitigation steps."
                    )

                    findings.append(
                        Finding(
                            checker_name=self.name,
                            title=f"Vulnerable dependency: {name}@{version} ({vuln_id})",
                            description=(
                                f"Package '{name}' version '{version}' has a known vulnerability: "
                                f"{summary}"
                            ),
                            severity=severity,
                            remediation=remediation,
                            evidence={
                                "package": name,
                                "installed_version": version,
                                "fixed_version": fixed_ver,
                                "osv_id": vuln_id,
                            },
                            cve_ids=cve_ids,
                            references=[f"https://osv.dev/vulnerability/{vuln_id}"],
                        )
                    )
        finally:
            if own_client:
                await client.aclose()

        return findings
