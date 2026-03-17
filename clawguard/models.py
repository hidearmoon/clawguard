"""
ClawGuard data models for scan results and findings.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[self.value]

    @property
    def color(self) -> str:
        return {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
        }[self.value]


class Finding(BaseModel):
    """A single security finding from a checker."""

    checker_name: str
    title: str
    description: str
    severity: Severity
    remediation: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)

    def __lt__(self, other: "Finding") -> bool:
        return self.severity.weight > other.severity.weight  # higher weight = more severe = first


class SummaryStats(BaseModel):
    """Aggregated counts per severity level."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "SummaryStats":
        counts: dict[str, int] = {s.value.lower(): 0 for s in Severity}
        for f in findings:
            counts[f.severity.value.lower()] += 1
        return cls(
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            info=counts["info"],
            total=len(findings),
        )

    @property
    def risk_score(self) -> int:
        """Weighted risk score (0–100 capped)."""
        raw = self.critical * 20 + self.high * 8 + self.medium * 3 + self.low * 1
        return min(raw, 100)


class ScanResult(BaseModel):
    """Complete result of a ClawGuard scan."""

    target: str
    scan_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_seconds: float = 0.0
    findings: list[Finding] = Field(default_factory=list)
    stats: SummaryStats = Field(default_factory=SummaryStats)
    scanner_version: str = "0.1.0"
    checkers_run: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        self.findings = sorted(self.findings)
        self.stats = SummaryStats.from_findings(self.findings)

    def has_critical_or_high(self) -> bool:
        return self.stats.critical > 0 or self.stats.high > 0

    def exit_code(self) -> int:
        """Suitable process exit code: 0=clean, 1=findings, 2=critical."""
        if self.stats.critical > 0:
            return 2
        if self.stats.total > 0:
            return 1
        return 0
