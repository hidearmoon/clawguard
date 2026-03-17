"""
ClawGuard – OpenClaw Security Audit & Vulnerability Scanner.
"""
from clawguard.models import Finding, ScanResult, Severity
from clawguard.scanner import Scanner

__version__ = "0.1.0"
__all__ = ["Scanner", "ScanResult", "Finding", "Severity"]
