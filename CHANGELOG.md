# Changelog

All notable changes to ClawGuard are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [0.3.0] – 2026-03-17

### Added
- **HTMLReporter**: self-contained HTML report with donut chart, risk gauge, severity badges, collapsible findings, and XSS-safe output – no external CDN dependencies.
- **TextReporter**: structured plain-text report suitable for log files and CI artefacts.
- **JSONReporter**: machine-readable JSON for SIEM/ticketing pipeline integration.
- `--html` / `--report` / `--json` output flags on `clawguard scan`.
- `--format json` flag to print JSON to stdout.
- `--evidence` flag to display finding evidence in terminal output.
- HTML report passes XSS escaping test for attacker-controlled titles.

### Changed
- `ScanResult.scanner_version` bumped to `0.3.0`.
- Improved `print_result` Rich rendering with evidence column support.

---

## [0.2.0] – 2026-03-10

### Added
- Full pytest test suite: 62 tests covering all three checkers, scanner orchestration, CLI exit codes, and all report formats.
- `--no-brute` flag to skip default-credential probing in environments with account lockout policies.
- `--checkers` flag to selectively run a subset of built-in checkers.
- `list-checkers` subcommand to enumerate available checkers.
- `Scanner.extra_checkers` parameter for plugin-style custom checker injection.

### Fixed
- **ConfigChecker**: YAML config file parsing now handles both `.yaml` and `.yml` extensions; malformed YAML no longer raises an unhandled exception.
- **DependencyChecker**: CVSS vector string now parsed via `cvss` library for accurate base scores; fallback to `database_specific.severity` label added.
- **PermissionChecker**: `_fetch_tokens` now tries both `/api/token/` and `/api/tokens` endpoints and handles 401 gracefully.

---

## [0.1.0] – 2026-03-01

### Added
- Initial release.
- **ConfigChecker**: detects default credentials, plain HTTP, debug endpoints, weak JWT secrets, default DB passwords, missing rate-limiting, CORS wildcard, 0.0.0.0 binding, and world-readable config files.
- **DependencyChecker**: parses `requirements.txt`, `package.json`, `go.mod` and queries [OSV API](https://osv.dev) in batches; reports CVE IDs and fix versions.
- **PermissionChecker**: audits API key rotation age, over-privileged keys, unused active keys, world-readable sensitive files, and group-readable private key files.
- Async `Scanner` orchestrator with configurable concurrency and per-request timeout.
- Typer CLI with `clawguard scan` and `clawguard list-checkers` commands.
- Rich terminal output with severity colour coding and summary panel.
- Pydantic v2 data models (`Finding`, `ScanResult`, `SummaryStats`).
- `--fail-on` exit code control for CI integration.
