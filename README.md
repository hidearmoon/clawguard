# ClawGuard

> Security audit & vulnerability scanner for [OpenClaw](https://github.com/openclaw) AI API Gateway deployments.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![OpenClaw](https://img.shields.io/badge/OpenClaw-compatible-orange.svg)](https://github.com/openclaw)

ClawGuard automatically detects configuration mistakes, outdated dependencies with known CVEs, and permission anomalies in your OpenClaw deployment — then generates a professional audit report for compliance or internal review.

---

## ✨ Features

| Category | What ClawGuard checks |
|---|---|
| **Config Security** | Default credentials, plain-HTTP, debug mode, weak JWT secrets, CORS wildcards, missing rate-limiting, database default passwords, 0.0.0.0 binding |
| **Dependency CVEs** | Scans `requirements.txt` / `package.json` / `go.mod` against the [OSV database](https://osv.dev) in bulk — shows CVE IDs and fix versions |
| **Permission Audit** | API key rotation age, over-privileged keys, unused-but-active keys, world-readable config files, loose private-key permissions |

**Output formats:** Rich terminal table · JSON · plain-text report
**CI-friendly:** configurable `--fail-on` exit codes for critical/high/medium findings

---

## ⚡ Quick Start (30 seconds)

```bash
# Install
pip install clawguard

# Scan a remote OpenClaw instance
clawguard scan --url http://localhost:3000

# Full audit: remote + local config + admin key
clawguard scan \
  --url https://openclaw.example.com \
  --config /opt/openclaw \
  --api-key sk-your-admin-key \
  --json report.json

# Local-only (no running instance needed)
clawguard scan --config ./openclaw-config/
```

---

## 📦 Installation

### From PyPI

```bash
pip install clawguard
```

### From source

```bash
git clone https://github.com/hidearmoon/clawguard.git
cd clawguard
pip install -e ".[dev]"
```

**Requirements:** Python 3.10+

---

## 🔍 Usage

```
Usage: clawguard scan [OPTIONS]

  Run a ClawGuard security audit against an OpenClaw instance.

Options:
  -u, --url TEXT         OpenClaw instance URL (e.g. http://localhost:3000)
  -c, --config TEXT      Path to OpenClaw config directory or file
  -k, --api-key TEXT     Admin API key for authenticated remote checks
  -t, --timeout FLOAT    Per-request timeout (seconds)  [default: 15.0]
  -j, --json TEXT        Save JSON report to this path
  -r, --report TEXT      Save text report to this path
  -v, --verbose          Enable debug logging
  -e, --evidence         Show evidence in terminal output
  --fail-on TEXT         Exit non-zero on findings at this level or above
                         (critical|high|medium|low|any|none)  [default: critical]
  --help                 Show this message and exit.
```

### Example output

```
╭──────────────────────── ClawGuard Security Scan ─────────────────────────╮
│ Target:   http://localhost:3000                                            │
│ Scanned:  2026-03-17 09:00:00 UTC                                         │
│ Checkers: config, dependency, permission                                  │
│ Duration: 4.2s                                                            │
╰───────────────────────────────────────────────────────────────────────────╯

╭─ Findings (5 total) ─────────────────────────────────────────────────────╮
│ Sev       Checker     Title                                               │
│ CRITICAL  config      Default admin credentials are still active          │
│ HIGH      config      Service exposed over plain HTTP (no TLS)            │
│ HIGH      dependency  Vulnerable dependency: requests@2.25.0 (CVE-...)    │
│ MEDIUM    config      No rate-limiting headers detected                   │
│ LOW       permission  Active but never used API key: 'test-key'           │
╰───────────────────────────────────────────────────────────────────────────╯

╭─ Summary ────────────╮
│ CRITICAL: 1  HIGH: 2  MEDIUM: 1  LOW: 1  INFO: 0   │
│ Risk Score: 41/100                                   │
╰──────────────────────╯
```

---

## 🔌 Python API

```python
import asyncio
from clawguard import Scanner

result = asyncio.run(
    Scanner(
        target_url="http://localhost:3000",
        config_path="/opt/openclaw",
        api_key="sk-admin-key",
    ).run()
)

for finding in result.findings:
    print(f"[{finding.severity}] {finding.title}")
    print(f"  Fix: {finding.remediation}")

print(f"Risk score: {result.stats.risk_score}/100")
print(f"Exit code:  {result.exit_code()}")
```

### Custom checkers

```python
from clawguard.checkers.base import BaseChecker, CheckContext, CheckerMode
from clawguard.models import Finding, Severity

class MyChecker(BaseChecker):
    name = "my_checker"
    description = "Example custom check"
    mode = CheckerMode.REMOTE

    async def check(self, context: CheckContext) -> list[Finding]:
        # your logic here
        return [
            Finding(
                checker_name=self.name,
                title="Example finding",
                description="...",
                severity=Severity.LOW,
                remediation="...",
            )
        ]

result = asyncio.run(
    Scanner(
        target_url="http://localhost:3000",
        extra_checkers=[MyChecker()],
    ).run()
)
```

---

## 🛡️ Checks Reference

### Config Checker (`--url`)

| Check | Severity | Details |
|---|---|---|
| Default admin credentials | CRITICAL | Probes `/api/user/login` with common default combos |
| Plain HTTP (no TLS) | HIGH | URL scheme check |
| Debug endpoints exposed | HIGH | Probes `/debug/pprof`, `/debug/vars`, `/metrics` |
| Weak JWT/session secret | CRITICAL | Parses local config, checks length ≥ 32 bytes |
| Default DB password | CRITICAL | Matches against known-weak password list |
| Missing rate limiting | MEDIUM | Checks response headers for RateLimit-* |
| CORS wildcard | MEDIUM | Checks `Access-Control-Allow-Origin: *` |
| Service binds to 0.0.0.0 | MEDIUM | Parsed from local config JSON |
| Debug mode enabled | MEDIUM | Matches `GIN_MODE=debug`, `DEBUG=true`, etc. |
| World-readable config file | HIGH | `os.stat()` file permission check |

### Dependency Checker (`--config`)

Parses manifest files and queries [OSV API](https://api.osv.dev) in batches:

- `requirements.txt` → PyPI ecosystem
- `package.json` → npm ecosystem
- `go.mod` → Go ecosystem

Reports CVE ID, CVSS-derived severity, installed version, and recommended fix version.

### Permission Checker (`--url --api-key` + `--config`)

| Check | Severity | Threshold |
|---|---|---|
| API key not rotated | HIGH | > 365 days |
| API key rotation overdue | MEDIUM | > 90 days |
| Over-privileged key (admin on regular user) | HIGH | Unlimited quota or admin role |
| Unused active key | LOW | Never used or > 365 days inactive |
| World-readable sensitive file | HIGH | `.env`, `*.pem`, `*.key`, etc. |
| Group-readable private key | MEDIUM | `*.key`, `*.pem`, `*.p12` |
| World-writable config directory | HIGH | `chmod o+w` |

---

## 🔄 CI/CD Integration

```yaml
# GitHub Actions example
- name: OpenClaw security audit
  run: |
    pip install clawguard
    clawguard scan \
      --url ${{ secrets.OPENCLAW_URL }} \
      --api-key ${{ secrets.OPENCLAW_ADMIN_KEY }} \
      --fail-on high \
      --json security-report.json

- name: Upload security report
  uses: actions/upload-artifact@v4
  with:
    name: clawguard-report
    path: security-report.json
```

---

## 🗂 Project Structure

```
clawguard/
├── pyproject.toml
├── README.md
└── clawguard/
    ├── __init__.py
    ├── cli.py                    # Typer CLI entry point
    ├── scanner.py                # Async scan orchestrator
    ├── models.py                 # Pydantic data models
    ├── utils.py                  # Rich rendering + report export
    └── checkers/
        ├── __init__.py
        ├── base.py               # BaseChecker + CheckContext
        ├── config_checker.py     # Configuration security
        ├── dependency_checker.py # CVE scanning via OSV
        └── permission_checker.py # API key & filesystem permissions
```

---

## 🤝 Contributing

Contributions are welcome! Ideas for new checkers:

- **Network exposure**: open ports, firewall rules
- **Docker / container**: running as root, exposed Docker socket
- **Secrets in environment**: scan running process env vars
- **Backup files**: leftover `.bak`, `.orig`, `*.sql` dumps

Please open an issue before submitting a large PR.

---

## 📄 License

MIT © [OpenClaw Labs](https://github.com/hidearmoon)

---

# ClawGuard

> 面向 [OpenClaw](https://github.com/openclaw) AI API 网关的安全审计与漏洞扫描工具。

ClawGuard 自动检测 OpenClaw 部署实例中的配置安全隐患、已知 CVE 依赖漏洞和 API 权限异常，生成专业的安全审计报告，帮助企业用户安全落地 OpenClaw。

## 核心功能

- **配置安全审计**：默认密码、明文 HTTP、调试模式、弱 JWT 密钥、CORS 通配符、缺少速率限制等
- **依赖漏洞扫描**：解析 `requirements.txt` / `package.json` / `go.mod`，批量查询 OSV 数据库，标注 CVE 编号和修复版本
- **权限异常检测**：API Key 轮换周期、越权 Key、僵尸 Key、配置文件权限松散等

## 快速开始

```bash
pip install clawguard

# 扫描远程实例
clawguard scan --url http://localhost:3000

# 完整审计（远端 + 本地配置 + 管理员 Key）
clawguard scan \
  --url https://openclaw.example.com \
  --config /opt/openclaw \
  --api-key sk-your-admin-key \
  --json report.json
```

详细文档见英文部分。
