```
   _____ _                  _____                     _
  / ____| |                / ____|                   | |
 | |    | | __ ___      __| |  __ _   _  __ _ _ __ __| |
 | |    | |/ _` \ \ /\ / /| | |_ | | | |/ _` | '__/ _` |
 | |____| | (_| |\ V  V / | |__| | |_| | (_| | | | (_| |
  \_____|_|\__,_| \_/\_/   \_____|\__,_|\__,_|_|  \__,_|

  Security Audit & Vulnerability Scanner for OpenClaw
```

> 🛡️ **Automated security auditing for [OpenClaw](https://github.com/openclaw) AI API Gateway deployments.**

[![CI](https://github.com/hidearmoon/clawguard/actions/workflows/ci.yml/badge.svg)](https://github.com/hidearmoon/clawguard/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![OpenClaw](https://img.shields.io/badge/OpenClaw-compatible-orange.svg)](https://github.com/openclaw)
[![PyPI](https://img.shields.io/pypi/v/clawguard.svg)](https://pypi.org/project/clawguard/)

ClawGuard automatically detects configuration mistakes, outdated dependencies with known CVEs, and API permission anomalies in your OpenClaw deployment — then generates a professional audit report for compliance or internal review.

---

## ✨ Features

| Category | What ClawGuard checks |
|---|---|
| **Config Security** | Default credentials, plain-HTTP, debug mode, weak JWT secrets, CORS wildcards, missing rate-limiting, database default passwords, 0.0.0.0 binding |
| **Dependency CVEs** | Scans `requirements.txt` / `package.json` / `go.mod` against the [OSV database](https://osv.dev) — shows CVE IDs and fix versions |
| **Permission Audit** | API key rotation age, over-privileged keys, unused-but-active keys, world-readable config files, loose private-key permissions |

**Output formats:** Rich terminal table · JSON · HTML report · plain-text
**CI-friendly:** configurable `--fail-on` exit codes for critical/high/medium findings
**Extensible:** inject custom checkers via the Python API

---

## ⚡ Quick Start

```bash
# Install
pip install clawguard

# Scan a running OpenClaw instance (remote)
clawguard scan --url http://localhost:3000

# Full audit: remote + local config + admin API key
clawguard scan \
  --url https://openclaw.example.com \
  --config /opt/openclaw \
  --api-key sk-your-admin-key \
  --json report.json \
  --html report.html

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

## 🔍 CLI Reference

### `clawguard scan`

```
Usage: clawguard scan [OPTIONS]

  Run a ClawGuard security audit against an OpenClaw instance.

Options:
  -u, --url TEXT          OpenClaw instance URL (e.g. http://localhost:3000)
  -c, --config TEXT       Path to OpenClaw config directory or file
  -k, --api-key TEXT      Admin API key for authenticated remote checks
  -t, --timeout FLOAT     Per-request timeout in seconds  [default: 15.0]
      --checkers TEXT     Comma-separated list of checkers to run
                          (default: all). Available: config, dependency, permission
  -j, --json TEXT         Save JSON report to this path
      --html TEXT         Save HTML report to this path
  -r, --report TEXT       Save plain-text report to this path
  -f, --format TEXT       Stdout format: text (default) | json | none
  -v, --verbose           Enable debug logging
  -e, --evidence          Show raw evidence data in terminal output
      --fail-on TEXT      Exit non-zero when findings at this severity exist
                          (critical|high|medium|low|any|none)  [default: critical]
      --no-brute          Skip default-credential probing (use in environments
                          with account lockout policies)
      --help              Show this message and exit.
```

### `clawguard list-checkers`

```
Usage: clawguard list-checkers

  List all available built-in checkers.
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Clean scan (no findings at or above `--fail-on` threshold) |
| `1`  | Findings at or above the `--fail-on` threshold |
| `2`  | Invalid arguments |

---

## 📸 Example output

```
╭──────────────────────── ClawGuard Security Scan ─────────────────────────╮
│ Target:   http://localhost:3000                                            │
│ Scanned:  2026-03-17 09:00:00 UTC                                         │
│ Checkers: config, dependency, permission                                  │
│ Duration: 4.2s                                                            │
╰───────────────────────────────────────────────────────────────────────────╯

╭─ Findings (5 total) ──────────────────────────────────────────────────────╮
│ Sev       Checker     Title                                                │
│ CRITICAL  config      Default admin credentials are still active          │
│ HIGH      config      Service exposed over plain HTTP (no TLS)            │
│ HIGH      dependency  Vulnerable dependency: requests@2.25.0 (CVE-...)    │
│ MEDIUM    config      No rate-limiting headers detected                   │
│ LOW       permission  Active but never used API key: 'test-key'           │
╰───────────────────────────────────────────────────────────────────────────╯

╭─ Summary ─────────────────────────────────────────╮
│ CRITICAL: 1  HIGH: 2  MEDIUM: 1  LOW: 1  INFO: 0  │
│ Risk Score: 41/100                                  │
╰────────────────────────────────────────────────────╯
```

---

## 🛡️ Checks Reference

### Config Checker

| Check | Severity | Mode | Details |
|---|---|---|---|
| Default admin credentials | CRITICAL | Remote | Probes `/api/user/login` with common default combos |
| Plain HTTP (no TLS) | HIGH | Remote | URL scheme check |
| Debug endpoints exposed | HIGH | Remote | Probes `/debug/pprof`, `/debug/vars`, `/_debug`, `/metrics` |
| Weak JWT/session secret | CRITICAL | Local | Parses config files, checks length ≥ 32 bytes |
| Default DB password | CRITICAL | Local | Matches against known-weak password list |
| Missing rate limiting | MEDIUM | Remote | Checks response headers for `RateLimit-*` |
| CORS wildcard | MEDIUM | Remote | Checks `Access-Control-Allow-Origin: *` |
| Service binds to 0.0.0.0 | MEDIUM | Local | Parsed from JSON/YAML config |
| Debug mode enabled | MEDIUM | Local | Matches `GIN_MODE=debug`, `DEBUG=true`, etc. |
| World-readable config file | HIGH | Local | `os.stat()` file permission check |

### Dependency Checker

Parses manifest files and queries [OSV API](https://api.osv.dev) in batches:

- `requirements.txt` → PyPI ecosystem
- `package.json` → npm ecosystem (production + dev dependencies)
- `go.mod` → Go ecosystem

Reports CVE ID, CVSS-derived severity, installed version, and recommended fix version.

### Permission Checker

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

Extend ClawGuard with your own checks by implementing `BaseChecker`:

```python
from clawguard.checkers.base import BaseChecker, CheckContext, CheckerMode
from clawguard.models import Finding, Severity

class MyChecker(BaseChecker):
    name = "my_checker"
    description = "My custom security check"
    mode = CheckerMode.REMOTE  # REMOTE | LOCAL | BOTH

    async def check(self, context: CheckContext) -> list[Finding]:
        # your logic here
        return [
            Finding(
                checker_name=self.name,
                title="Example finding",
                description="Something is misconfigured.",
                severity=Severity.MEDIUM,
                remediation="Change the setting to X.",
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

## ⚙️ Configuration file (`.clawguard.yaml`)

Place a `.clawguard.yaml` in your project root to set default options:

```yaml
# .clawguard.yaml – ClawGuard project configuration

# Default target URL (overridden by --url flag)
target_url: "http://localhost:3000"

# Default config path (overridden by --config flag)
config_path: "/opt/openclaw"

# Default timeout in seconds
timeout: 15.0

# Checkers to run by default (omit to run all)
# checkers:
#   - config
#   - dependency
#   - permission

# Fail-on threshold for CI (critical | high | medium | low | any | none)
fail_on: "high"

# Skip credential brute-force probe (recommended for prod environments
# with account lockout policies)
no_brute: false
```

> **Note:** CLI flags always take precedence over `.clawguard.yaml` values.

---

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: OpenClaw Security Audit

on:
  schedule:
    - cron: "0 6 * * 1"   # every Monday 06:00 UTC
  push:
    branches: [main]

jobs:
  clawguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install ClawGuard
        run: pip install clawguard

      - name: Run security audit
        run: |
          clawguard scan \
            --url ${{ secrets.OPENCLAW_URL }} \
            --api-key ${{ secrets.OPENCLAW_ADMIN_KEY }} \
            --fail-on high \
            --json security-report.json \
            --html security-report.html

      - name: Upload security report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: clawguard-report
          path: |
            security-report.json
            security-report.html
```

### GitLab CI

```yaml
clawguard:
  image: python:3.11-slim
  stage: security
  script:
    - pip install clawguard
    - clawguard scan
        --url "$OPENCLAW_URL"
        --api-key "$OPENCLAW_ADMIN_KEY"
        --fail-on high
        --json report.json
  artifacts:
    paths:
      - report.json
    when: always
```

---

## 🗂 Project Structure

```
clawguard/
├── pyproject.toml
├── README.md
├── CHANGELOG.md
├── LICENSE
└── clawguard/
    ├── __init__.py
    ├── cli.py                    # Typer CLI entry point
    ├── scanner.py                # Async scan orchestrator
    ├── models.py                 # Pydantic data models
    ├── reporter.py               # Text / JSON / HTML report generators
    ├── utils.py                  # Rich rendering helpers
    └── checkers/
        ├── __init__.py
        ├── base.py               # BaseChecker + CheckContext
        ├── config_checker.py     # Configuration security
        ├── dependency_checker.py # CVE scanning via OSV
        └── permission_checker.py # API key & filesystem permissions
```

---

## 🤝 Contributing

Contributions welcome! To add a new checker:

1. Create `clawguard/checkers/my_checker.py` extending `BaseChecker`
2. Register it in `scanner._BUILTIN_CHECKERS`
3. Add `≥ 3` test cases to `tests/test_my_checker.py`
4. Update the CLI `_BUILTIN_CHECKER_INFO` list and this README

Ideas for future checkers:
- **Network exposure**: open ports, firewall rules
- **Docker / container**: running as root, exposed Docker socket
- **Secrets in environment**: scan running process env vars
- **Backup files**: leftover `.bak`, `.orig`, `*.sql` dumps

Please open an issue before submitting a large PR.

### Development setup

```bash
git clone https://github.com/hidearmoon/clawguard.git
cd clawguard
pip install -e ".[dev]"
pytest tests/ -v
ruff check clawguard/ tests/
```

---

## 📄 License

MIT © [OpenClaw Labs](https://github.com/hidearmoon)

---

---

# ClawGuard（中文文档）

> 🛡️ 面向 [OpenClaw](https://github.com/openclaw) AI API 网关的**自动化安全审计与漏洞扫描工具**。

ClawGuard 自动检测 OpenClaw 部署实例中的配置安全隐患、已知 CVE 依赖漏洞和 API 权限异常，生成专业的安全审计报告，帮助企业用户安全落地 OpenClaw。

---

## 核心功能

| 类别 | 检查项 |
|---|---|
| **配置安全** | 默认密码、明文 HTTP、调试模式、弱 JWT 密钥、CORS 通配符、缺少速率限制、数据库默认密码、0.0.0.0 绑定 |
| **依赖漏洞扫描** | 解析 `requirements.txt` / `package.json` / `go.mod`，批量查询 [OSV 数据库](https://osv.dev)，标注 CVE 编号和修复版本 |
| **权限异常检测** | API Key 轮换周期、越权 Key、僵尸 Key、配置文件世界可读、私钥权限松散 |

---

## 快速开始（30 秒）

```bash
pip install clawguard

# 扫描远程实例
clawguard scan --url http://localhost:3000

# 完整审计（远端 + 本地配置 + 管理员 Key）
clawguard scan \
  --url https://openclaw.example.com \
  --config /opt/openclaw \
  --api-key sk-your-admin-key \
  --json report.json \
  --html report.html

# 仅本地审计（无需运行实例）
clawguard scan --config ./openclaw-config/
```

---

## CLI 参数说明

| 参数 | 说明 | 默认值 |
|---|---|---|
| `--url`, `-u` | OpenClaw 实例 URL | — |
| `--config`, `-c` | OpenClaw 配置目录或文件路径 | — |
| `--api-key`, `-k` | 管理员 API Key（用于远端权限检查） | — |
| `--timeout`, `-t` | 每个请求的超时时间（秒） | `15.0` |
| `--checkers` | 指定运行的检查器（逗号分隔） | 全部 |
| `--json`, `-j` | 保存 JSON 报告到指定路径 | — |
| `--html` | 保存 HTML 报告到指定路径 | — |
| `--report`, `-r` | 保存纯文本报告到指定路径 | — |
| `--format`, `-f` | 终端输出格式：`text`/`json`/`none` | `text` |
| `--verbose`, `-v` | 开启 Debug 日志 | `false` |
| `--evidence`, `-e` | 在终端输出中显示证据数据 | `false` |
| `--fail-on` | CI 失败阈值（`critical`/`high`/`medium`/`low`/`any`/`none`） | `critical` |
| `--no-brute` | 跳过默认密码探测（适用于有账号锁定策略的环境） | `false` |

---

## 检查项详细说明

### 配置安全检查器（ConfigChecker）

| 检查项 | 严重级别 | 说明 |
|---|---|---|
| 默认管理员密码未修改 | CRITICAL | 探测 `/api/user/login` 常见默认组合 |
| 明文 HTTP（无 TLS） | HIGH | URL Scheme 检查 |
| 调试端点对外暴露 | HIGH | 探测 `/debug/pprof`、`/debug/vars`、`/metrics` |
| JWT/会话密钥强度不足 | CRITICAL | 解析本地配置，校验长度 ≥ 32 字节 |
| 数据库默认密码 | CRITICAL | 匹配已知弱密码列表 |
| 缺少速率限制 | MEDIUM | 检查响应头是否包含 `RateLimit-*` |
| CORS 通配符 | MEDIUM | 检查 `Access-Control-Allow-Origin: *` |
| 服务监听 0.0.0.0 | MEDIUM | 从本地配置文件解析 |
| 调试模式已开启 | MEDIUM | 匹配 `GIN_MODE=debug`、`DEBUG=true` 等 |
| 配置文件世界可读 | HIGH | `os.stat()` 文件权限检查 |

### 依赖漏洞检查器（DependencyChecker）

解析 `requirements.txt`、`package.json`、`go.mod`，批量查询 [OSV API](https://api.osv.dev)，输出 CVE 编号、CVSS 评分、已安装版本、推荐修复版本。

### 权限检查器（PermissionChecker）

| 检查项 | 严重级别 | 阈值 |
|---|---|---|
| API Key 超过 365 天未轮换 | HIGH | > 365 天 |
| API Key 轮换警告 | MEDIUM | > 90 天 |
| 越权 Key（普通用户持有管理员 Key） | HIGH | 无限额度或管理员角色 |
| 活跃但从未使用的 Key | LOW | 从未使用或 > 365 天未使用 |
| 敏感文件世界可读 | HIGH | `.env`、`*.pem`、`*.key` 等 |
| 私钥文件组可读 | MEDIUM | `*.key`、`*.pem`、`*.p12` |
| 配置目录世界可写 | HIGH | `chmod o+w` |

---

## CI/CD 集成示例

```yaml
# GitHub Actions
- name: OpenClaw 安全审计
  run: |
    pip install clawguard
    clawguard scan \
      --url ${{ secrets.OPENCLAW_URL }} \
      --api-key ${{ secrets.OPENCLAW_ADMIN_KEY }} \
      --fail-on high \
      --json security-report.json

- name: 上传安全报告
  uses: actions/upload-artifact@v4
  with:
    name: clawguard-report
    path: security-report.json
```

---

## 配置文件（`.clawguard.yaml`）

```yaml
target_url: "http://localhost:3000"
config_path: "/opt/openclaw"
timeout: 15.0
fail_on: "high"
no_brute: false
```

---

## 贡献指南

欢迎提交 Issue 和 PR！添加自定义检查器只需继承 `BaseChecker`：

```python
from clawguard.checkers.base import BaseChecker, CheckContext, CheckerMode
from clawguard.models import Finding, Severity

class MyChecker(BaseChecker):
    name = "my_checker"
    description = "自定义安全检查"
    mode = CheckerMode.REMOTE

    async def check(self, context: CheckContext) -> list[Finding]:
        ...
```

---

## 许可证

MIT © [OpenClaw Labs](https://github.com/hidearmoon)
