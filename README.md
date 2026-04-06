# NjordScan - Security Scanner (Beta)

> **Security Scanner for Next.js, React, and Vite Applications**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-121%20Passing-brightgreen.svg)](#test-status)

## Quick Start

```bash
# Create virtual environment (REQUIRED)
python3 -m venv venv && source venv/bin/activate  # Linux/Mac
# OR: venv\Scripts\activate  # Windows

# Install and run
pip install -e .
python -m njordscan update        # Download latest CVE/exploit data
python -m njordscan legal --accept # Accept terms (one-time)
python -m njordscan scan .        # Start scanning!
```

**Guides:**
- [BEGINNER_GUIDE.md](BEGINNER_GUIDE.md) - Step-by-step for beginners
- [QUICK_INSTALL.md](QUICK_INSTALL.md) - Copy/paste installation
- [Full Documentation](docs/README.md) - Comprehensive reference

---

## What It Does

NjordScan scans Next.js, React, and Vite projects for security vulnerabilities using **pattern matching, heuristic analysis, and threat intelligence** — not machine learning.

### Detection Modules

| Module | What It Scans | Mode |
|--------|--------------|------|
| **Static Analysis** | XSS, SQL injection, command injection, secrets, eval() usage | Static |
| **Supply Chain** | Malicious install scripts, lockfile tampering, registry mismatch, git deps | Static |
| **Dependencies** | npm audit integration, typosquatting, outdated/vulnerable packages | Static |
| **Configuration** | Exposed secrets, insecure configs, .env leaks | Static |
| **Security Headers** | CSP, HSTS, X-Frame-Options, server info disclosure | Dynamic |
| **Runtime** | DAST testing with payloads against live applications | Dynamic |
| **AI Endpoints** | Exposed AI/LLM API endpoints and keys | Dynamic |
| **Pattern Engine** | 11+ built-in patterns with CWE/OWASP mapping, custom pattern support | Static |

### Supply Chain Security

Defends against modern supply chain attacks:

- **Install Script Analysis** — flags `curl|sh`, reverse shells, credential harvesting, encoded payloads in `postinstall`/`preinstall` scripts
- **Lockfile Integrity** — detects missing integrity hashes, non-standard registries (dependency confusion), git URL dependencies
- **Typosquatting Detection** — catches misspelled package names via string similarity
- **Maintainer Profiling** — flags suspicious ownership patterns and account anomalies

### Infrastructure

- **Circuit Breaker** — prevents cascading failures when scan modules crash
- **Rate Limiter** — token bucket + sliding window + adaptive rate limiting for API calls
- **Caching** — intelligent result caching with configurable strategies
- **SBOM Generation** — CycloneDX and SPDX output via `--sbom`
- **CI/CD Integration** — `--ci` mode with `--fail-on` severity gating for pipelines

---

## Test Status

**121 tests passing** across 6 test suites:

| Suite | Tests | What's Tested |
|-------|-------|---------------|
| Core Functionality | 27 | Real XSS/eval/secrets detection, scan flow, scoring |
| CLI | 12 | Command output, config init, mode validation |
| Supply Chain | 34 | Install scripts, lockfile integrity, yarn.lock, registry mismatch |
| Core Infrastructure | 24 | Circuit breaker state machine, rate limiter algorithms |
| Pattern Engine | 19 | Built-in patterns, secret detection, false positive avoidance |
| Vulnerability Types | 5 | Type normalization, OWASP/CWE mapping |

```bash
# Run all tests
python -m pytest tests/test_core_functionality.py tests/test_cli.py \
  tests/test_vulnerability_types.py tests/test_supply_chain.py \
  tests/test_core_infra.py tests/test_pattern_engine.py -v
```

---

## Usage

**Always activate your virtual environment first:**
```bash
source venv/bin/activate  # Linux/Mac
# OR: venv\Scripts\activate  # Windows
```

### Scanning

```bash
# Scan local project
python -m njordscan scan .

# Scan a website
python -m njordscan scan https://example.com

# Scan with specific framework
python -m njordscan scan . --framework nextjs

# Deep scan with threat intelligence
python -m njordscan scan . --mode deep --threat-intel

# Framework-specific pentesting (requires permission!)
python -m njordscan scan http://localhost:3000 --pentest
```

### Output Formats

```bash
# JSON report
python -m njordscan scan . --format json --output report.json

# HTML report
python -m njordscan scan . --format html --output report.html

# SARIF (for GitHub Code Scanning)
python -m njordscan scan . --format sarif --output results.sarif

# Generate SBOM
python -m njordscan scan . --sbom sbom.json --sbom-format cyclonedx
```

### CI/CD

```bash
# Fail build on high+ severity findings
python -m njordscan scan . --mode quick --ci --fail-on high

# Quality gate
python -m njordscan scan . --ci --fail-on critical --format sarif --output results.sarif
```

### Docker

```bash
docker run -v $(pwd):/workspace njordscan scan /workspace
docker run -v $(pwd):/workspace njordscan scan /workspace --mode deep --format html --output /workspace/report.html
```

---

## Scan Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `quick` | Fast static analysis | CI/CD pipelines |
| `standard` | Balanced checks | Regular audits |
| `deep` | Full analysis with threat intel | Thorough assessment |
| `enterprise` | Everything enabled | Complete security review |

---

## Installation

### Standard
```bash
python3 -m venv venv && source venv/bin/activate
pip install njordscan
```

### Development
```bash
git clone https://github.com/nimdy/njordscan.git
cd njordscan
python3 -m venv venv && source venv/bin/activate
pip install -e .
python -m njordscan update
python -m njordscan legal --accept
```

### Troubleshooting
- [Kali Linux Setup](docs/getting-started/KALI_LINUX_GUIDE.md)
- [LXML Issues](docs/advanced/LXML_TROUBLESHOOTING.md)

---

## 35+ Vulnerability Types

Aligned with **OWASP Top 10 2021**:

- **Injection** — XSS (reflected/stored/DOM), SQL injection, command injection, SSRF, path traversal
- **Cryptographic Failures** — hardcoded secrets, weak encryption, exposed API keys
- **Access Control** — IDOR, privilege escalation, CSRF, unauthorized access
- **Security Misconfiguration** — missing headers, debug mode, insecure CORS
- **Vulnerable Components** — outdated deps, typosquatting, malicious packages
- **Software Integrity** — malicious install scripts, lockfile tampering, registry mismatch
- **AI/LLM Security** — prompt injection, exposed AI endpoints, LLM-specific vulns (OWASP LLM Top 10 2025)

---

## Contributing

```bash
git clone https://github.com/nimdy/njordscan.git && cd njordscan
python3 -m venv venv && source venv/bin/activate
pip install -e .
python -m pytest tests/ -v  # Run tests before submitting
```

**Where to help:**
- Add detection patterns for emerging threats
- Extend framework support (Vue.js, Angular, Svelte)
- Improve false positive filtering
- Write tests for untested modules

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Honest Assessment

NjordScan uses **regex pattern matching, string similarity, entropy scoring, and heuristic rules** for detection. It does **not** use machine learning, LLMs, or neural networks despite the `ai/` package name (kept for backward compatibility).

**What it does well:**
- Supply chain security (install scripts, lockfile integrity, typosquatting)
- Security header analysis
- Static pattern detection (XSS, secrets, injection)
- Framework-specific scanning (Next.js, React, Vite)
- CI/CD integration with quality gates

**Known limitations:**
- No data flow / taint tracking (regex-only, no inter-procedural analysis)
- Pattern matching can produce false positives without semantic context
- Dynamic scanning requires the target application to be running
- Detection depth is comparable to linting, not to tools like Semgrep or Snyk

---

## License

MIT License — see [LICENSE](LICENSE).

## Support

- **Documentation**: [docs/README.md](docs/README.md)
- **Issues**: [GitHub Issues](https://github.com/nimdy/njordscan/issues)

---

## Legal Disclaimer

**ONLY USE ON SYSTEMS YOU OWN OR HAVE EXPLICIT PERMISSION TO TEST.**

NjordScan is provided "AS IS" without warranty. You use it at your own risk. Scan results are informational, not professional security advice. Unauthorized scanning is illegal. See `python -m njordscan legal --show` for full terms.

---

**Made with care for the security community**
