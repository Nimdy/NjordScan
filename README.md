# NjordScan - Security Scanner (Beta)

> **Security Scanner for Next.js, React, and Vite Applications**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-167%20Passing-brightgreen.svg)](#test-status)

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

NjordScan scans Next.js, React, and Vite projects for security vulnerabilities using **AST-based taint tracking, pattern matching, dependency graph analysis, and optional LLM-powered explanation**.

### Detection Modules

| Module | What It Scans | Mode |
|--------|--------------|------|
| **Static Analysis** | XSS, SQL injection, command injection, secrets, eval() — regex + **tree-sitter taint tracking** | Static |
| **Supply Chain** | Malicious install scripts, lockfile tampering, registry mismatch, **transitive dependency risk scoring** | Static |
| **Dependencies** | npm audit integration, typosquatting, outdated/vulnerable packages | Static |
| **Configuration** | Exposed secrets, insecure configs, .env leaks | Static |
| **Security Headers** | CSP, HSTS, X-Frame-Options, server info disclosure | Dynamic |
| **Runtime** | DAST testing with payloads against live applications | Dynamic |
| **AI Endpoints** | Exposed AI/LLM API endpoints and keys | Dynamic |
| **Pattern Engine** | 11+ built-in patterns with CWE/OWASP mapping, custom pattern support | Static |

### Taint Tracking (tree-sitter)

NjordScan parses JavaScript/TypeScript into ASTs using tree-sitter and tracks how user-controlled data flows to dangerous sinks:

- **Sources**: `req.body`, `req.query`, `req.params`, `window.location`, `document.cookie`, `prompt()`, `decodeURIComponent()`, and more
- **Sinks**: `innerHTML`, `eval()`, `exec()`, `document.write()`, `readFile()`, `res.redirect()`, `dangerouslySetInnerHTML`, SQL `query()`/`execute()`
- **Propagation**: tracks taint through variable assignments and reassignments
- **Cross-function tracking**: if a function passes its parameter to a sink, calling that function with tainted data is flagged
- **Languages**: JS, JSX, TS, TSX

```
Example: req.body -> variable -> function call -> innerHTML
FLOW: req.body (line 4) -> renderContent() -> innerHTML (line 7) [CWE-79]
```

### LLM-Powered Analysis (opt-in)

Use Claude or OpenAI to explain findings in plain language and filter false positives:

```bash
# Explain findings with Claude
python -m njordscan scan . --explain-with-ai --ai-provider claude

# Or with OpenAI
python -m njordscan scan . --explain-with-ai --ai-provider openai
```

Requires `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` environment variable. The LLM receives each finding with surrounding code context and returns:
- Plain-language explanation of the risk
- Suggested fix with code
- Whether it's likely a false positive

### Supply Chain Security

Defends against modern supply chain attacks:

- **Install Script Analysis** — flags `curl|sh`, reverse shells, credential harvesting, encoded payloads in `postinstall`/`preinstall` scripts
- **Lockfile Integrity** — detects missing integrity hashes, non-standard registries (dependency confusion), git URL dependencies
- **Dependency Graph Analysis** — parses lockfiles into a full graph, scores transitive dependencies for risk (known-malicious packages, missing integrity, non-standard registries, blast radius)
- **Typosquatting Detection** — catches misspelled package names via string similarity
- **Maintainer Profiling** — flags suspicious ownership patterns and account anomalies

### Infrastructure

- **Circuit Breaker** — prevents cascading failures when scan modules crash
- **Rate Limiter** — token bucket + sliding window + adaptive rate limiting for API calls
- **Caching** — intelligent result caching with configurable strategies
- **SBOM Generation** — CycloneDX and SPDX output via `--sbom`
- **SARIF Output** — full SARIF 2.1.0 with rules, CWE tags, security-severity scores, and taint flow code paths for GitHub Code Scanning
- **CI/CD Integration** — `--ci` mode with `--fail-on` severity gating for pipelines

---

## Test Status

**167 tests passing** across 9 test suites:

| Suite | Tests | What's Tested |
|-------|-------|---------------|
| Core Functionality | 27 | Real XSS/eval/secrets detection, scan flow, scoring |
| CLI | 12 | Command output, config init, mode validation |
| Supply Chain | 34 | Install scripts, lockfile integrity, yarn.lock, registry mismatch |
| Core Infrastructure | 24 | Circuit breaker state machine, rate limiter algorithms |
| Pattern Engine | 19 | Built-in patterns, secret detection, false positive avoidance |
| Vulnerability Types | 5 | Type normalization, OWASP/CWE mapping |
| Taint Tracker | 23 | Source-to-sink flows, propagation, cross-function, TS/TSX, false positive avoidance |
| Dependency Graph | 9 | Graph parsing (v1/v2 lockfiles), risk scoring, known-malicious detection |
| LLM Analyzer | 13 | Config, prompt construction, response parsing (no API calls in tests) |

```bash
# Run all tests
python -m pytest tests/test_core_functionality.py tests/test_cli.py \
  tests/test_vulnerability_types.py tests/test_supply_chain.py \
  tests/test_core_infra.py tests/test_pattern_engine.py \
  tests/test_taint_tracker.py tests/test_dep_graph.py \
  tests/test_llm_analyzer.py -v
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

# LLM-powered explanation of findings
python -m njordscan scan . --explain-with-ai --ai-provider claude
```

### Output Formats

```bash
# JSON report
python -m njordscan scan . --format json --output report.json

# HTML report
python -m njordscan scan . --format html --output report.html

# SARIF (for GitHub Code Scanning) — includes taint flow paths
python -m njordscan scan . --format sarif --output results.sarif

# Generate SBOM
python -m njordscan scan . --sbom sbom.json --sbom-format cyclonedx
```

### CI/CD

```bash
# Fail build on high+ severity findings
python -m njordscan scan . --mode quick --ci --fail-on high

# Quality gate with SARIF for GitHub
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
pip install -e .
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
- **Software Integrity** — malicious install scripts, lockfile tampering, registry mismatch, transitive dependency risks
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
- Add taint sources/sinks for more frameworks
- Extend framework support (Vue.js, Angular, Svelte)
- Improve false positive filtering
- Test against real vulnerable applications (OWASP Juice Shop, DVNA)
- Write tests for untested modules

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Honest Assessment

**What NjordScan does:**
- **Tree-sitter AST taint tracking** — parses JS/TS into syntax trees, tracks user input through variable assignments and function calls to dangerous sinks (innerHTML, eval, exec, etc.)
- **Cross-function taint analysis** — detects when tainted data flows through user-defined functions to sinks
- **Pattern matching** — regex-based detection for secrets, XSS, injection patterns
- **Dependency graph analysis** — full lockfile graph with transitive risk scoring
- **LLM integration** — optional Claude/OpenAI for finding explanation and false positive filtering
- **Supply chain security** — install script analysis, lockfile integrity, typosquatting
- **SARIF with code flows** — taint tracking results render as source-to-sink paths in GitHub Code Scanning

**Known limitations:**
- Taint tracking is intra-file only (does not follow data across module imports)
- Cross-function analysis is limited to functions defined in the same file
- No control flow sensitivity (doesn't consider if/else branches)
- Pattern matching can still produce false positives without full semantic context
- Dynamic scanning requires the target application to be running
- LLM features require API keys and incur costs

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
