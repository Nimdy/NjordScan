# NjordScan Documentation

Documentation for NjordScan — a security scanner for Next.js, React, and Vite applications.

## Getting Started
- [**Installation Guide**](getting-started/installation.md) - Complete installation instructions
- [**Quick Start**](getting-started/quick-start.md) - Get up and running in minutes
- [**Kali Linux Guide**](getting-started/KALI_LINUX_GUIDE.md) - Installation for Kali Linux
- [**Wheel Installation Guide**](getting-started/WHEEL_INSTALLATION_GUIDE.md) - Resolve wheel issues

## User Guide
- [**CLI Reference**](user-guide/cli-reference.md) - Command-line interface documentation
- [**Vulnerability Types**](security/vulnerability-types.md) - Detection types with CWE/OWASP mapping

## Development
- [**Architecture**](development/architecture.md) - System architecture and components
- [**API Documentation**](development/api.md) - Programmatic API reference

## Advanced
- [**Troubleshooting**](advanced/troubleshooting.md) - Common issues and solutions
- [**LXML Troubleshooting**](advanced/LXML_TROUBLESHOOTING.md) - Resolve lxml issues
- [**Framework Pentesting**](security/framework-pentesting.md) - Framework-specific security testing

## Documentation Structure

```
docs/
├── README.md                         # This file
├── getting-started/
│   ├── installation.md
│   ├── quick-start.md
│   ├── KALI_LINUX_GUIDE.md
│   └── WHEEL_INSTALLATION_GUIDE.md
├── user-guide/
│   └── cli-reference.md
├── development/
│   ├── api.md
│   └── architecture.md
├── security/
│   ├── vulnerability-types.md
│   └── framework-pentesting.md
├── advanced/
│   ├── troubleshooting.md
│   └── LXML_TROUBLESHOOTING.md
└── docker/
    └── README.md
```

## What NjordScan Does

NjordScan scans web applications for security vulnerabilities using pattern matching, heuristic analysis, and threat intelligence:

- **Static Analysis** — regex-based code scanning for XSS, injection, secrets, and misconfigurations
- **Supply Chain Security** — install script analysis, lockfile integrity, typosquatting detection
- **Dynamic Testing** — HTTP header analysis and runtime testing against live applications
- **Dependency Auditing** — npm audit integration, known-malicious package detection
- **Framework-Specific** — specialized patterns for Next.js, React, and Vite
- **Pattern Engine** — extensible pattern system with CWE/OWASP mapping and custom rule support

## Quick Start

```bash
python3 -m venv venv && source venv/bin/activate
pip install -e .
python -m njordscan update
python -m njordscan legal --accept
python -m njordscan scan .
```

## Support

- **Issues**: [GitHub Issues](https://github.com/nimdy/njordscan/issues)
- **Discussions**: [GitHub Discussions](https://github.com/nimdy/njordscan/discussions)
