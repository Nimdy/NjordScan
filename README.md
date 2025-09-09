# 🛡️ NjordScan - Ultimate Security Scanner

> **The Ultimate Security Scanner for Next.js, React, and Vite Applications**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CLI](https://img.shields.io/badge/CLI-Powerful-orange.svg)](#command-line-interface)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)](#)
[![Tests](https://img.shields.io/badge/Tests-90%25%20Passing-brightgreen.svg)](#)

## 🚀 Quick Start

```bash
# Install NjordScan
pip install njordscan

# Basic scan
njordscan scan .

# Advanced scan with AI
njordscan scan . --mode deep --ai-enhanced --behavioral-analysis

# Penetration testing
njordscan scan http://localhost:3000 --mode enterprise --pentest
```

## ✨ Key Features

- **🔍 Comprehensive Security Scanning** - Static analysis, dynamic testing, and penetration testing
- **🤖 AI-Powered Intelligence** - Machine learning-powered vulnerability detection and behavioral analysis
- **🛡️ Threat Intelligence** - Real-time CVE and MITRE ATT&CK data integration
- **⚡ High Performance** - Multi-threading, intelligent caching, and resource optimization
- **🔌 Plugin Ecosystem** - Extensible architecture with community and official plugins
- **🎯 Framework-Specific** - Specialized for Next.js, React, and Vite applications

## 📚 Documentation

**📖 [Complete Documentation](docs/README.md)** - Comprehensive guides and references

### Quick Links
- [**Installation Guide**](docs/getting-started/installation.md) - Setup instructions
- [**CLI Reference**](docs/user-guide/cli-reference.md) - Command-line interface
- [**Vulnerability Types**](docs/security/vulnerability-types.md) - Security detection types
- [**Troubleshooting**](docs/advanced/troubleshooting.md) - Common issues and solutions

## 🎯 Scan Modes

| Mode | Description | Timeout | Use Case |
|------|-------------|---------|----------|
| `quick` | Fast CI/CD scanning | 60s | Automated pipelines |
| `standard` | Balanced security checks | 5min | Regular security audits |
| `deep` | Comprehensive with AI | 15min | Thorough security analysis |
| `enterprise` | Full enterprise scan | 30min | Complete security assessment |

## 🔧 Installation Options

### Standard Installation
```bash
pip install njordscan
```

### Development Installation
```bash
git clone https://github.com/nimdy/njordscan.git
cd njordscan
pip install -e .
```

### Troubleshooting
- [**Wheel Installation Issues**](docs/getting-started/WHEEL_INSTALLATION_GUIDE.md)
- [**Kali Linux Setup**](docs/getting-started/KALI_LINUX_GUIDE.md)
- [**LXML Issues**](docs/advanced/LXML_TROUBLESHOOTING.md)

## 🛡️ Security Capabilities

### Vulnerability Detection
- **35+ Vulnerability Types** - XSS, SQL Injection, CSRF, SSRF, LLM vulnerabilities, and more
- **OWASP Top 10 2021** - Complete coverage of critical security risks
- **OWASP LLM Applications 2025** - AI/LLM-specific security vulnerabilities
- **Framework-Specific** - Next.js, React, and Vite security patterns
- **AI-Enhanced** - Machine learning for novel vulnerability detection

### Penetration Testing
- **Active Exploitation** - Real payload testing and vulnerability exploitation
- **Business Logic Testing** - Application-specific security flaws
- **Behavioral Analysis** - Advanced persistent threat detection
- **Threat Intelligence** - Real-world attack pattern correlation

## 🚀 Usage Examples

### Basic Scanning
```bash
# Scan current directory
njordscan scan .

# Scan specific URL
njordscan scan https://example.com

# Scan with specific framework
njordscan scan . --framework nextjs
```

### Advanced Scanning
```bash
# AI-enhanced deep scan
njordscan scan . --mode deep --ai-enhanced --behavioral-analysis

# Penetration testing mode
njordscan scan http://localhost:3000 --pentest --threat-intel

# Custom output format
njordscan scan . --format json --output security-report.json
```

### CI/CD Integration
```bash
# Quick scan for CI/CD
njordscan scan . --mode quick --ci --fail-on high

# Quality gate integration
njordscan scan . --quality-gate policy.yaml --fail-on critical
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/nimdy/njordscan.git
cd njordscan
pip install -e .
python -m pytest  # Run tests
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [docs/README.md](docs/README.md)
- **Issues**: [GitHub Issues](https://github.com/nimdy/njordscan/issues)
- **Security**: [Security Policy](SECURITY.md)

---

**Made with ❤️ for the security community**