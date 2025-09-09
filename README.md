# 🛡️ NjordScan - Ultimate Security Scanner

> **The Ultimate Security Scanner for Next.js, React, and Vite Applications**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CLI](https://img.shields.io/badge/CLI-Powerful-orange.svg)](#command-line-interface)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)](#)
[![Tests](https://img.shields.io/badge/Tests-77%25%20Passing-yellow.svg)](#)

## 📊 Test Status

**Current Test Results (as of latest run):**
- ✅ **37 tests passing** (77% pass rate)
- ⚠️ **11 tests failing** (mostly AI integration and async issues)
- ⏭️ **25 tests skipped** (require async setup or external dependencies)

**Test Coverage:**
- ✅ Core functionality: **100% passing**
- ✅ CLI interface: **80% passing** 
- ✅ Vulnerability detection: **100% passing**
- ⚠️ AI features: **60% passing** (some async integration issues)
- ⏭️ Advanced features: **Skipped** (require full environment setup)

*Note: The failing tests are primarily related to async integration and AI features that require additional setup. Core security scanning functionality is fully operational.*

**To verify test status:**
```bash
# Run all tests
python -m pytest tests/ -v

# Run only core functionality tests
python -m pytest tests/test_core_functionality.py -v

# Run with coverage
python -m pytest tests/ --cov=njordscan --cov-report=html
```

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

## ⚖️ Legal Disclaimer

**IMPORTANT: READ THIS DISCLAIMER CAREFULLY BEFORE USING NJORDSCAN**

### **Terms of Use and Liability Disclaimer**

By using NjordScan, you acknowledge and agree to the following terms:

#### **1. No Warranty**
- NjordScan is provided "AS IS" without any warranty, express or implied
- We make no representations or warranties regarding the accuracy, reliability, or completeness of scan results
- We do not guarantee that NjordScan will detect all vulnerabilities or security issues

#### **2. Limitation of Liability**
- **YOU USE NJORDSCAN AT YOUR OWN RISK**
- We are not responsible for any damage, loss, or harm caused by:
  - Use or misuse of this software
  - False positives or false negatives in scan results
  - System instability, crashes, or data loss
  - Any security incidents that occur before, during, or after scanning
  - Actions taken based on scan results

#### **3. Ethical Use Only**
- **ONLY USE ON SYSTEMS YOU OWN OR HAVE EXPLICIT PERMISSION TO TEST**
- Unauthorized scanning of systems is illegal and prohibited
- You are solely responsible for ensuring you have proper authorization
- We are not responsible for any legal consequences of unauthorized use

#### **4. Professional Advice**
- Scan results are for informational purposes only
- They do not constitute professional security advice
- Consult qualified security professionals for critical security decisions
- We recommend independent verification of all findings

#### **5. Data and Privacy**
- Scan results may contain sensitive information
- You are responsible for protecting and securing scan data
- We are not responsible for data breaches or privacy violations

#### **6. Third-Party Dependencies**
- NjordScan uses third-party libraries and services
- We are not responsible for vulnerabilities in third-party components
- Use of external APIs is subject to their respective terms of service

#### **7. Updates and Changes**
- Software may be updated without notice
- We reserve the right to modify or discontinue the software
- Previous versions may become unsupported

### **Acceptance of Terms**
By running NjordScan, you confirm that you have read, understood, and agree to be bound by this disclaimer. If you do not agree to these terms, do not use this software.

### **Contact**
For legal questions or concerns, please contact us through our [GitHub Issues](https://github.com/nimdy/njordscan/issues).

---

**Made with ❤️ for the security community**