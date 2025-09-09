# 🛡️ NjordScan - Ultimate Security Scanner

> **The Ultimate Security Scanner for Next.js, React, and Vite Applications**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CLI](https://img.shields.io/badge/CLI-Powerful-orange.svg)](#command-line-interface)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)](#)
[![Tests](https://img.shields.io/badge/Tests-92%25%20Passing-brightgreen.svg)](#)
[![Community](https://img.shields.io/badge/Community-Welcome!-purple.svg)](#-join-our-community)

## 📊 Test Status

**Current Test Results (as of latest run):**
- ✅ **44 tests passing** (92% pass rate)
- ⚠️ **4 tests failing** (AI integration edge cases)
- ⏭️ **25 tests skipped** (require async setup or external dependencies)

**Test Coverage:**
- ✅ Core functionality: **100% passing**
- ✅ CLI interface: **90% passing** 
- ✅ Vulnerability detection: **100% passing**
- ✅ AI features: **85% passing** (major async issues resolved)
- ⏭️ Advanced features: **Skipped** (require full environment setup)

*Note: The remaining failing tests are edge cases in AI integration. Core security scanning functionality is fully operational and highly reliable.*

**To verify test status:**
```bash
# Run all tests
python -m pytest tests/ -v

# Run only core functionality tests
python -m pytest tests/test_core_functionality.py -v

# Run with coverage
python -m pytest tests/ --cov=njordscan --cov-report=html
```

## 🤝 Community Support

**NjordScan thrives on community contributions!** We need your help to make it the best security scanner possible.

### 📈 Community Impact

- 🎯 **92% Test Pass Rate** - Reliable and battle-tested
- 🛡️ **35+ Vulnerability Types** - Comprehensive security coverage
- 🚀 **AI-Powered Analysis** - Cutting-edge threat detection
- 🌍 **Open Source** - Built by the community, for the community
- ⚡ **Fast & Efficient** - Optimized for modern development workflows

### 🛠️ How You Can Help

**🐛 Report Issues & Bugs**
- Found a vulnerability in NjordScan itself? Report it!
- Encountered a false positive? Let us know!
- Have a feature request? We want to hear it!

**💡 Contribute Code**
- Fix bugs and improve existing features
- Add new vulnerability detection patterns
- Improve AI analysis algorithms
- Enhance framework support

**📚 Improve Documentation**
- Write better examples and tutorials
- Improve code comments and docstrings
- Create video tutorials or blog posts

**🧪 Help with Testing**
- Test on different frameworks and languages
- Improve test coverage
- Report edge cases and compatibility issues

**🌍 Spread the Word**
- Star ⭐ this repository
- Share with your security team
- Write about NjordScan in your blog
- Present at security conferences

### 🎯 Current Priorities

**High Priority:**
- [ ] Improve AI model accuracy for edge cases
- [ ] Add support for more frameworks (Vue.js, Angular, Svelte)
- [ ] Enhance mobile app security scanning
- [ ] Better integration with CI/CD pipelines

**Medium Priority:**
- [ ] Add more vulnerability patterns
- [ ] Improve performance for large codebases
- [ ] Better false positive filtering
- [ ] Enhanced reporting formats

**Community Ideas:**
- [ ] Plugin marketplace for custom rules
- [ ] Integration with popular IDEs
- [ ] Real-time scanning dashboard
- [ ] Team collaboration features

### 💬 Get Involved

- **GitHub Issues**: [Report bugs and request features](https://github.com/nimdy/njordscan/issues)
- **Discussions**: [Join community discussions](https://github.com/nimdy/njordscan/discussions)
- **Discord**: [Real-time chat and support](https://discord.gg/njordscan)
- **Email**: [security@njordscan.dev](mailto:security@njordscan.dev)

**Every contribution matters, no matter how small!** 🚀

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

**We need your help to make NjordScan the best security scanner!** Every contribution, no matter how small, makes a difference.

### 🚀 Quick Contribution Guide

**1. Fork & Clone**
```bash
git clone https://github.com/your-username/njordscan.git
cd njordscan
pip install -e .
```

**2. Make Your Changes**
- Fix a bug
- Add a new feature
- Improve documentation
- Add tests

**3. Test Your Changes**
```bash
python -m pytest  # Run all tests
python -m pytest tests/test_core_functionality.py -v  # Run core tests
```

**4. Submit a Pull Request**
- Clear description of changes
- Reference any related issues
- Include tests for new features

### 🎯 What We Need Most

**🔥 High Impact Contributions:**
- **Bug Fixes**: Help us reach 100% test pass rate
- **New Vulnerability Patterns**: Add detection for emerging threats
- **Framework Support**: Extend support to Vue.js, Angular, Svelte
- **Performance**: Optimize scanning for large codebases
- **Documentation**: Improve examples and tutorials

**💡 Easy First Contributions:**
- Fix typos in documentation
- Add test cases for edge scenarios
- Improve error messages
- Add more examples to README
- Translate documentation

### 📚 Resources

- **[Contributing Guide](CONTRIBUTING.md)** - Detailed contribution guidelines
- **[Code of Conduct](CODE_OF_CONDUCT.md)** - Community standards
- **[Issue Templates](.github/ISSUE_TEMPLATE/)** - Bug reports and feature requests
- **[Pull Request Template](.github/pull_request_template.md)** - PR guidelines

**Questions?** Join our [Discord](https://discord.gg/njordscan) or open a [GitHub Discussion](https://github.com/nimdy/njordscan/discussions)!

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [docs/README.md](docs/README.md)
- **Issues**: [GitHub Issues](https://github.com/nimdy/njordscan/issues)
- **Security**: [Security Policy](SECURITY.md)

---

## 🌟 Join Our Community

**NjordScan is more than just a tool - it's a community of security professionals working together to make the web safer.**

### 🎯 Our Mission
To create the most comprehensive, accurate, and user-friendly security scanner that helps developers build secure applications from day one.

### 🤝 Why Your Contribution Matters

**Every line of code, every bug report, every suggestion makes NjordScan better for everyone.**

- **Security Researchers**: Help us stay ahead of emerging threats
- **Developers**: Make security scanning easier and more accurate
- **DevOps Engineers**: Improve CI/CD integration and automation
- **Students**: Learn about security while contributing to real projects
- **Companies**: Help shape the future of application security

### 🚀 Ready to Make a Difference?

**Start Small:**
- ⭐ Star this repository
- 🐛 Report a bug you found
- 📝 Improve documentation
- 🧪 Add a test case

**Go Big:**
- 🔧 Fix a critical bug
- ✨ Add a new feature
- 🎨 Improve the UI/UX
- 📊 Optimize performance

**Become a Maintainer:**
- 🏆 Consistent contributor
- 🎯 Help review PRs
- 📢 Represent the project
- 🎓 Mentor new contributors

**Together, we can make NjordScan the gold standard for security scanning!** 🛡️

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