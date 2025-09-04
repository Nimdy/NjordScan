# 🛡️ NjordScan - Ultimate Security Scanner

> **The Ultimate Security Scanner for Next.js, React, and Vite Applications**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CLI](https://img.shields.io/badge/CLI-Powerful-orange.svg)](#command-line-interface)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)](#)
[![Tests](https://img.shields.io/badge/Tests-90%25%20Passing-brightgreen.svg)](#)

## 🚀 **Quick Start**

### **💻 Command Line Interface**

```bash
# 🚀 Easy Installation (Recommended)
# Use our automated installation script
curl -sSL https://raw.githubusercontent.com/nimdy/njordscan/main/install.sh | bash

# Or install manually
pip install njordscan

# 🔧 Troubleshooting Wheel Issues
# If you encounter wheel installation errors, try:
pip install --upgrade pip setuptools wheel
pip install njordscan

# Or use our Python installer
python install.py

# 🛠️ Development Installation
git clone https://github.com/nimdy/njordscan.git
cd njordscan
pip install -e .

# Start scanning
njordscan scan . --mode deep --ai-enhanced
```

---

## ✨ **Amazing Developer Experience**

### **💻 CLI Features**
- **🎯 Multiple Scan Modes** - Quick, Standard, Deep, Enterprise
- **🤖 AI-Enhanced Analysis** - Machine learning powered detection
- **🔍 Behavioral Analysis** - Advanced threat detection
- **🛡️ Threat Intelligence** - Real-time CVE and MITRE ATT&CK data
- **👥 Community Rules** - Shared security patterns
- **⚡ Performance Tuning** - Multi-threading, caching, timeout controls
- **📦 Module Selection** - Choose which security modules to run

## 🎯 **Key Features**

### **🔍 Comprehensive Security Scanning**
- **Framework Detection** - Auto-detect Next.js, React, Vite
- **Standardized Vulnerability Types** - 25+ vulnerability types aligned with OWASP Top 10
- **Dependency Analysis** - CVE scanning, license compliance, typosquatting detection
- **Configuration Security** - Environment variables, secrets detection, insecure settings
- **Runtime Security** - Headers, cookies, authentication, dynamic testing
- **Enhanced Static Analysis** - Advanced pattern matching and code analysis

### **🤖 AI-Powered Intelligence**
- **Enhanced Behavioral Analysis** - Multi-strategy sequence analysis and anomaly detection
- **Threat Intelligence** - Real-time CVE and MITRE ATT&CK data with graceful error handling
- **False Positive Filtering** - AI-powered noise reduction with standardized vulnerability types
- **Adaptive Learning** - Improve detection over time
- **Risk Assessment** - Intelligent vulnerability prioritization with CWE mapping
- **AI Orchestrator** - Comprehensive AI analysis with threat assessment and code understanding

### **⚡ High Performance**
- **Multi-threading** - Parallel processing for faster scans
- **Intelligent Caching** - Smart result caching strategies
- **Resource Management** - Memory and CPU optimization
- **Timeout Controls** - Configurable scan duration limits
- **Progress Tracking** - Real-time scan status updates

### **🔌 Plugin Ecosystem**
- **Marketplace** - Community and official plugins
- **Hot Reloading** - Instant plugin updates
- **Security Validation** - Plugin safety checks
- **SDK** - Easy plugin development
- **Version Management** - Plugin compatibility

---

## 🚀 **Quick Start**

### **💻 Command Line Interface**

```bash
# 1. Install NjordScan
pip install njordscan

# 2. Start scanning
njordscan scan . --mode standard

# 3. Advanced scanning
njordscan scan https://example.com --mode deep --ai-enhanced --threat-intel
```

---

## 🛠️ **Installation**

### **System Requirements**
- **Python**: 3.8 or higher
- **Memory**: 2GB RAM minimum, 4GB recommended
- **Storage**: 1GB free space

### **CLI Installation**
```bash
# From PyPI
pip install njordscan

# From source
git clone https://github.com/nimdy/njordscan.git
cd njordscan
pip install -e .
```

---

## 🎮 **Usage**

### **💻 CLI Usage**

```bash
# Basic scan
njordscan scan . --mode standard

# AI-enhanced scan
njordscan scan . --mode deep --ai-enhanced --behavioral-analysis

# Framework-specific scan
njordscan scan . --framework nextjs --threat-intel

# Performance-optimized scan
njordscan scan . --threads 8 --cache-strategy aggressive --timeout 30

# Module-specific scan
njordscan scan . --only headers,static,dependencies --include-remediation
```

---

## 🏗️ **Architecture Overview**

```
💻 Command Line Interface
├── 🎯 Multiple scan modes and options
├── 🤖 AI and intelligence features
├── ⚡ Performance optimization
└── 🔌 Plugin system integration

🔍 Core Security Modules
├── 📋 Headers Analysis
├── 🔍 Static Code Analysis
├── ⚙️ Configuration Security
├── 📦 Dependency Analysis
├── 🚀 Runtime Security
├── 🤖 AI Endpoints
├── 🧠 Intelligence Engine
└── ⚡ Performance Monitor

🤖 AI & Intelligence Layer
├── 🧠 Behavioral Analysis
├── 🛡️ Threat Intelligence
├── 🎯 False Positive Filtering
├── 📊 Risk Assessment
└── 🔄 Adaptive Learning

⚡ Performance Layer
├── 🧵 Multi-threading
├── 💾 Intelligent Caching
├── 📊 Resource Monitoring
└── ⏱️ Timeout Management

🔌 Plugin System
├── 🏪 Marketplace
├── 🔄 Hot Reloading
├── ✅ Security Validation
└── 🛠️ SDK & Tools
```

---

## 📊 **Core Security Modules**

| Module | CLI | Description |
|--------|-----|-------------|
| **Headers** | ✅ | HTTP security headers analysis |
| **Static Analysis** | ✅ | Source code vulnerability scanning |
| **Configuration** | ✅ | Environment and config security |
| **Dependencies** | ✅ | CVE scanning and license compliance |
| **Runtime** | ✅ | Live application security testing |
| **AI Endpoints** | ✅ | AI-powered vulnerability detection |
| **Intelligence** | ✅ | Threat intelligence and correlation |
| **Performance** | ✅ | Security performance optimization |

---

## 🎯 **Developer Experience Features**

### **💻 CLI**
- **🎯 Rich Interface** - Beautiful terminal output
- **🔧 Interactive Setup** - Guided configuration
- **📊 Progress Bars** - Real-time scan progress
- **🎨 Color Themes** - Customizable appearance
- **📝 Detailed Logging** - Comprehensive debugging

---

## 🔌 **Plugin Development**

### **Creating Plugins**
```python
from njordscan.plugins_v2 import BasePlugin

class MySecurityPlugin(BasePlugin):
    name = "my_security_plugin"
    version = "1.0.0"
    
    def scan(self, target, options):
        # Your security logic here
        return {"vulnerabilities": [], "score": 100}
```

### **Plugin Marketplace**
- **Community Plugins** - Shared security rules
- **Official Plugins** - Core NjordScan functionality
- **Custom Plugins** - Organization-specific security
- **Version Management** - Plugin compatibility

---

## 🤝 **Contributing**

We welcome contributions! Here are some areas where you can help:

### **💻 CLI & Core**
- **Security Modules** - New vulnerability detection
- **AI Features** - Machine learning improvements
- **Performance** - Optimization and caching
- **Documentation** - Guides and tutorials

### **🔌 Plugins**
- **Security Rules** - New vulnerability patterns
- **Framework Support** - Additional frameworks
- **Integration** - Third-party tool connections
- **Testing** - Quality assurance

---

## 📚 **Documentation**

- **[🔧 CLI Reference](docs/user-guide/cli-reference.md)** - Complete command-line documentation
- **[🚀 Quick Start](docs/getting-started/quick-start.md)** - Get up and running quickly
- **[🛡️ Security Guide](docs/security/vulnerability-types.md)** - Understanding vulnerability types

---

## 🚨 **Troubleshooting**

### **CLI Issues**
```bash
# Check installation
njordscan --version

# Verify dependencies
pip list | grep njordscan

# Run with verbose output
njordscan scan . --verbose

# Test system validation
python3 tests/test_complete_system_validation.py
```

### **Common Issues**
- **Plugin System**: Minor configuration issues with plugin directories (non-blocking)
- **External APIs**: NIST CVE and MITRE ATT&CK APIs may have rate limits (handled gracefully)
- **Target Validation**: Ensure target directory exists for local scans

---

## 🌟 **Upcoming Features**

- **🔐 Authentication** - User accounts and permissions
- **👥 Team Collaboration** - Shared scans and results
- **☁️ Cloud Integration** - AWS, Azure, GCP scanning
- **📱 Mobile App** - Native mobile application
- **🔗 CI/CD Integration** - Automated security testing
- **📊 Advanced Analytics** - Machine learning insights

---

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🔧 **Troubleshooting**

### **Wheel Installation Issues**

If you encounter wheel-related installation errors, try these solutions:

```bash
# Solution 1: Upgrade pip and install wheel
pip install --upgrade pip setuptools wheel
pip install njordscan

# Solution 2: Use our automated installer
python install.py

# Solution 3: Install from source with wheel
pip install --upgrade pip setuptools wheel
git clone https://github.com/nimdy/njordscan.git
cd njordscan
pip install -e .

# Solution 4: Use virtual environment
python -m venv njordscan-env
source njordscan-env/bin/activate  # On Windows: njordscan-env\Scripts\activate
pip install --upgrade pip setuptools wheel
pip install njordscan
```

### **Common Issues**

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: No module named 'wheel'` | Run `pip install wheel` |
| `error: Microsoft Visual C++ 14.0 is required` | Install Visual Studio Build Tools |
| `Permission denied` | Use `pip install --user njordscan` |
| `SSL: CERTIFICATE_VERIFY_FAILED` | Use `pip install --trusted-host pypi.org njordscan` |

### **Platform-Specific Solutions**

**Windows:**
```cmd
# Use our Windows installer
install.bat

# Or manually
python -m pip install --upgrade pip setuptools wheel
python -m pip install njordscan
```

**macOS:**
```bash
# Use our shell installer
./install.sh

# Or with Homebrew
brew install python
pip3 install njordscan
```

**Linux:**
```bash
# Use our shell installer
./install.sh

# Or with system package manager
sudo apt-get install python3-pip python3-dev
pip3 install njordscan
```

---

## 🆘 **Support & Community**

- **📖 Documentation** - [CLI Reference](docs/user-guide/cli-reference.md)
- **🐛 Bug Reports** - [GitHub Issues](https://github.com/nimdy/njordscan/issues)

---

## 🎯 **Quick Reference**

### **💻 CLI Commands**
```bash
njordscan scan . --mode standard                    # Basic scan
njordscan scan . --ai-enhanced --threat-intel      # AI scan
njordscan scan . --framework nextjs --verbose      # Framework scan
njordscan scan . --threads 8 --cache-strategy aggressive  # Performance scan
```

---

**🎉 Powerful CLI security scanning with AI-enhanced analysis and comprehensive vulnerability detection!**
