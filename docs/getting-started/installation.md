# 📦 Installation Guide

Complete installation guide for NjordScan with system requirements, dependencies, and troubleshooting.

---

## 🎯 **System Requirements**

### **Operating Systems**
- **Linux**: Ubuntu 18.04+, CentOS 7+, RHEL 7+, Debian 9+
- **macOS**: 10.15+ (Catalina or later)
- **Windows**: Windows 10+ (64-bit)

### **Python Requirements**
- **Python**: 3.8+ (recommended 3.10+)
- **pip**: 21.0+ (for dependency management)
- **Memory**: Minimum 512MB RAM, Recommended 2GB+
- **Disk Space**: 100MB for installation, additional for caches

### **Network Requirements**
- **Internet**: Required for initial installation and updates
- **Ports**: No specific ports required (outbound connections only)
- **Firewall**: No inbound connections required

---

## 🚀 **Installation Methods**

### **Method 1: pip Install (Recommended)**

#### **Standard Installation**
```bash
# Install NjordScan
pip install njordscan

# Verify installation
njordscan --version
```

#### **Install with Development Dependencies**
```bash
# Install with dev dependencies
pip install njordscan[dev]

# Or install from requirements
pip install -r requirements-dev.txt
```

#### **Install Specific Version**
```bash
# Install specific version
pip install njordscan==1.0.0

# Install latest pre-release
pip install njordscan --pre
```

### **Method 2: From Source**

#### **Clone and Install**
```bash
# Clone repository
git clone https://github.com/nimdy/njordscan.git
cd njordscan

# Install in development mode
pip install -e .

# Or install normally
pip install .
```

#### **Development Setup**
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install in development mode
pip install -e .
```

### **Method 3: Docker (Coming Soon)**

```bash
# Pull Docker image (when available)
docker pull njordscan/njordscan:latest

# Run NjordScan in container
docker run -v $(pwd):/workspace njordscan/njordscan scan /workspace
```

---

## 🔧 **Dependency Management**

### **Core Dependencies**
NjordScan requires the following core dependencies:

```bash
# Core CLI and Terminal UI
click>=8.0.0
rich>=13.0.0
colorama>=0.4.4

# HTTP and Networking
aiohttp>=3.8.0
requests>=2.28.0
httpx>=0.24.0

# Configuration and Data Parsing
pyyaml>=6.0
toml>=0.10.2
python-dotenv>=1.0.0

# Security Scanning
safety>=3.0.0
bandit>=1.7.0
cryptography>=40.0.0
```

### **Optional Dependencies**
Some features require additional dependencies:

```bash
# AI/ML Features (optional)
pip install njordscan[ai]

# Enhanced Reporting (optional)
pip install njordscan[reporting]

# All Optional Features
pip install njordscan[all]
```

---

## 🐍 **Python Environment Setup**

### **Virtual Environment (Recommended)**

#### **Using venv**
```bash
# Create virtual environment
python -m venv njordscan-env

# Activate environment
# Linux/Mac:
source njordscan-env/bin/activate
# Windows:
njordscan-env\Scripts\activate

# Install NjordScan
pip install njordscan

# Deactivate when done
deactivate
```

#### **Using conda**
```bash
# Create conda environment
conda create -n njordscan python=3.10

# Activate environment
conda activate njordscan

# Install NjordScan
pip install njordscan
```

#### **Using poetry**
```bash
# Initialize poetry project
poetry init

# Add NjordScan dependency
poetry add njordscan

# Install dependencies
poetry install

# Run NjordScan
poetry run njordscan
```

---

## 🔍 **Verification and Testing**

### **Basic Verification**
```bash
# Check version
njordscan --version

# Show help
njordscan --help

# Run system diagnostics
njordscan doctor
```

### **Test Installation**
```bash
# Create test project
mkdir test-project
cd test-project

# Create simple HTML file
echo '<html><body>Test</body></html>' > index.html

# Run basic scan
njordscan scan . --mode quick

# Should complete without errors
```

### **System Validation Test**
```bash
# Run comprehensive system validation
python3 tests/test_complete_system_validation.py

# Should show 9/10 tests passing (90% success rate)
# Plugin system may show minor configuration issues (non-blocking)
```

### **Framework Detection Test**
```bash
# Test Next.js detection
mkdir nextjs-test
cd nextjs-test
echo '{"name": "test", "dependencies": {"next": "^13.0.0"}}' > package.json
njordscan --framework nextjs .

# Test React detection
mkdir react-test
cd react-test
echo '{"name": "test", "dependencies": {"react": "^18.0.0"}}' > package.json
njordscan --framework react .
```

---

## 🛠️ **Configuration Setup**

### **Initial Configuration**
```bash
# Initialize configuration
njordscan configure --init

# Interactive configuration
njordscan configure --interactive
```

### **Configuration File**
Create `.njordscan.json` in your project root:

```json
{
  "framework": "auto",
  "mode": "standard",
  "modules": {
    "headers": true,
    "static": true,
    "dependencies": true,
    "configs": true,
    "runtime": false
  },
  "output": {
    "format": "terminal",
    "verbose": false
  }
}
```

---

## 🚨 **Troubleshooting Installation**

### **Common Issues**

#### **Python Version Issues**
```bash
# Check Python version
python --version

# If Python < 3.8, upgrade Python
# Ubuntu/Debian:
sudo apt update
sudo apt install python3.10 python3.10-pip

# macOS (with Homebrew):
brew install python@3.10

# Windows: Download from python.org
```

#### **Permission Issues**
```bash
# Install for current user only
pip install --user njordscan

# Or use virtual environment
python -m venv venv
source venv/bin/activate
pip install njordscan
```

#### **Network Issues**
```bash
# Use different index
pip install -i https://pypi.org/simple/ njordscan

# Use proxy
pip install --proxy http://proxy.company.com:8080 njordscan

# Offline installation
pip download njordscan
pip install njordscan-*.whl
```

#### **Dependency Conflicts**
```bash
# Check for conflicts
pip check

# Force reinstall
pip install --force-reinstall njordscan

# Install without dependencies (not recommended)
pip install --no-deps njordscan
```

### **Platform-Specific Issues**

#### **Linux Issues**
```bash
# Install system dependencies
sudo apt update
sudo apt install python3-dev python3-pip build-essential

# For CentOS/RHEL:
sudo yum install python3-devel python3-pip gcc
```

#### **macOS Issues**
```bash
# Install Xcode command line tools
xcode-select --install

# Fix SSL issues
/Applications/Python\ 3.x/Install\ Certificates.command
```

#### **Windows Issues**
```bash
# Install Visual C++ Build Tools
# Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/

# Fix PATH issues
# Add Python and Scripts to PATH environment variable
```

---

## 🔄 **Updates and Maintenance**

### **Update NjordScan**
```bash
# Check for updates
njordscan update --check

# Update to latest version
pip install --upgrade njordscan

# Update specific version
pip install --upgrade njordscan==1.1.0
```

### **Clean Installation**
```bash
# Uninstall NjordScan
pip uninstall njordscan

# Clean pip cache
pip cache purge

# Reinstall
pip install njordscan
```

### **Cache Management**
```bash
# Clear NjordScan cache
njordscan cache clear

# Show cache statistics
njordscan cache stats
```

---

## 📋 **Post-Installation Checklist**

### **✅ Verification Steps**
- [ ] NjordScan version displays correctly
- [ ] Help command works
- [ ] Basic scan completes without errors
- [ ] Framework detection works
- [ ] Configuration file can be created
- [ ] Output formats work (terminal, json, html)
- [ ] System validation test passes (9/10 tests)
- [ ] AI integration works correctly
- [ ] Vulnerability type system functions properly

### **✅ Optional Setup**
- [ ] Configure IDE integration
- [ ] Set up CI/CD integration
- [ ] Configure custom rules
- [ ] Set up plugin system
- [ ] Configure reporting templates

---

## 🆘 **Getting Help**

### **Documentation**
- **User Guide**: [docs/user-guide/cli-reference.md](../user-guide/cli-reference.md)
- **Quick Start**: [docs/getting-started/quick-start.md](quick-start.md)
- **Security Guide**: [docs/security/vulnerability-types.md](../security/vulnerability-types.md)

### **Community Support**
- **GitHub Issues**: [Report installation problems](https://github.com/nimdy/njordscan/issues)
- **Discord**: [Join community for help](https://discord.gg/njordscan)
- **Discussions**: [GitHub Discussions](https://github.com/nimdy/njordscan/discussions)

### **Professional Support**
- **Email**: support@njordscan.dev
- **Enterprise**: enterprise@njordscan.dev

---

<div align="center">

## 🎉 **Installation Complete!**

**You're ready to start securing your applications with NjordScan!**

[**🚀 Quick Start Guide**](quick-start.md) | [**📋 CLI Reference**](../user-guide/cli-reference.md) | [**🛡️ Security Features**](../security/vulnerability-types.md)

</div>
