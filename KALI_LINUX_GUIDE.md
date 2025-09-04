# 🐉 NjordScan Installation Guide for Kali Linux

This guide specifically addresses installation issues on Kali Linux, including the `pkg_resources` deprecation warning and missing development packages.

## 🚨 Common Kali Linux Issues

### Issue 1: `pkg_resources is deprecated as of 2025-11-30`
**Error Message:**
```
DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
```

**Solution:**
```bash
# Upgrade setuptools to latest version
pip3 install --upgrade setuptools

# Or use our Kali installer
./install-kali.sh
```

### Issue 2: Missing libxml2 and libxslt development packages
**Error Message:**
```
Please make sure libxml2 and libxslt development packages are installed
```

**Solution:**
```bash
# Install required development packages
sudo apt update
sudo apt install -y libxml2-dev libxslt1-dev

# Then install NjordScan
pip3 install njordscan
```

### Issue 3: Missing build tools
**Error Message:**
```
error: Microsoft Visual C++ 14.0 is required
```

**Solution:**
```bash
# Install build essentials
sudo apt install -y build-essential python3-dev

# Install additional dependencies
sudo apt install -y libssl-dev libffi-dev
```

## 🛠️ Complete Kali Linux Installation

### Method 1: Automated Installation (Recommended)
```bash
# Download and run our Kali-specific installer
curl -sSL https://raw.githubusercontent.com/nimdy/njordscan/main/install-kali.sh | bash

# Or if you have the source code
./install-kali.sh
```

### Method 2: Manual Installation
```bash
# 1. Update package lists
sudo apt update

# 2. Install system dependencies
sudo apt install -y \
    python3-dev \
    python3-pip \
    python3-venv \
    build-essential \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    libjpeg-dev \
    libpng-dev \
    libfreetype6-dev \
    liblcms2-dev \
    libwebp-dev \
    libharfbuzz-dev \
    libfribidi-dev \
    libxcb1-dev \
    pkg-config \
    git \
    curl \
    wget

# 3. Upgrade pip and install build tools
python3 -m pip install --upgrade pip setuptools wheel

# 4. Install NjordScan
pip3 install njordscan
```

### Method 3: Virtual Environment Installation
```bash
# 1. Install system dependencies (same as Method 2, step 2)

# 2. Create virtual environment
python3 -m venv njordscan-env
source njordscan-env/bin/activate

# 3. Upgrade pip and install build tools
pip install --upgrade pip setuptools wheel

# 4. Install NjordScan
pip install njordscan

# 5. Test installation
njordscan --help
```

## 🔧 Troubleshooting Specific Errors

### Error: `ModuleNotFoundError: No module named 'wheel'`
```bash
pip3 install wheel
```

### Error: `Permission denied`
```bash
# Use user installation
pip3 install --user njordscan

# Or use virtual environment
python3 -m venv njordscan-env
source njordscan-env/bin/activate
pip install njordscan
```

### Error: `SSL: CERTIFICATE_VERIFY_FAILED`
```bash
# Use trusted hosts
pip3 install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org njordscan
```

### Error: `error: can't create or remove files in install directory`
```bash
# Use user installation
pip3 install --user njordscan

# Or specify a different directory
pip3 install --target /home/$USER/.local/lib/python3.10/site-packages njordscan
```

## 🧪 Testing Your Installation

After installation, verify everything works:

```bash
# Test import
python3 -c "import njordscan; print('✅ NjordScan installed successfully!')"

# Test CLI
njordscan --help

# Test scan
njordscan scan . --mode quick
```

## 🚀 Quick Start Commands

```bash
# Basic scan
njordscan scan /path/to/project

# AI-enhanced scan
njordscan scan /path/to/project --ai-enhanced

# Framework-specific scan
njordscan scan /path/to/project --framework nextjs

# Deep scan with all features
njordscan scan /path/to/project --mode deep --ai-enhanced --behavioral-analysis --threat-intel
```

## 📦 Package Management

### Updating NjordScan
```bash
pip3 install --upgrade njordscan
```

### Uninstalling NjordScan
```bash
pip3 uninstall njordscan
```

### Checking Installation
```bash
pip3 show njordscan
```

## 🔍 Advanced Configuration

### Environment Variables
```bash
# Set NjordScan configuration directory
export NJORDSCAN_CONFIG_DIR="$HOME/.config/njordscan"

# Set cache directory
export NJORDSCAN_CACHE_DIR="$HOME/.cache/njordscan"

# Set log level
export NJORDSCAN_LOG_LEVEL="INFO"
```

### Configuration File
```bash
# Create configuration directory
mkdir -p ~/.config/njordscan

# Create config file
cat > ~/.config/njordscan/config.yaml << EOF
scanning:
  default_mode: "standard"
  max_threads: 8
  timeout: 300

ai:
  enabled: true
  model: "gpt-3.5-turbo"

reporting:
  format: "html"
  include_remediation: true
EOF
```

## 🆘 Getting Help

If you're still having issues:

1. **Check our main troubleshooting guide**: `WHEEL_INSTALLATION_GUIDE.md`
2. **Open an issue** on GitHub with:
   - Kali Linux version (`cat /etc/os-release`)
   - Python version (`python3 --version`)
   - Pip version (`pip3 --version`)
   - Full error message
3. **Join our community** for support

## 🔗 Useful Links

- [NjordScan GitHub Repository](https://github.com/nimdy/njordscan)
- [Kali Linux Documentation](https://www.kali.org/docs/)
- [Python Packaging User Guide](https://packaging.python.org/)
- [Pip Documentation](https://pip.pypa.io/en/stable/)

---

**Note:** This guide is specifically tailored for Kali Linux. For other distributions, see the main installation guide.
