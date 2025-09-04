# 🔧 lxml Installation Troubleshooting Guide

## The Problem

The `lxml` library is a critical dependency for NjordScan that provides fast XML and HTML parsing. However, it requires compilation of C extensions, which can fail on certain systems, especially Kali Linux.

**Common Error Messages:**
```
error: failed building wheel for lxml
running setup.py clean for lxml
failed to build installable wheels for some pyproject.toml based project lxml
```

## 🚀 Quick Fixes

### For Kali Linux Users
```bash
# Use our dedicated fix script
./fix-lxml-kali.sh

# Or use the enhanced Kali installer
./install-kali.sh
```

### For All Linux Users
```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3-dev libxml2-dev libxslt1-dev build-essential

# Try installing lxml
pip3 install lxml --no-cache-dir
```

## 🔍 Detailed Solutions

### Method 1: System Package Manager (Recommended)
```bash
# Ubuntu/Debian/Kali
sudo apt install python3-lxml

# CentOS/RHEL/Fedora
sudo yum install python3-lxml
# or
sudo dnf install python3-lxml

# Arch Linux
sudo pacman -S python-lxml
```

### Method 2: Pre-compiled Wheels
```bash
# Force use of pre-compiled wheels
pip install lxml --only-binary=all --no-cache-dir
```

### Method 3: Source Installation with Flags
```bash
# Set environment variables for compilation
export STATIC_DEPS=true
export STATICBUILD=true
export LDFLAGS="-L/usr/lib/x86_64-linux-gnu"
export CPPFLAGS="-I/usr/include/libxml2"

# Install from source
pip install lxml --no-cache-dir --no-binary=lxml
```

### Method 4: Alternative XML Parser
If lxml continues to fail, NjordScan can work with alternative parsers:

```bash
# Install alternative parsers
pip install beautifulsoup4 html5lib

# NjordScan will automatically fall back to these
```

### Method 5: Virtual Environment
Sometimes installing in a fresh virtual environment helps:

```bash
# Create virtual environment
python3 -m venv njordscan-env
source njordscan-env/bin/activate

# Install dependencies
pip install --upgrade pip setuptools wheel
pip install lxml

# Install NjordScan
pip install njordscan
```

### Method 6: Conda Installation
If pip continues to fail, try conda:

```bash
# Install conda if not already installed
# Then:
conda install lxml
conda install -c conda-forge njordscan
```

## 🐛 Platform-Specific Issues

### Kali Linux
Kali Linux often has issues with lxml due to:
- Missing development packages
- Outdated build tools
- Conflicting system libraries

**Solution:**
```bash
# Install all required dependencies
sudo apt update
sudo apt install -y \
    python3-dev \
    python3-pip \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    libxslt-dev \
    libxml2-utils \
    libxml2 \
    libxslt1.1 \
    zlib1g-dev \
    gcc \
    g++ \
    make \
    pkg-config

# Try installation
pip3 install lxml --no-cache-dir
```

### Ubuntu/Debian
```bash
sudo apt install python3-dev libxml2-dev libxslt1-dev build-essential
pip3 install lxml
```

### CentOS/RHEL
```bash
sudo yum groupinstall "Development Tools"
sudo yum install python3-devel libxml2-devel libxslt-devel
pip3 install lxml
```

### macOS
```bash
# Install Xcode command line tools
xcode-select --install

# Install dependencies via Homebrew
brew install libxml2 libxslt

# Set environment variables
export LDFLAGS="-L$(brew --prefix libxml2)/lib -L$(brew --prefix libxslt)/lib"
export CPPFLAGS="-I$(brew --prefix libxml2)/include -I$(brew --prefix libxslt)/include"

# Install lxml
pip install lxml
```

### Windows
```bash
# Install Visual Studio Build Tools
# Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/

# Or use pre-compiled wheels
pip install lxml --only-binary=all
```

## 🔧 Advanced Troubleshooting

### Check System Dependencies
```bash
# Check if required libraries are installed
ldconfig -p | grep libxml2
ldconfig -p | grep libxslt

# Check Python development headers
python3-config --includes
```

### Debug Compilation Issues
```bash
# Install with verbose output
pip install lxml --no-cache-dir --no-binary=lxml -v

# Check compiler version
gcc --version
g++ --version
```

### Alternative Installation Methods
```bash
# Try different pip versions
pip3 install --upgrade pip
pip3 install lxml

# Try with specific Python version
python3.9 -m pip install lxml
python3.10 -m pip install lxml
```

## 🆘 When All Else Fails

If lxml still won't install, NjordScan can function without it:

1. **Install NjordScan without lxml:**
   ```bash
   pip install njordscan --no-deps
   pip install beautifulsoup4 html5lib pyyaml click rich
   ```

2. **Use alternative XML parsing:**
   - NjordScan will automatically fall back to `beautifulsoup4` + `html5lib`
   - Some advanced XML features may be limited
   - Core security scanning will still work

3. **Contact Support:**
   - Open an issue on GitHub with your system details
   - Include the full error message
   - Mention your OS version and Python version

## 📋 System Information to Include

When reporting lxml issues, include:

```bash
# System information
uname -a
cat /etc/os-release
python3 --version
pip3 --version

# Library information
ldconfig -p | grep -E "(libxml2|libxslt)"
pkg-config --modversion libxml-2.0
pkg-config --modversion libxslt

# Error details
pip3 install lxml --no-cache-dir --no-binary=lxml -v 2>&1 | tail -50
```

## 🎯 Prevention

To avoid lxml issues in the future:

1. **Always install system dependencies first**
2. **Use virtual environments**
3. **Keep build tools updated**
4. **Consider using system package managers for lxml**

---

**Remember:** NjordScan is designed to be resilient and will work even if lxml installation fails, though some XML parsing features may be limited.
