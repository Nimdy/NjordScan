# 🔧 NjordScan Wheel Installation Guide

This guide helps you resolve wheel installation issues when installing NjordScan.

## 🚨 Common Wheel Installation Errors

### Error Messages You Might See:
- `ModuleNotFoundError: No module named 'wheel'`
- `error: Microsoft Visual C++ 14.0 is required`
- `Permission denied` during installation
- `SSL: CERTIFICATE_VERIFY_FAILED`
- `error: can't create or remove files in install directory`

## 🛠️ Solutions (Try in Order)

### Solution 1: Quick Fix
```bash
# Upgrade pip and install wheel
pip install --upgrade pip setuptools wheel
pip install njordscan
```

### Solution 2: Use Our Automated Installer
```bash
# Download and run our installer
curl -sSL https://raw.githubusercontent.com/nimdy/njordscan/main/install.sh | bash

# Or use the Python installer
python install.py
```

### Solution 3: Install from Source
```bash
# Clone the repository
git clone https://github.com/nimdy/njordscan.git
cd njordscan

# Install build tools
pip install --upgrade pip setuptools wheel

# Install in development mode
pip install -e .
```

### Solution 4: Use Virtual Environment
```bash
# Create virtual environment
python -m venv njordscan-env

# Activate (Linux/macOS)
source njordscan-env/bin/activate

# Activate (Windows)
njordscan-env\Scripts\activate

# Install
pip install --upgrade pip setuptools wheel
pip install njordscan
```

### Solution 5: User Installation (No Admin Rights)
```bash
# Install to user directory
pip install --user --upgrade pip setuptools wheel
pip install --user njordscan
```

## 🖥️ Platform-Specific Solutions

### Windows
```cmd
# Use our Windows installer
install.bat

# Or manually
python -m pip install --upgrade pip setuptools wheel
python -m pip install njordscan

# If you get Visual C++ errors, install:
# Microsoft Visual C++ Build Tools
# https://visualstudio.microsoft.com/visual-cpp-build-tools/
```

### macOS
```bash
# Use our shell installer
./install.sh

# Or with Homebrew
brew install python
pip3 install njordscan

# If you get SSL errors:
pip3 install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org njordscan
```

### Linux
```bash
# Use our shell installer
./install.sh

# Or with system package manager
sudo apt-get update
sudo apt-get install python3-pip python3-dev build-essential
pip3 install --upgrade pip setuptools wheel
pip3 install njordscan

# For CentOS/RHEL:
sudo yum install python3-pip python3-devel gcc
pip3 install --upgrade pip setuptools wheel
pip3 install njordscan
```

## 🔍 Troubleshooting Specific Issues

### Issue: `ModuleNotFoundError: No module named 'wheel'`
**Solution:**
```bash
pip install wheel
```

### Issue: `error: Microsoft Visual C++ 14.0 is required`
**Solution:**
1. Install Visual Studio Build Tools: https://visualstudio.microsoft.com/visual-cpp-build-tools/
2. Or install pre-compiled wheels: `pip install --only-binary=all njordscan`

### Issue: `Permission denied`
**Solution:**
```bash
# Use user installation
pip install --user njordscan

# Or use sudo (Linux/macOS)
sudo pip install njordscan
```

### Issue: `SSL: CERTIFICATE_VERIFY_FAILED`
**Solution:**
```bash
# Use trusted hosts
pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org njordscan
```

### Issue: `error: can't create or remove files in install directory`
**Solution:**
```bash
# Use user installation
pip install --user njordscan

# Or specify a different directory
pip install --target /path/to/your/directory njordscan
```

## 🧪 Test Your Installation

After installation, test that everything works:

```bash
# Test import
python -c "import njordscan; print('✅ NjordScan installed successfully!')"

# Test CLI
njordscan --help

# Test scan
njordscan scan . --mode quick
```

## 📞 Getting Help

If you're still having issues:

1. **Check our troubleshooting section** in the main README
2. **Open an issue** on GitHub with:
   - Your operating system
   - Python version (`python --version`)
   - Pip version (`pip --version`)
   - Full error message
3. **Join our community** for support

## 🔗 Useful Links

- [NjordScan GitHub Repository](https://github.com/nimdy/njordscan)
- [Python Packaging User Guide](https://packaging.python.org/)
- [Pip Documentation](https://pip.pypa.io/en/stable/)
- [Wheel Documentation](https://wheel.readthedocs.io/)

---

**Remember:** Most wheel installation issues are resolved by upgrading pip and installing the wheel package first!
