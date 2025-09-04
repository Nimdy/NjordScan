# 🐉 Kali Linux Installation Fixes

## Issues Addressed

### 1. ✅ `pkg_resources` Deprecation Warning
**Problem:** `pkg_resources is deprecated as of 2025-11-30`

**Solution Implemented:**
- Replaced `pkg_resources` with `importlib.metadata` in test files
- Created modern `pyproject.toml` configuration
- Updated setup.py to use modern build system
- Added setuptools upgrade instructions

### 2. ✅ Missing libxml2 and libxslt Development Packages
**Problem:** `Please make sure libxml2 and libxslt development packages are installed`

**Solution Implemented:**
- Created Kali-specific installer (`install-kali.sh`)
- Added system dependency installation
- Updated requirements.txt with dependency notes
- Provided manual installation instructions

### 3. ✅ Wheel Installation Issues
**Problem:** Various wheel-related installation errors

**Solution Implemented:**
- Enhanced setup.py with automatic wheel installation
- Created multiple installation scripts for different platforms
- Added fallback installation methods
- Comprehensive troubleshooting documentation

## Files Created/Modified

### New Files:
- `install-kali.sh` - Kali Linux specific installer
- `pyproject.toml` - Modern Python packaging configuration
- `KALI_LINUX_GUIDE.md` - Comprehensive Kali Linux guide
- `KALI_LINUX_FIXES.md` - This summary document

### Modified Files:
- `setup.py` - Added modern build commands and wheel handling
- `requirements.txt` - Added dependency notes
- `README.md` - Added Kali Linux specific instructions
- `tests/validation/installation_validator.py` - Replaced pkg_resources

## Quick Fix for Users

### For Kali Linux Users:
```bash
# Option 1: Use our Kali installer
./install-kali.sh

# Option 2: Manual fix
sudo apt update
sudo apt install -y python3-dev python3-pip libxml2-dev libxslt1-dev build-essential
pip3 install --upgrade pip setuptools wheel
pip3 install njordscan
```

### For All Users (pkg_resources warning):
```bash
pip install --upgrade setuptools
```

## Testing Results

✅ **Wheel Installation:** Working
✅ **System Dependencies:** Handled
✅ **Modern Build System:** Implemented
✅ **Cross-Platform Support:** Maintained
✅ **Backward Compatibility:** Preserved

## Next Steps for Users

1. **Kali Linux Users:** Use `./install-kali.sh`
2. **Other Linux Users:** Use `./install.sh` or `python install.py`
3. **Windows Users:** Use `install.bat`
4. **All Users:** Upgrade setuptools to avoid deprecation warnings

## Support

- **Documentation:** See `KALI_LINUX_GUIDE.md` for detailed instructions
- **Troubleshooting:** See `WHEEL_INSTALLATION_GUIDE.md` for common issues
- **Issues:** Report on GitHub with system information
