@echo off
REM NjordScan Installation Script for Windows
REM Handles wheel installation issues and provides comprehensive setup

echo 🛡️  NjordScan Installation Script
echo ==================================
echo.

REM Check Python version
echo ℹ️  Checking Python version...
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python not found. Please install Python 3.8 or higher.
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo ✅ Found Python %PYTHON_VERSION%

REM Check pip version
echo ℹ️  Checking pip version...
python -m pip --version >nul 2>&1
if errorlevel 1 (
    echo ❌ pip not found. Please install pip.
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('python -m pip --version 2^>^&1') do set PIP_VERSION=%%i
echo ✅ Found pip %PIP_VERSION%

REM Install wheel if not available
echo ℹ️  Checking wheel package...
python -c "import wheel" >nul 2>&1
if errorlevel 1 (
    echo ⚠️  wheel package not found, installing...
    python -m pip install wheel
    if errorlevel 1 (
        echo ❌ Failed to install wheel package
        echo ℹ️  Trying alternative installation methods...
        echo ℹ️  Upgrading pip...
        python -m pip install --upgrade pip
        python -m pip install wheel
        if errorlevel 1 (
            echo ❌ Still failed to install wheel. Please install manually:
            echo    python -m pip install wheel
            pause
            exit /b 1
        )
    )
    echo ✅ wheel package installed successfully
) else (
    echo ✅ wheel package is already available
)

REM Install build tools
echo ℹ️  Installing build tools...
python -m pip install --upgrade setuptools wheel
echo ✅ Build tools installed

REM Install NjordScan
echo ℹ️  Installing NjordScan...
if exist "setup.py" if exist "njordscan" (
    echo ℹ️  Installing from source...
    python -m pip install -e .
) else (
    echo ℹ️  Installing from PyPI...
    python -m pip install njordscan
)
echo ✅ NjordScan installed successfully

REM Verify installation
echo ℹ️  Verifying installation...
python -c "import njordscan; print('NjordScan version:', njordscan.__version__)" >nul 2>&1
if errorlevel 1 (
    echo ❌ NjordScan installation verification failed
    pause
    exit /b 1
)
echo ✅ NjordScan installation verified

echo.
echo 🎉 Installation Complete!
echo ========================
echo.
echo 🚀 Quick Start:
echo    njordscan --help
echo    njordscan setup
echo    njordscan scan ^<target^>
echo.
echo 📚 Documentation: https://github.com/your-repo/njordscan
echo 🐛 Issues: https://github.com/your-repo/njordscan/issues
echo.
pause
