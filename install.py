#!/usr/bin/env python3
"""
NjordScan Installation Script
Handles wheel installation issues and provides comprehensive setup
"""

import sys
import subprocess
import os
import platform
from pathlib import Path

def print_status(message):
    """Print success message."""
    print(f"✅ {message}")

def print_warning(message):
    """Print warning message."""
    print(f"⚠️  {message}")

def print_error(message):
    """Print error message."""
    print(f"❌ {message}")

def print_info(message):
    """Print info message."""
    print(f"ℹ️  {message}")

def check_python_version():
    """Check if Python version is compatible."""
    print_info("Checking Python version...")
    
    if sys.version_info < (3, 8):
        print_error(f"Python 3.8 or higher is required. Found: {sys.version}")
        sys.exit(1)
    
    print_status(f"Python {sys.version.split()[0]} is compatible")

def check_pip():
    """Check if pip is available."""
    print_info("Checking pip...")
    
    try:
        result = subprocess.run([sys.executable, "-m", "pip", "--version"], 
                              capture_output=True, text=True, check=True)
        pip_version = result.stdout.split()[1]
        print_status(f"Found pip {pip_version}")
    except subprocess.CalledProcessError:
        print_error("pip not found. Please install pip.")
        sys.exit(1)

def install_wheel():
    """Install wheel package if not available."""
    print_info("Checking wheel package...")
    
    try:
        import wheel
        print_status("wheel package is already available")
    except ImportError:
        print_warning("wheel package not found, installing...")
        
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "wheel"], 
                          check=True)
            print_status("wheel package installed successfully")
        except subprocess.CalledProcessError:
            print_error("Failed to install wheel package")
            print_info("Trying alternative installation methods...")
            
            # Try upgrading pip first
            print_info("Upgrading pip...")
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], 
                              check=True)
                
                # Try installing wheel again
                subprocess.run([sys.executable, "-m", "pip", "install", "wheel"], 
                              check=True)
                print_status("wheel package installed successfully after pip upgrade")
            except subprocess.CalledProcessError:
                print_error("Still failed to install wheel. Please install manually:")
                print("  python -m pip install wheel")
                sys.exit(1)

def install_build_tools():
    """Install build tools."""
    print_info("Installing build tools...")
    
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", 
                       "setuptools", "wheel"], check=True)
        print_status("Build tools installed")
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to install build tools: {e}")
        sys.exit(1)

def install_njordscan():
    """Install NjordScan."""
    print_info("Installing NjordScan...")
    
    # Check if we're in the source directory
    if Path("setup.py").exists() and Path("njordscan").exists():
        print_info("Installing from source...")
        try:
            # Try user installation first
            subprocess.run([sys.executable, "-m", "pip", "install", "--user", "-e", "."], 
                          check=True)
        except subprocess.CalledProcessError:
            print_warning("User installation failed, trying system installation...")
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", "-e", "."], 
                              check=True)
            except subprocess.CalledProcessError as e:
                print_error(f"Failed to install from source: {e}")
                print_info("Try running with sudo or use: pip install --user njordscan")
                sys.exit(1)
    else:
        print_info("Installing from PyPI...")
        try:
            # Try user installation first
            subprocess.run([sys.executable, "-m", "pip", "install", "--user", "njordscan"], 
                          check=True)
        except subprocess.CalledProcessError:
            print_warning("User installation failed, trying system installation...")
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", "njordscan"], 
                              check=True)
            except subprocess.CalledProcessError as e:
                print_error(f"Failed to install from PyPI: {e}")
                print_info("Try running with sudo or use: pip install --user njordscan")
                sys.exit(1)
    
    print_status("NjordScan installed successfully")

def verify_installation():
    """Verify the installation."""
    print_info("Verifying installation...")
    
    try:
        import njordscan
        version = getattr(njordscan, '__version__', 'unknown')
        print_status(f"NjordScan {version} installation verified")
    except ImportError:
        print_error("NjordScan installation verification failed")
        sys.exit(1)

def main():
    """Main installation process."""
    print("🛡️  NjordScan Installation Script")
    print("==================================")
    print()
    
    check_python_version()
    check_pip()
    install_wheel()
    install_build_tools()
    install_njordscan()
    verify_installation()
    
    print()
    print("🎉 Installation Complete!")
    print("========================")
    print()
    print("🚀 Quick Start:")
    print("   njordscan --help")
    print("   njordscan setup")
    print("   njordscan scan <target>")
    print()
    print("📚 Documentation: https://github.com/your-repo/njordscan")
    print("🐛 Issues: https://github.com/your-repo/njordscan/issues")
    print()

if __name__ == "__main__":
    main()
