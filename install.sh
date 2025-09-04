#!/bin/bash

# NjordScan Installation Script
# Handles wheel installation issues and provides comprehensive setup

set -e  # Exit on any error

echo "🛡️  NjordScan Installation Script"
echo "=================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check Python version
check_python() {
    print_info "Checking Python version..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
    else
        print_error "Python not found. Please install Python 3.8 or higher."
        exit 1
    fi
    
    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | cut -d' ' -f2)
    print_status "Found Python $PYTHON_VERSION"
    
    # Check if version is 3.8 or higher
    if ! $PYTHON_CMD -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" 2>/dev/null; then
        print_error "Python 3.8 or higher is required. Found: $PYTHON_VERSION"
        exit 1
    fi
}

# Check pip version
check_pip() {
    print_info "Checking pip version..."
    
    if ! $PYTHON_CMD -m pip --version &> /dev/null; then
        print_error "pip not found. Please install pip."
        exit 1
    fi
    
    PIP_VERSION=$($PYTHON_CMD -m pip --version | cut -d' ' -f2)
    print_status "Found pip $PIP_VERSION"
}

# Install wheel if not available
install_wheel() {
    print_info "Checking wheel package..."
    
    if $PYTHON_CMD -c "import wheel" 2>/dev/null; then
        print_status "wheel package is already available"
    else
        print_warning "wheel package not found, installing..."
        
        if $PYTHON_CMD -m pip install wheel; then
            print_status "wheel package installed successfully"
        else
            print_error "Failed to install wheel package"
            print_info "Trying alternative installation methods..."
            
            # Try upgrading pip first
            print_info "Upgrading pip..."
            $PYTHON_CMD -m pip install --upgrade pip
            
            # Try installing wheel again
            if $PYTHON_CMD -m pip install wheel; then
                print_status "wheel package installed successfully after pip upgrade"
            else
                print_error "Still failed to install wheel. Please install manually:"
                echo "  $PYTHON_CMD -m pip install wheel"
                exit 1
            fi
        fi
    fi
}

# Install build tools
install_build_tools() {
    print_info "Installing build tools..."
    
    # Install setuptools and wheel
    $PYTHON_CMD -m pip install --upgrade setuptools wheel
    
    print_status "Build tools installed"
}

# Install NjordScan
install_njordscan() {
    print_info "Installing NjordScan..."
    
    # Check if we're in the source directory
    if [ -f "setup.py" ] && [ -d "njordscan" ]; then
        print_info "Installing from source..."
        $PYTHON_CMD -m pip install -e .
    else
        print_info "Installing from PyPI..."
        $PYTHON_CMD -m pip install njordscan
    fi
    
    print_status "NjordScan installed successfully"
}

# Verify installation
verify_installation() {
    print_info "Verifying installation..."
    
    if $PYTHON_CMD -c "import njordscan; print('NjordScan version:', njordscan.__version__)" 2>/dev/null; then
        print_status "NjordScan installation verified"
    else
        print_error "NjordScan installation verification failed"
        exit 1
    fi
}

# Main installation process
main() {
    echo "Starting NjordScan installation..."
    echo ""
    
    check_python
    check_pip
    install_wheel
    install_build_tools
    install_njordscan
    verify_installation
    
    echo ""
    echo "🎉 Installation Complete!"
    echo "========================"
    echo ""
    echo "🚀 Quick Start:"
    echo "   njordscan --help"
    echo "   njordscan setup"
    echo "   njordscan scan <target>"
    echo ""
    echo "📚 Documentation: https://github.com/your-repo/njordscan"
    echo "🐛 Issues: https://github.com/your-repo/njordscan/issues"
    echo ""
}

# Run main function
main "$@"
