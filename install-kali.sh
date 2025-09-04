#!/bin/bash

# NjordScan Installation Script for Kali Linux
# Handles Kali-specific dependencies and wheel installation issues

set -e  # Exit on any error

echo "🛡️  NjordScan Installation Script for Kali Linux"
echo "================================================="
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

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. Consider using a non-root user for security."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Update package lists
update_packages() {
    print_info "Updating package lists..."
    sudo apt update
    print_status "Package lists updated"
}

# Install system dependencies
install_system_deps() {
    print_info "Installing system dependencies for Kali Linux..."
    
    # Essential build tools
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
    
    print_status "System dependencies installed"
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

# Install wheel and build tools
install_build_tools() {
    print_info "Installing build tools and wheel..."
    
    # Upgrade pip first
    $PYTHON_CMD -m pip install --upgrade pip
    
    # Install essential build tools
    $PYTHON_CMD -m pip install --upgrade setuptools wheel
    
    # Install additional build dependencies
    $PYTHON_CMD -m pip install --upgrade \
        cython \
        numpy \
        lxml \
        beautifulsoup4
    
    print_status "Build tools installed"
}

# Create virtual environment
create_venv() {
    print_info "Creating virtual environment..."
    
    VENV_DIR="njordscan-env"
    
    if [ -d "$VENV_DIR" ]; then
        print_warning "Virtual environment already exists. Removing..."
        rm -rf "$VENV_DIR"
    fi
    
    $PYTHON_CMD -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"
    
    # Upgrade pip in virtual environment
    pip install --upgrade pip setuptools wheel
    
    print_status "Virtual environment created and activated"
}

# Install NjordScan
install_njordscan() {
    print_info "Installing NjordScan..."
    
    # Check if we're in the source directory
    if [ -f "setup.py" ] && [ -d "njordscan" ]; then
        print_info "Installing from source..."
        pip install -e .
    else
        print_info "Installing from PyPI..."
        pip install njordscan
    fi
    
    print_status "NjordScan installed successfully"
}

# Verify installation
verify_installation() {
    print_info "Verifying installation..."
    
    if python -c "import njordscan; print('NjordScan version:', njordscan.__version__)" 2>/dev/null; then
        print_status "NjordScan installation verified"
    else
        print_error "NjordScan installation verification failed"
        exit 1
    fi
}

# Create activation script
create_activation_script() {
    print_info "Creating activation script..."
    
    cat > activate-njordscan.sh << 'EOF'
#!/bin/bash
# NjordScan Environment Activation Script

echo "🛡️  Activating NjordScan Environment"
echo "===================================="

if [ -d "njordscan-env" ]; then
    source njordscan-env/bin/activate
    echo "✅ NjordScan environment activated"
    echo "🚀 You can now use: njordscan --help"
    echo "💡 To deactivate, run: deactivate"
else
    echo "❌ NjordScan environment not found"
    echo "Run ./install-kali.sh first"
fi
EOF
    
    chmod +x activate-njordscan.sh
    print_status "Activation script created: ./activate-njordscan.sh"
}

# Main installation process
main() {
    echo "Starting NjordScan installation for Kali Linux..."
    echo ""
    
    check_root
    update_packages
    install_system_deps
    check_python
    check_pip
    install_build_tools
    create_venv
    install_njordscan
    verify_installation
    create_activation_script
    
    echo ""
    echo "🎉 Installation Complete!"
    echo "========================"
    echo ""
    echo "🚀 To use NjordScan:"
    echo "   source activate-njordscan.sh"
    echo "   njordscan --help"
    echo "   njordscan scan <target>"
    echo ""
    echo "💡 To deactivate the environment:"
    echo "   deactivate"
    echo ""
    echo "📚 Documentation: https://github.com/your-repo/njordscan"
    echo "🐛 Issues: https://github.com/your-repo/njordscan/issues"
    echo ""
}

# Run main function
main "$@"
