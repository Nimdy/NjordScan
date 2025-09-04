#!/bin/bash

# NjordScan lxml Fix Script for Kali Linux
# Specifically addresses the "failed building wheel for lxml" error

set -e  # Exit on any error

echo "🔧 NjordScan lxml Fix Script for Kali Linux"
echo "==========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
if [[ $EUID -eq 0 ]]; then
    print_warning "Running as root. Consider using a non-root user for security."
fi

# Update package lists
print_info "Updating package lists..."
sudo apt update
print_status "Package lists updated"

# Install all lxml dependencies
print_info "Installing lxml build dependencies..."
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
    pkg-config \
    libffi-dev \
    libssl-dev

print_status "lxml dependencies installed"

# Upgrade pip and build tools
print_info "Upgrading pip and build tools..."
python3 -m pip install --upgrade pip setuptools wheel
print_status "Build tools upgraded"

# Try multiple lxml installation methods
print_info "Attempting lxml installation..."

# Method 1: Direct pip install
print_info "Method 1: Direct pip install..."
if python3 -m pip install lxml --no-cache-dir; then
    print_status "lxml installed successfully via direct pip install"
    exit 0
fi

print_warning "Method 1 failed, trying method 2..."

# Method 2: Pre-compiled wheel only
print_info "Method 2: Pre-compiled wheel only..."
if python3 -m pip install lxml --only-binary=all --no-cache-dir; then
    print_status "lxml installed successfully via pre-compiled wheel"
    exit 0
fi

print_warning "Method 2 failed, trying method 3..."

# Method 3: With static build flags
print_info "Method 3: Static build with compiler flags..."
export STATIC_DEPS=true
export STATICBUILD=true
export LDFLAGS="-L/usr/lib/x86_64-linux-gnu"
export CPPFLAGS="-I/usr/include/libxml2"
if python3 -m pip install lxml --no-cache-dir --no-binary=lxml; then
    print_status "lxml installed successfully with static build"
    exit 0
fi

print_warning "Method 3 failed, trying method 4..."

# Method 4: Install from source with specific flags
print_info "Method 4: Source build with specific flags..."
export LDFLAGS="-L/usr/lib/x86_64-linux-gnu -L/usr/lib"
export CPPFLAGS="-I/usr/include/libxml2 -I/usr/include/libxslt"
export PKG_CONFIG_PATH="/usr/lib/x86_64-linux-gnu/pkgconfig"
if python3 -m pip install lxml --no-cache-dir --no-binary=lxml --force-reinstall; then
    print_status "lxml installed successfully from source"
    exit 0
fi

print_warning "Method 4 failed, trying method 5..."

# Method 5: Alternative XML parser
print_info "Method 5: Installing alternative XML parser..."
if python3 -m pip install beautifulsoup4 html5lib --no-cache-dir; then
    print_status "Alternative XML parser installed (beautifulsoup4 + html5lib)"
    print_info "Note: NjordScan will use beautifulsoup4 instead of lxml"
    exit 0
fi

print_error "All lxml installation methods failed"
echo ""
print_info "Manual installation options:"
echo "1. Try installing lxml from your distribution's package manager:"
echo "   sudo apt install python3-lxml"
echo ""
echo "2. Use a different Python version:"
echo "   sudo apt install python3.9-dev python3.9-lxml"
echo ""
echo "3. Install in a virtual environment:"
echo "   python3 -m venv njordscan-env"
echo "   source njordscan-env/bin/activate"
echo "   pip install lxml"
echo ""
echo "4. Use conda instead of pip:"
echo "   conda install lxml"
echo ""
print_info "If none of these work, NjordScan can still function without lxml"
print_info "but some XML parsing features may be limited."

exit 1
