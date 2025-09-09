#!/bin/bash
# ============================================================================
# Docker Build Script for NjordScan
# Builds and tests Docker images for NjordScan
# ============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
IMAGE_NAME="njordscan"
TAG="latest"
BUILD_TYPE="production"
CLEAN=false
TEST=false
PUSH=false

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -n, --name NAME      Image name (default: njordscan)"
    echo "  -t, --tag TAG        Image tag (default: latest)"
    echo "  -b, --build TYPE     Build type: production|dev|test (default: production)"
    echo "  -c, --clean          Clean up before building"
    echo "  -T, --test           Run tests after building"
    echo "  -p, --push           Push image to registry (not implemented yet)"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Build production image"
    echo "  $0 -t v1.0.0 -T                      # Build with tag and test"
    echo "  $0 -b dev -c                         # Build dev image with cleanup"
    echo "  $0 -n my-njordscan -t latest -T      # Build with custom name and test"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--name)
            IMAGE_NAME="$2"
            shift 2
            ;;
        -t|--tag)
            TAG="$2"
            shift 2
            ;;
        -b|--build)
            BUILD_TYPE="$2"
            shift 2
            ;;
        -c|--clean)
            CLEAN=true
            shift
            ;;
        -T|--test)
            TEST=true
            shift
            ;;
        -p|--push)
            PUSH=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate build type
if [[ ! "$BUILD_TYPE" =~ ^(production|dev|test)$ ]]; then
    print_error "Invalid build type: $BUILD_TYPE. Must be one of: production, dev, test"
    exit 1
fi

# Set full image name
FULL_IMAGE_NAME="${IMAGE_NAME}:${TAG}"

print_status "Building NjordScan Docker image..."
print_status "Image: $FULL_IMAGE_NAME"
print_status "Build Type: $BUILD_TYPE"

# Clean up if requested
if [ "$CLEAN" = true ]; then
    print_status "Cleaning up Docker resources..."
    docker system prune -f
    docker builder prune -f
fi

# Build the image
print_status "Building Docker image..."

case $BUILD_TYPE in
    production)
        docker build -t "$FULL_IMAGE_NAME" .
        ;;
    dev)
        docker build --target builder -t "$FULL_IMAGE_NAME" .
        ;;
    test)
        docker build -t "$FULL_IMAGE_NAME" .
        ;;
esac

if [ $? -eq 0 ]; then
    print_success "Docker image built successfully: $FULL_IMAGE_NAME"
else
    print_error "Failed to build Docker image"
    exit 1
fi

# Run tests if requested
if [ "$TEST" = true ]; then
    print_status "Running tests..."
    
    # Test basic functionality
    print_status "Testing basic functionality..."
    docker run --rm "$FULL_IMAGE_NAME" version
    
    if [ $? -eq 0 ]; then
        print_success "Version test passed"
    else
        print_error "Version test failed"
        exit 1
    fi
    
    # Test help command
    print_status "Testing help command..."
    docker run --rm "$FULL_IMAGE_NAME" --help > /dev/null
    
    if [ $? -eq 0 ]; then
        print_success "Help test passed"
    else
        print_error "Help test failed"
        exit 1
    fi
    
    # Test scan command with help
    print_status "Testing scan command..."
    docker run --rm "$FULL_IMAGE_NAME" scan --help > /dev/null
    
    if [ $? -eq 0 ]; then
        print_success "Scan command test passed"
    else
        print_error "Scan command test failed"
        exit 1
    fi
    
    print_success "All tests passed!"
fi

# Show image information
print_status "Image information:"
docker images "$IMAGE_NAME" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"

# Show usage examples
print_status "Usage examples:"
echo "  # Basic scan"
echo "  docker run -v \$(pwd):/workspace $FULL_IMAGE_NAME scan /workspace"
echo ""
echo "  # Deep scan with HTML output"
echo "  docker run -v \$(pwd):/workspace $FULL_IMAGE_NAME scan /workspace --mode deep --format html --output /workspace/report.html"
echo ""
echo "  # Interactive mode"
echo "  docker run -it -v \$(pwd):/workspace $FULL_IMAGE_NAME bash"

# Push if requested (not implemented yet)
if [ "$PUSH" = true ]; then
    print_warning "Push functionality not implemented yet"
    print_status "To push manually: docker push $FULL_IMAGE_NAME"
fi

print_success "Build completed successfully!"
