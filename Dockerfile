# ============================================================================
# NjordScan Docker Container
# Security Scanner for Next.js, React, and Vite Applications
# ============================================================================

# Use Python 3.11 slim as base image for smaller size
FROM python:3.11-slim as builder

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies needed for building Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    libffi-dev \
    libssl-dev \
    gcc \
    g++ \
    # AI/ML dependencies
    python3-dev \
    python3-numpy \
    python3-scipy \
    python3-sklearn \
    # Additional dependencies for AI detection
    libblas-dev \
    liblapack-dev \
    libatlas-base-dev \
    && rm -rf /var/lib/apt/lists/*

# Create and set working directory
WORKDIR /app

# Copy requirements first for better Docker layer caching
COPY requirements.txt pyproject.toml setup.py ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . .

# Install NjordScan in development mode
RUN pip install -e .

# ============================================================================
# Runtime stage - minimal image
# ============================================================================
FROM python:3.11-slim as runtime

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.local/bin:$PATH" \
    HOME="/home/njordscan"

# Install only runtime system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2 \
    libxslt1.1 \
    libffi8 \
    libssl3 \
    curl \
    git \
    # AI/ML runtime dependencies
    python3-numpy \
    python3-scipy \
    python3-sklearn \
    # Additional runtime dependencies
    libblas3 \
    liblapack3 \
    libatlas3-base \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd -r njordscan && useradd -r -g njordscan -m -d /home/njordscan njordscan

# Create app directory and set permissions
WORKDIR /app
RUN chown -R njordscan:njordscan /app

# Copy Python packages from builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy NjordScan application
COPY --from=builder /app/njordscan /app/njordscan
COPY --from=builder /app/setup.py /app/setup.py
COPY --from=builder /app/pyproject.toml /app/pyproject.toml

# Install NjordScan
RUN pip install -e /app

# Create directories for cache and output
RUN mkdir -p /app/cache /app/output /workspace /home/njordscan/.njordscan && \
    chown -R njordscan:njordscan /app/cache /app/output /workspace /home/njordscan

# Switch to non-root user
USER njordscan

# Set working directory to workspace (where files will be mounted)
WORKDIR /workspace

# Create entrypoint script
RUN echo '#!/bin/bash\n\
# NjordScan Docker Entrypoint\n\
# Default command if no arguments provided\n\
if [ $# -eq 0 ]; then\n\
    echo "🛡️  NjordScan - Ultimate Security Scanner"\n\
    echo "Usage: docker run -v \$(pwd):/workspace njordscan [COMMAND] [OPTIONS]"\n\
    echo ""\n\
    echo "Examples:"\n\
    echo "  docker run -v \$(pwd):/workspace njordscan scan /workspace"\n\
    echo "  docker run -v \$(pwd):/workspace njordscan scan /workspace --mode deep --format html"\n\
    echo "  docker run -v \$(pwd):/workspace njordscan --help"\n\
    echo ""\n\
    echo "For more information, visit: https://github.com/nimdy/njordscan"\n\
    exit 0\n\
fi\n\
\n\
# Execute NjordScan with provided arguments\n\
exec njordscan "$@"' > /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command
CMD ["--help"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD njordscan --version || exit 1

# Labels for metadata
LABEL maintainer="NjordScan Team" \
      version="1.0.0" \
      description="Ultimate Security Scanner for Next.js, React, and Vite Applications" \
      org.opencontainers.image.title="NjordScan" \
      org.opencontainers.image.description="Security Scanner for Modern Web Applications" \
      org.opencontainers.image.url="https://github.com/nimdy/njordscan" \
      org.opencontainers.image.source="https://github.com/nimdy/njordscan" \
      org.opencontainers.image.version="1.0.0"
