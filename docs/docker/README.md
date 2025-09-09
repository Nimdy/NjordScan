# 🐳 NjordScan Docker Guide

This guide explains how to use NjordScan with Docker containers for easy, consistent security scanning.

## 🚀 Quick Start

### Prerequisites
- Docker installed on your system
- Basic understanding of Docker volumes

### Basic Usage

```bash
# Scan current directory
docker run -v $(pwd):/workspace njordscan scan /workspace

# Scan with specific options
docker run -v $(pwd):/workspace njordscan scan /workspace --mode deep --format html --output /workspace/report.html
```

## 📦 Docker Images

### Available Images
- `njordscan:latest` - Stable release
- `njordscan:dev` - Development version
- `njordscan:test` - Testing version

### Building Images

```bash
# Build latest image
docker build -t njordscan:latest .

# Build development image
docker build --target builder -t njordscan:dev .

# Build with specific tag
docker build -t njordscan:v1.0.0 .
```

## 🔧 Docker Compose

### Using Docker Compose

```bash
# Basic scanning
docker-compose run --rm njordscan scan /workspace

# Deep scan with HTML output
docker-compose run --rm njordscan scan /workspace --mode deep --format html --output /app/output/report.html

# Interactive development
docker-compose run --rm njordscan-dev bash

# Run tests
docker-compose run --rm njordscan-test
```

### Docker Compose Services

- **njordscan** - Production scanning service
- **njordscan-dev** - Development environment
- **njordscan-test** - Testing environment

## 📁 Volume Mounting

### Directory Structure
```
/workspace    - Your project files (read-only)
/app/output   - Generated reports
/app/cache    - Scan cache for performance
```

### Mount Examples

```bash
# Mount current directory
docker run -v $(pwd):/workspace njordscan scan /workspace

# Mount specific directory
docker run -v /path/to/project:/workspace njordscan scan /workspace

# Mount with output directory
docker run -v $(pwd):/workspace -v $(pwd)/reports:/app/output njordscan scan /workspace --output /app/output/report.html

# Mount with cache for performance
docker run -v $(pwd):/workspace -v $(pwd)/.njordscan-cache:/app/cache njordscan scan /workspace
```

## 🛠️ Advanced Usage

### Environment Variables

```bash
# Set cache directory
docker run -e NJORDSCAN_CACHE_DIR=/app/cache -v $(pwd):/workspace njordscan scan /workspace

# Set output directory
docker run -e NJORDSCAN_OUTPUT_DIR=/app/output -v $(pwd):/workspace njordscan scan /workspace
```

### Custom Configuration

```bash
# Mount configuration file
docker run -v $(pwd):/workspace -v $(pwd)/.njordscan.json:/workspace/.njordscan.json njordscan scan /workspace
```

### Interactive Mode

```bash
# Get shell access
docker run -it -v $(pwd):/workspace njordscan bash

# Run specific commands
docker run -it -v $(pwd):/workspace njordscan njordscan --help
```

## 🔒 Security Considerations

### File Permissions
- Container runs as non-root user (`njordscan`)
- Output files maintain proper permissions
- Use `--user` flag if needed: `docker run --user $(id -u):$(id -g) ...`

### Network Access
- Container has internet access by default
- Use `--network none` for offline scanning
- Use `--network host` for local network access

### Resource Limits

```bash
# Limit memory usage
docker run --memory=2g -v $(pwd):/workspace njordscan scan /workspace

# Limit CPU usage
docker run --cpus=2 -v $(pwd):/workspace njordscan scan /workspace
```

## 🚀 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run NjordScan
        run: |
          docker run -v ${{ github.workspace }}:/workspace \
            njordscan scan /workspace --mode standard --format json \
            --output /workspace/security-report.json
      - name: Upload Security Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.json
```

### GitLab CI

```yaml
security-scan:
  stage: test
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker run -v $(pwd):/workspace njordscan scan /workspace --mode standard
  artifacts:
    reports:
      junit: security-report.xml
```

## 🐛 Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Fix file permissions
docker run --user $(id -u):$(id -g) -v $(pwd):/workspace njordscan scan /workspace
```

#### Out of Space
```bash
# Clean up Docker
docker system prune -a
docker volume prune
```

#### Slow Performance
```bash
# Use cache volume
docker run -v $(pwd):/workspace -v njordscan-cache:/app/cache njordscan scan /workspace
```

### Debug Mode

```bash
# Enable verbose output
docker run -v $(pwd):/workspace njordscan scan /workspace --verbose

# Check container logs
docker logs <container_id>
```

## 📚 Examples

### Scan Next.js Project
```bash
docker run -v $(pwd):/workspace njordscan scan /workspace --framework nextjs --mode deep
```

### Generate Multiple Reports
```bash
docker run -v $(pwd):/workspace njordscan scan /workspace \
  --format json --output /workspace/report.json \
  --format html --output /workspace/report.html
```

### Scan with Custom Rules
```bash
docker run -v $(pwd):/workspace -v $(pwd)/custom-rules:/workspace/custom-rules \
  njordscan scan /workspace --rules /workspace/custom-rules
```

## 🤝 Contributing

### Development Setup

```bash
# Clone repository
git clone https://github.com/nimdy/njordscan.git
cd njordscan

# Build development image
docker-compose build njordscan-dev

# Start development environment
docker-compose run --rm njordscan-dev bash
```

### Testing

```bash
# Run tests in container
docker-compose run --rm njordscan-test

# Run specific test
docker-compose run --rm njordscan-test python -m pytest tests/test_scanner.py -v
```

---

For more information, visit the [main documentation](../README.md) or [GitHub repository](https://github.com/nimdy/njordscan).
