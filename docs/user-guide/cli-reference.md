# 📋 CLI Command Reference

Complete reference for all NjordScan command-line interface commands and options.

---

## 🎯 **Main Commands**

### `njordscan scan [TARGET] [OPTIONS]`

**Description**: Run security analysis on target application

**Arguments**:
- `TARGET` (optional): Path to project directory or URL to scan
  - **Default**: Current directory (`.`)
  - **Examples**: `/path/to/project`, `https://example.com`, `./my-app`

### `njordscan [COMMAND] [OPTIONS]`

**Description**: Access various NjordScan features and utilities

---

## 🔍 **Core Scanning Commands**

### **Basic Scanning**
```bash
# Scan current directory
njordscan scan

# Scan specific directory
njordscan scan /path/to/project

# Scan remote URL
njordscan scan https://example.com

# Interactive mode (basic implementation)
njordscan scan --interactive
```

### **Scan Modes**
```bash
# Quick scan - Fast analysis with basic modules
njordscan scan --mode quick

# Standard scan (default) - Comprehensive analysis with AI enhancement
njordscan scan --mode standard

# Deep scan - Thorough analysis with enhanced behavioral analysis
njordscan scan --mode deep

# Enterprise scan - Full analysis with all advanced features
njordscan scan --mode enterprise
```

### **Framework-Specific Scanning**
```bash
# Force framework detection
njordscan scan --framework nextjs
njordscan scan --framework react
njordscan scan --framework vite

# Auto-detect framework (default)
njordscan scan --framework auto
```

---

## 🛠️ **Available Commands**

### **Core Commands**
```bash
# Main scanning command
njordscan scan [TARGET] [OPTIONS]

# System diagnostics
njordscan doctor

# Version information
njordscan version

# Update vulnerability database
njordscan update [OPTIONS]
```

### **Configuration Commands**
```bash
# Interactive setup wizard
njordscan setup [OPTIONS]

# Configuration management
njordscan configure [OPTIONS]
```

### **Utility Commands**
```bash
# Explain vulnerability
njordscan explain [VULN_ID]

# Cache management
njordscan cache [COMMAND]

# Plugin management
njordscan plugins [ACTION] [OPTIONS]

# Community features
njordscan community [ACTION] [OPTIONS]
```

---

## 🎨 **User Interface Options**

### **Themes** (Basic Implementation)
```bash
# Available themes (limited implementation)
njordscan scan --theme default
njordscan scan --theme dark
njordscan scan --theme cyberpunk
njordscan scan --theme hacker
njordscan scan --theme professional
```

### **Output Control**
```bash
# Verbose output
njordscan scan --verbose
njordscan scan -v

# Quiet mode (errors only)
njordscan scan --quiet
njordscan scan -q

# Output format
njordscan scan --format terminal
njordscan scan --format json
njordscan scan --format html
njordscan scan --format sarif
```

### **Interactive Features** (Basic Implementation)
```bash
# Interactive mode (basic)
njordscan scan --interactive

# Non-interactive (CI/CD mode)
njordscan scan --ci

# Interactive results browser (basic)
njordscan results

# Interactive configuration (basic)
njordscan configure
```

---

## 🧠 **AI & Intelligence Options** (Limited Implementation)

### **AI Features** (Basic Implementation)
```bash
# Enable AI-enhanced analysis (basic)
njordscan --ai-enhanced

# Enable behavioral analysis (basic)
njordscan --behavioral-analysis

# Enable threat intelligence (basic)
njordscan --threat-intel

# Use community rules (not implemented)
njordscan --community-rules

# Custom rules (basic)
njordscan --custom-rules

# False positive filtering (basic)
njordscan --false-positive-filter
```

**Note**: AI features are in early development. Most advanced AI capabilities are not yet fully implemented.

---

## 🔧 **Module Control**

### **Enable/Disable Modules**
```bash
# Skip specific modules
njordscan --skip runtime,configs

# Run only specific modules
njordscan --only headers,static,dependencies

# Enhanced scanner with advanced features
njordscan --enhanced
```

### **Available Modules**
- **headers** - HTTP security headers analysis
- **static** - Static code analysis
- **dependencies** - Dependency vulnerability scanning
- **configs** - Configuration security analysis
- **runtime** - Runtime security testing
- **ai** - AI-powered analysis (basic)

---

## ⚡ **Performance Options**

### **Threading & Parallelism**
```bash
# Set number of threads
njordscan --threads 8

# Auto-detect optimal threads
njordscan --threads auto

# Single-threaded mode
njordscan --threads 1
```

### **Caching**
```bash
# Cache strategies
njordscan --cache-strategy off
njordscan --cache-strategy basic
njordscan --cache-strategy intelligent
njordscan --cache-strategy aggressive

# Clear cache
njordscan cache clear

# Cache statistics
njordscan cache stats
```

### **Resource Limits**
```bash
# Memory limit (MB)
njordscan --memory-limit 2048

# Scan timeout (seconds)
njordscan --timeout 600

# Request timeout (seconds)
njordscan --request-timeout 30
```

---

## 📊 **Output & Reporting**

### **Output Formats**
```bash
# Terminal output (default)
njordscan --format terminal

# HTML report
njordscan --format html --output report.html

# JSON output
njordscan --format json --output results.json

# SARIF for GitHub
njordscan --format sarif --output results.sarif

# Multiple formats
njordscan --format html,json,sarif
```

### **Report Options**
```bash
# Include executive summary
njordscan --executive-summary

# Include remediation guidance
njordscan --include-remediation

# Include false positives
njordscan --include-false-positives

# Custom report template
njordscan --template custom-template.j2
```

### **Output Filtering**
```bash
# Minimum severity level
njordscan --severity critical
njordscan --severity high
njordscan --severity medium
njordscan --severity low

# Specific vulnerability types
njordscan --types xss,sql-injection,csrf

# Exclude patterns
njordscan --exclude "test/**" --exclude "node_modules/**"
```

---

## 🔄 **CI/CD Integration**

### **CI/CD Mode**
```bash
# Non-interactive CI mode
njordscan --ci

# Fail build on severity
njordscan --fail-on critical
njordscan --fail-on high

# Exit codes for automation
njordscan --exit-code-on-findings
```

### **Quality Gates**
```bash
# Use quality gate policy
njordscan --quality-gate policy.yaml

# Maximum allowed issues
njordscan --max-critical 0 --max-high 5

# Trend comparison
njordscan --compare-with previous-results.json
```

### **Integration Options**
```bash
# GitHub Actions integration
njordscan --github-token $GITHUB_TOKEN

# GitLab CI integration
njordscan --gitlab-token $GITLAB_TOKEN

# SARIF upload
njordscan --upload-sarif --github-repository owner/repo
```

---

## 🛠️ **Configuration Commands**

### **Setup & Configuration**
```bash
# Interactive setup wizard
njordscan setup

# Setup for specific IDE
njordscan setup --ide vscode
njordscan setup --ide intellij
njordscan setup --ide vim

# Setup CI/CD integration
njordscan setup --ci github
njordscan setup --ci gitlab
njordscan setup --ci jenkins
```

### **Configuration Management**
```bash
# Interactive configuration
njordscan configure

# Generate config template
njordscan config init --framework nextjs

# Validate configuration
njordscan config validate

# Show current configuration
njordscan config show

# Export configuration
njordscan config export --output my-config.json
```

---

## 🔌 **Plugin Management**

### **Plugin Commands**
```bash
# List installed plugins
njordscan plugins list

# Browse available plugins
njordscan plugins browse

# Install plugin
njordscan plugins install plugin-name

# Update plugins
njordscan plugins update

# Remove plugin
njordscan plugins remove plugin-name
```

### **Plugin Development**
```bash
# Create new plugin
njordscan plugins create --template scanner --name my-plugin

# Validate plugin
njordscan plugins validate my-plugin

# Test plugin
njordscan plugins test my-plugin

# Publish plugin
njordscan plugins publish my-plugin
```

---

## 🌟 **Community Features** (Not Implemented)

**Note**: Community features are planned for future releases but are not currently implemented.

### **Planned Community Commands**
```bash
# These commands are not yet available
njordscan community register
njordscan community browse
njordscan community challenges
```

---

## 🎓 **Learning & Help**

### **Educational Commands** (Basic Implementation)
```bash
# Interactive tutorials (basic)
njordscan learn

# Framework-specific guides (basic)
njordscan guide --framework nextjs

# Explain vulnerability (basic)
njordscan explain NJORD-XSS-001

# Security best practices (basic)
njordscan best-practices --framework react
```

### **Help Commands**
```bash
# Show help
njordscan --help

# Show version
njordscan version

# System diagnostics
njordscan doctor
```

---

## 🔍 **Results & Analysis**

### **Results Management** (Basic Implementation)
```bash
# Browse results interactively (basic)
njordscan results

# List recent scans (basic)
njordscan results --list
```

### **Fix Management** (Basic Implementation)
```bash
# Interactive fix mode (basic)
njordscan fix --interactive

# Fix specific issue (basic)
njordscan fix --issue NJORD-XSS-001
```

**Note**: Advanced result analysis and fix management features are in development.

---

## 🔧 **System Commands**

### **Maintenance** (Basic Implementation)
```bash
# Check for updates
njordscan update --check

# System diagnostics
njordscan doctor
```

### **Information Commands**
```bash
# Show version
njordscan --version
njordscan version

# Show system info (basic)
njordscan info
```

**Note**: Advanced system maintenance commands are in development.

---

## 🎯 **Usage Examples**

### **Basic Scanning**
```bash
# Scan current directory
njordscan

# Scan with specific framework
njordscan --framework nextjs

# Quick scan for development
njordscan --mode quick --skip runtime
```

### **CI/CD Pipeline** (Basic)
```bash
# Basic CI/CD usage
njordscan --ci \
  --mode standard \
  --format json \
  --output results.json \
  --fail-on high
```

### **Development Workflow**
```bash
# Development scan with progress
njordscan --mode quick \
  --show-progress \
  --skip runtime \
  --format terminal
```

### **Comprehensive Scan**
```bash
# Deep scan with all modules
njordscan --mode deep \
  --enhanced \
  --format html \
  --output security-report.html
```

---

## 📋 **Environment Variables**

### **Configuration** (Basic)
```bash
# Default configuration file
export NJORDSCAN_CONFIG=/path/to/config.json

# Default output directory
export NJORDSCAN_OUTPUT_DIR=/path/to/reports
```

### **Performance** (Basic)
```bash
# Default thread count
export NJORDSCAN_THREADS=8

# Default timeout (seconds)
export NJORDSCAN_TIMEOUT=600
```

**Note**: Most environment variables are not yet implemented. Basic configuration is handled through command-line options.

---

## 🚨 **Exit Codes** (Basic Implementation)

| Code | Meaning |
|------|---------|
| `0` | Success, no security issues found |
| `1` | General error or invalid usage |
| `2` | Security issues found |

### **Exit Code Usage** (Basic)
```bash
# Check exit code in scripts
njordscan --ci
exit_code=$?

if [ $exit_code -eq 0 ]; then
    echo "No security issues found"
else
    echo "Security issues found or error occurred"
    exit 1
fi
```

**Note**: Advanced exit code handling is in development.

---

## 💡 **Tips & Best Practices**

### **Performance Tips**
- Use `--mode quick` for fast feedback in development
- Enable `--skip runtime` when not testing live applications
- Use `--threads` to control parallel processing

### **Accuracy Tips**
- Always specify `--framework` for better detection
- Use `--enhanced` for advanced analysis
- Enable `--custom-rules` for additional security patterns

### **Automation Tips**
- Use `--ci` mode for non-interactive environments
- Set appropriate `--fail-on` levels for your security policy
- Use `--format json` for programmatic processing

### **Development Tips**
- Use `--interactive` mode for learning (basic)
- Enable `--show-progress` for long scans
- Use `--verbose` for detailed output

---

<div align="center">

## 🛡️ **Master the CLI, Master Security!**

**With these commands, you have control over NjordScan's security analysis capabilities.**

[**🚀 Quick Start**](../getting-started/quick-start.md) | [**🛡️ Security Features**](../security/vulnerability-types.md) | [**🔌 Plugins**](../plugins/overview.md) | [**💬 Get Help**](https://discord.gg/njordscan)

</div>
