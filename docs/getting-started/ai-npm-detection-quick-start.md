# 🚀 AI NPM Attack Detection - Quick Start

> **Get started with NjordScan's AI-powered npm attack detection in minutes**

## 🎯 What You'll Learn

In this guide, you'll learn how to:
- Enable AI NPM attack detection
- Scan for different types of threats
- Interpret detection results
- Configure detection settings
- Use advanced features

## ⚡ Quick Start (5 minutes)

### 1. Install NjordScan

```bash
# Install NjordScan
pip install njordscan

# Or with Docker (no installation needed)
docker pull njordscan/njordscan:latest
```

### 2. Basic AI Detection

```bash
# Enable AI NPM detection
njordscan scan . --ai-npm-detection

# Scan with all AI features
njordscan scan . --ai-enhanced
```

### 3. View Results

```bash
# Generate HTML report
njordscan scan . --ai-npm-detection --format html --output report.html

# Generate JSON report
njordscan scan . --ai-npm-detection --format json --output report.json
```

## 🔍 Detection Types

### Typosquatting Detection

Detects packages with similar names that could confuse users.

```bash
# Detect typosquatting
njordscan scan . --typosquatting

# Check specific package
njordscan scan-package react-dom-router --typosquatting-check
```

**Example Output:**
```
🔍 Typosquatting Detection: HIGH RISK
   - react-dom-router (similarity: 0.95)
   - Risk: High similarity to react-router-dom
```

### Dependency Confusion Detection

Detects scoped vs unscoped package confusion.

```bash
# Detect dependency confusion
njordscan scan . --dependency-confusion

# Check for @babel/core confusion
njordscan scan-package babel --dependency-confusion-check
```

**Example Output:**
```
🎯 Dependency Confusion: CRITICAL RISK
   - @babel/core confusion detected
   - Risk: Exact name match with scoped package
```

### AI-Generated Malware Detection

Detects packages created by AI tools for malicious purposes.

```bash
# Detect AI-generated malware
njordscan scan . --ai-generated-malware

# With confidence threshold
njordscan scan . --ai-generated-malware --confidence-threshold 0.8
```

**Example Output:**
```
🤖 AI-Generated Malware: HIGH RISK
   - Confidence: 85%
   - Patterns: Repetitive code, generic functions
```

### Crypto Wallet Targeting

Detects packages designed to steal cryptocurrency.

```bash
# Detect crypto targeting
njordscan scan . --crypto-targeting

# Check for ethereum targeting
njordscan scan . --ethereum-targeting
```

**Example Output:**
```
🔐 Crypto Targeting: HIGH RISK
   - Score: 75%
   - Patterns: Ethereum access, wallet connection
```

### Data Exfiltration Detection

Detects packages attempting to steal sensitive data.

```bash
# Detect data exfiltration
njordscan scan . --data-exfiltration

# Monitor network requests
njordscan scan . --network-monitoring
```

**Example Output:**
```
📊 Data Exfiltration: HIGH RISK
   - Score: 80%
   - Patterns: User agent collection, cookie harvesting
```

### Obfuscation Detection

Detects obfuscated malicious code.

```bash
# Detect obfuscated code
njordscan scan . --obfuscation-detection

# Check for string obfuscation
njordscan scan . --string-obfuscation
```

**Example Output:**
```
🛡️ Obfuscation: CRITICAL RISK
   - Score: 90%
   - Patterns: String obfuscation, eval usage
```

### Maintainer Profile Analysis

Analyzes maintainer patterns for suspicious behavior.

```bash
# Analyze maintainer profiles
njordscan scan . --maintainer-analysis

# Check for suspicious maintainers
njordscan scan . --suspicious-maintainer
```

**Example Output:**
```
👤 Maintainer Analysis: MEDIUM RISK
   - Patterns: New maintainer, suspicious email
   - Confidence: 60%
```

## ⚙️ Configuration

### Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--ai-npm-detection` | Enable all AI NPM detection | `--ai-npm-detection` |
| `--typosquatting` | Enable typosquatting detection | `--typosquatting` |
| `--dependency-confusion` | Enable dependency confusion detection | `--dependency-confusion` |
| `--ai-generated-malware` | Enable AI-generated malware detection | `--ai-generated-malware` |
| `--crypto-targeting` | Enable crypto wallet targeting detection | `--crypto-targeting` |
| `--data-exfiltration` | Enable data exfiltration detection | `--data-exfiltration` |
| `--obfuscation-detection` | Enable obfuscation detection | `--obfuscation-detection` |
| `--maintainer-analysis` | Enable maintainer profile analysis | `--maintainer-analysis` |
| `--similarity-threshold` | Set similarity threshold (0.0-1.0) | `--similarity-threshold 0.9` |
| `--confidence-threshold` | Set confidence threshold (0.0-1.0) | `--confidence-threshold 0.8` |

### Configuration File

Create a `njordscan.yaml` file in your project root:

```yaml
ai_npm_detection:
  enabled: true
  typosquatting:
    enabled: true
    threshold: 0.9
  dependency_confusion:
    enabled: true
    threshold: 0.85
  ai_generated_malware:
    enabled: true
    confidence_threshold: 0.7
  crypto_targeting:
    enabled: true
    wallet_analysis: true
  data_exfiltration:
    enabled: true
    sensitive_data_check: true
  obfuscation:
    enabled: true
    complexity_analysis: true
  maintainer_analysis:
    enabled: true
    profile_check: true
    activity_analysis: true
```

## 🐳 Docker Usage

### Basic Docker Usage

```bash
# Scan with Docker
docker run -v $(pwd):/workspace njordscan scan /workspace --ai-npm-detection

# Deep AI analysis
docker run -v $(pwd):/workspace njordscan scan /workspace --mode deep --ai-enhanced

# Generate HTML report
docker run -v $(pwd):/workspace njordscan scan /workspace --ai-npm-detection --format html --output /workspace/report.html
```

### Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'
services:
  njordscan:
    image: njordscan/njordscan:latest
    volumes:
      - .:/workspace
    command: scan /workspace --ai-npm-detection --format html --output /workspace/report.html
```

Run with:
```bash
docker-compose up
```

## 📊 Understanding Results

### Risk Levels

| Level | Description | Action Required |
|-------|-------------|-----------------|
| **LOW** | Minimal risk detected | Monitor and review |
| **MEDIUM** | Moderate risk detected | Investigate and verify |
| **HIGH** | High risk detected | Immediate investigation required |
| **CRITICAL** | Critical risk detected | Immediate action required |

### Confidence Scores

| Score | Description | Reliability |
|-------|-------------|-------------|
| **0.0 - 0.3** | Low confidence | Review manually |
| **0.3 - 0.7** | Medium confidence | Investigate further |
| **0.7 - 1.0** | High confidence | Likely accurate |

### Similarity Scores

| Score | Description | Risk Level |
|-------|-------------|------------|
| **0.0 - 0.5** | Low similarity | Low risk |
| **0.5 - 0.8** | Medium similarity | Medium risk |
| **0.8 - 0.95** | High similarity | High risk |
| **0.95 - 1.0** | Very high similarity | Critical risk |

## 🧪 Testing Your Setup

### Test Commands

```bash
# Test AI detection
python -m pytest tests/test_ai_npm_detection.py -v

# Test integration
python -m pytest tests/test_ai_detection_integration.py -v

# Test performance
python -m pytest tests/test_ai_detection_performance.py -v
```

### Validate Installation

```bash
# Check NjordScan version
njordscan --version

# Check AI detection capabilities
njordscan scan --help | grep -i "ai\|npm"

# Test with sample package
njordscan scan-package react --ai-npm-detection --verbose
```

## 🚨 Common Issues

### False Positives

If you get false positives:

1. **Adjust thresholds**:
   ```bash
   njordscan scan . --similarity-threshold 0.95 --confidence-threshold 0.8
   ```

2. **Disable specific detections**:
   ```bash
   njordscan scan . --ai-npm-detection --no-typosquatting
   ```

3. **Use configuration file** to fine-tune settings

### Performance Issues

If scanning is slow:

1. **Use quick mode**:
   ```bash
   njordscan scan . --mode quick --ai-npm-detection
   ```

2. **Limit detection types**:
   ```bash
   njordscan scan . --typosquatting --dependency-confusion
   ```

3. **Use Docker** for better performance

### Memory Issues

If you run out of memory:

1. **Scan smaller directories**:
   ```bash
   njordscan scan src/ --ai-npm-detection
   ```

2. **Use Docker** with more memory:
   ```bash
   docker run -m 4g -v $(pwd):/workspace njordscan scan /workspace --ai-npm-detection
   ```

## 📚 Next Steps

### Learn More

- [**Complete AI NPM Detection Guide**](../ai-npm-detection.md) - Comprehensive documentation
- [**CLI Reference**](../user-guide/cli-reference.md) - All command-line options
- [**Configuration Guide**](../advanced/configuration.md) - Advanced configuration
- [**Troubleshooting**](../advanced/troubleshooting.md) - Common issues and solutions

### Advanced Usage

- [**API Integration**](../development/api.md) - Programmatic usage
- [**Custom Patterns**](../ai-npm-detection.md#custom-patterns) - Add custom detection patterns
- [**CI/CD Integration**](../docker/README.md) - Automated scanning
- [**Performance Tuning**](../advanced/performance.md) - Optimize for large projects

### Community

- [**GitHub Issues**](https://github.com/nimdy/njordscan/issues) - Report bugs and request features
- [**Discussions**](https://github.com/nimdy/njordscan/discussions) - Community discussions
- [**Contributing**](../../CONTRIBUTING.md) - Contribute to NjordScan

## 🎉 Congratulations!

You've successfully set up AI NPM attack detection with NjordScan! 

**What's next?**
- Run your first scan with AI detection
- Explore different detection types
- Configure settings for your needs
- Integrate into your CI/CD pipeline

**Need help?** Check out our [troubleshooting guide](../advanced/troubleshooting.md) or [join our community](https://github.com/nimdy/njordscan/discussions)!

---

**Made with ❤️ for the security community**
