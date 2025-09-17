# 🤖 AI-Powered NPM Attack Detection

> **Advanced machine learning-powered detection for sophisticated npm package attacks**

## Overview

NjordScan's AI-powered NPM attack detection system uses cutting-edge machine learning algorithms to identify sophisticated threats in the npm ecosystem. This system can detect AI-generated malicious packages, typosquatting attempts, dependency confusion attacks, and other advanced supply chain threats.

## 🚀 Quick Start

### Basic Usage

```bash
# Enable AI NPM detection
njordscan scan . --ai-npm-detection

# Scan with all AI features
njordscan scan . --ai-enhanced --ai-npm-detection

# Specific threat detection
njordscan scan . --typosquatting --dependency-confusion --maintainer-analysis
```

### Docker Usage

```bash
# Scan with Docker
docker run -v $(pwd):/workspace njordscan scan /workspace --ai-npm-detection

# Deep AI analysis
docker run -v $(pwd):/workspace njordscan scan /workspace --mode deep --ai-enhanced
```

## 🔍 Detection Capabilities

### 1. AI-Generated Malware Detection

Detects packages created by AI tools for malicious purposes.

**Features:**
- Pattern recognition for AI-generated code
- Confidence scoring for AI detection
- Behavioral analysis of AI-generated packages

**Example:**
```bash
# Scan for AI-generated malware
njordscan scan . --ai-generated-malware --confidence-threshold 0.8
```

**Detection Patterns:**
- Repetitive code patterns typical of AI generation
- Unusual variable naming conventions
- Generic function structures
- Lack of human coding patterns

### 2. Typosquatting Detection

Uses ML-based similarity analysis to catch package name confusion attacks.

**Features:**
- Levenshtein distance calculation
- N-gram similarity analysis
- Visual similarity detection
- Homoglyph attack detection

**Example:**
```bash
# Detect typosquatting attempts
njordscan scan . --typosquatting --similarity-threshold 0.9

# Check specific package
njordscan scan-package react-dom-router --typosquatting-check
```

**Detection Patterns:**
- Character substitution (0/o, 1/l/I)
- Character omission or addition
- Common typo patterns
- Visual similarity with legitimate packages

### 3. Dependency Confusion Detection

Detects scoped vs unscoped package confusion attempts.

**Features:**
- Scoped package analysis
- Unscoped package comparison
- Similarity scoring
- Risk assessment

**Example:**
```bash
# Detect dependency confusion
njordscan scan . --dependency-confusion --scope-analysis

# Check for @babel/core confusion
njordscan scan-package babel --dependency-confusion-check
```

**Detection Patterns:**
- Scoped packages (@babel/core) vs unscoped (babel)
- Subdomain-style confusion
- Package name similarity analysis

### 4. Crypto Wallet Targeting Detection

Identifies packages designed to steal cryptocurrency.

**Features:**
- Ethereum wallet detection
- Crypto API usage analysis
- Wallet connection patterns
- Transaction monitoring code

**Example:**
```bash
# Detect crypto targeting
njordscan scan . --crypto-targeting --wallet-analysis

# Check for ethereum targeting
njordscan scan . --ethereum-targeting --crypto-wallet-check
```

**Detection Patterns:**
- `window.ethereum` access
- Wallet connection requests
- Private key extraction attempts
- Transaction manipulation code

### 5. Data Exfiltration Detection

Detects packages attempting to steal sensitive data.

**Features:**
- Data collection pattern analysis
- Network request monitoring
- Sensitive data identification
- Exfiltration method detection

**Example:**
```bash
# Detect data exfiltration
njordscan scan . --data-exfiltration --sensitive-data-check

# Monitor network requests
njordscan scan . --network-monitoring --data-leak-detection
```

**Detection Patterns:**
- `navigator.userAgent` collection
- Cookie harvesting
- Local storage access
- Form data collection
- External API calls with sensitive data

### 6. Obfuscation Detection

Advanced pattern recognition for obfuscated malicious code.

**Features:**
- String obfuscation detection
- Control flow obfuscation
- Variable name obfuscation
- Code complexity analysis

**Example:**
```bash
# Detect obfuscated code
njordscan scan . --obfuscation-detection --complexity-analysis

# Check for string obfuscation
njordscan scan . --string-obfuscation --pattern-analysis
```

**Detection Patterns:**
- `String.fromCharCode()` usage
- Base64 encoding/decoding
- Eval() function usage
- Complex control flow structures
- Unusual variable naming

### 7. Maintainer Profile Analysis

Analyzes maintainer patterns for suspicious behavior.

**Features:**
- New maintainer detection
- Activity pattern analysis
- Email pattern analysis
- Name pattern analysis
- Account takeover detection

**Example:**
```bash
# Analyze maintainer profiles
njordscan scan . --maintainer-analysis --profile-check

# Check for suspicious maintainers
njordscan scan . --suspicious-maintainer --activity-analysis
```

**Detection Patterns:**
- New maintainers with many packages
- Generic or suspicious names
- Suspicious email patterns
- Rapid activity patterns
- Account takeover indicators

## ⚙️ Configuration

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--ai-npm-detection` | Enable AI NPM attack detection | `false` |
| `--typosquatting` | Enable typosquatting detection | `false` |
| `--dependency-confusion` | Enable dependency confusion detection | `false` |
| `--ai-generated-malware` | Enable AI-generated malware detection | `false` |
| `--crypto-targeting` | Enable crypto wallet targeting detection | `false` |
| `--data-exfiltration` | Enable data exfiltration detection | `false` |
| `--obfuscation-detection` | Enable obfuscation detection | `false` |
| `--maintainer-analysis` | Enable maintainer profile analysis | `false` |
| `--similarity-threshold` | Similarity threshold for detection | `0.8` |
| `--confidence-threshold` | Confidence threshold for AI detection | `0.7` |

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

## 📊 Output and Reporting

### JSON Output

```json
{
  "ai_npm_detection": {
    "typosquatting": {
      "detected": true,
      "candidates": [
        {
          "package": "react-dom-router",
          "similarity": 0.95,
          "risk_level": "high",
          "description": "Similar to react-router-dom"
        }
      ]
    },
    "dependency_confusion": {
      "detected": true,
      "candidates": [
        {
          "package": "@babel/core",
          "unscoped_name": "babel",
          "similarity": 1.0,
          "risk_level": "critical"
        }
      ]
    },
    "ai_generated_malware": {
      "detected": true,
      "confidence": 0.85,
      "patterns": ["repetitive_code", "generic_functions"],
      "risk_level": "high"
    },
    "crypto_targeting": {
      "detected": true,
      "score": 0.75,
      "patterns": ["ethereum_access", "wallet_connection"],
      "risk_level": "high"
    },
    "data_exfiltration": {
      "detected": true,
      "score": 0.8,
      "patterns": ["user_agent_collection", "cookie_harvesting"],
      "risk_level": "high"
    },
    "obfuscation": {
      "detected": true,
      "score": 0.9,
      "patterns": ["string_obfuscation", "eval_usage"],
      "risk_level": "critical"
    },
    "maintainer_analysis": {
      "suspicious_patterns": ["new_maintainer", "suspicious_email"],
      "risk_level": "medium",
      "confidence": 0.6
    }
  }
}
```

### HTML Report

The HTML report includes interactive visualizations for:
- Threat level distribution
- Similarity analysis charts
- Maintainer risk profiles
- Pattern detection results
- Confidence scores

### Console Output

```
🤖 AI NPM Attack Detection Results
================================

🔍 Typosquatting Detection: HIGH RISK
   - react-dom-router (similarity: 0.95)
   - Risk: High similarity to react-router-dom

🎯 Dependency Confusion: CRITICAL RISK
   - @babel/core confusion detected
   - Risk: Exact name match with scoped package

🤖 AI-Generated Malware: HIGH RISK
   - Confidence: 85%
   - Patterns: Repetitive code, generic functions

🔐 Crypto Targeting: HIGH RISK
   - Score: 75%
   - Patterns: Ethereum access, wallet connection

📊 Data Exfiltration: HIGH RISK
   - Score: 80%
   - Patterns: User agent collection, cookie harvesting

🛡️ Obfuscation: CRITICAL RISK
   - Score: 90%
   - Patterns: String obfuscation, eval usage

👤 Maintainer Analysis: MEDIUM RISK
   - Patterns: New maintainer, suspicious email
   - Confidence: 60%
```

## 🧪 Testing and Validation

### Test Your Detection

```bash
# Test with known malicious packages
njordscan scan-package malicious-package --ai-npm-detection --verbose

# Test typosquatting detection
njordscan scan-package react-dom-router --typosquatting --similarity-check

# Test dependency confusion
njordscan scan-package babel --dependency-confusion --scope-analysis
```

### Validation Commands

```bash
# Run AI detection tests
python -m pytest tests/test_ai_npm_detection.py -v

# Run integration tests
python -m pytest tests/test_ai_detection_integration.py -v

# Run performance tests
python -m pytest tests/test_ai_detection_performance.py -v
```

## 🔧 Advanced Usage

### Custom Patterns

You can add custom detection patterns by creating a `patterns.yaml` file:

```yaml
custom_patterns:
  crypto_targeting:
    - "window.ethereum"
    - "web3"
    - "metamask"
  data_exfiltration:
    - "navigator.userAgent"
    - "document.cookie"
    - "localStorage"
  obfuscation:
    - "String.fromCharCode"
    - "eval("
    - "Function("
```

### API Usage

```python
from njordscan.ai import AIPackageAnalyzer, PackageSimilarityAnalyzer

# Initialize analyzers
package_analyzer = AIPackageAnalyzer()
similarity_analyzer = PackageSimilarityAnalyzer()

# Analyze package
result = await package_analyzer.analyze_package(
    package_name="suspicious-package",
    package_data={"name": "suspicious-package", "version": "1.0.0"},
    package_files={"index.js": "malicious code"}
)

# Check similarity
similarity_result = await similarity_analyzer.analyze_package_similarity(
    package_name="suspicious-package"
)
```

## 🚨 Security Considerations

### False Positives

The AI detection system is designed to minimize false positives, but some legitimate packages may trigger alerts:

- **AI-Generated Code**: Legitimate packages created with AI assistance
- **Similar Names**: Packages with similar but legitimate names
- **Obfuscated Code**: Legitimately obfuscated packages for performance
- **New Maintainers**: Legitimate new package maintainers

### Recommendations

1. **Review Alerts**: Always review AI detection alerts before taking action
2. **Verify Sources**: Check package maintainer reputation and history
3. **Test Packages**: Test suspicious packages in isolated environments
4. **Update Regularly**: Keep NjordScan updated for latest detection patterns
5. **Customize Thresholds**: Adjust detection thresholds based on your needs

## 📚 Further Reading

- [Vulnerability Types](vulnerability-types.md) - Complete list of detected vulnerabilities
- [CLI Reference](cli-reference.md) - Command-line interface documentation
- [Configuration Guide](configuration.md) - Advanced configuration options
- [Troubleshooting](troubleshooting.md) - Common issues and solutions

## 🤝 Contributing

We welcome contributions to improve AI NPM attack detection:

- **New Detection Patterns**: Add patterns for emerging threats
- **Improved Algorithms**: Enhance ML algorithms for better accuracy
- **Performance Optimization**: Improve detection speed and efficiency
- **Test Cases**: Add test cases for edge scenarios
- **Documentation**: Improve documentation and examples

## 📄 License

This feature is part of NjordScan and is licensed under the MIT License.

---

**Made with ❤️ for the security community**
