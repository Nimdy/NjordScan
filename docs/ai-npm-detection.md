# NPM Package Threat Detection

> Heuristic detection for malicious npm packages, typosquatting, and supply chain attacks

## Overview

NjordScan's package threat detection uses **pattern matching, string similarity (SequenceMatcher), and scoring heuristics** to identify risks in npm dependencies. It does not use machine learning or LLMs.

## What It Detects

### 1. Typosquatting
Compares package names against known legitimate packages using string similarity scoring. Flags packages with names suspiciously close to popular packages (e.g., `react-dom-router` vs `react-router-dom`).

### 2. Obfuscation Patterns
Regex-based detection of code obfuscation techniques:
- `String.fromCharCode()`, `atob()`, `unescape()`
- `eval()` and `Function()` constructor usage
- Long hex/base64 strings
- Unusual variable naming patterns

### 3. Data Exfiltration Indicators
Flags code patterns that suggest data harvesting:
- `document.cookie`, `localStorage.getItem()`
- `navigator.userAgent` collection
- External HTTP requests with collected data
- File system reads (`fs.readFile`, `fs.readdir`)

### 4. Crypto Wallet Targeting
Detects patterns targeting cryptocurrency:
- `window.ethereum` access
- Private key / seed phrase extraction
- Wallet API interaction patterns

### 5. Maintainer Anomalies
Checks package metadata for suspicious maintainer patterns:
- Missing or malformed maintainer info
- Suspicious email formats
- Short or random usernames

### 6. Malicious Install Scripts (via Supply Chain Module)
The `supply_chain` module separately scans `package.json` lifecycle scripts for:
- `curl|sh` and `wget` in `postinstall`/`preinstall`
- Reverse shell patterns
- Environment variable / credential harvesting
- Encoded payload execution

See the [supply chain module](../njordscan/modules/supply_chain.py) for details.

## Usage

```bash
# Standard scan includes dependency and supply chain checks
python -m njordscan scan .

# Deep scan with enhanced analysis
python -m njordscan scan . --mode deep --ai-enhanced
```

## Programmatic API

```python
from njordscan.ai.ai_package_analyzer import AIPackageAnalyzer

analyzer = AIPackageAnalyzer()

result = await analyzer.analyze_package(
    package_name="suspicious-package",
    package_data={"name": "suspicious-package", "version": "1.0.0"},
    package_files={"index.js": "eval(atob('...'))"}
)

print(result.detected_threats)   # List of threat types
print(result.risk_level)         # LOW / MEDIUM / HIGH / CRITICAL
print(result.confidence_score)   # 0.0 - 1.0
```

## How It Works

All detection is **rule-based**, not ML-based:

| Detection | Technique | Implementation |
|-----------|-----------|----------------|
| Typosquatting | `difflib.SequenceMatcher` string similarity | Compares against set of known legitimate packages |
| Obfuscation | Regex pattern matching | Counts matches against obfuscation pattern lists |
| Data exfiltration | Regex pattern matching | Scans for network request + data collection combos |
| Crypto targeting | Regex pattern matching | Looks for wallet/crypto API access patterns |
| Maintainer analysis | Metadata heuristics | Checks email format, name patterns |

Each detection category produces a score (0.0–1.0). Scores above configurable thresholds trigger findings. The overall risk level is calculated by weighting detected threat types.

## False Positives

Legitimate packages may trigger alerts:
- Build tools that use `eval()` for code generation
- Packages with names naturally similar to popular packages
- Analytics libraries that collect browser info
- New maintainers who are legitimate first-time publishers

Always review findings before acting on them.

## Testing

```bash
python -m pytest tests/test_supply_chain.py -v
```
