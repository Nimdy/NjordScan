# 🚀 Quick Start Guide

Get up and running with NjordScan in just 5 minutes! This guide will walk you through installation, your first scan, and basic usage.

---

## ⚡ **1-Minute Installation**

### 📦 **Install via pip (Recommended)**
```bash
pip install njordscan
```

### 🔍 **Verify Installation**
```bash
njordscan --version
# Output: NjordScan v1.0.0 - The Ultimate Security Scanner
```

---

## 🎯 **Your First Scan (2 minutes)**

### 🏃 **Quick Scan**
Navigate to your project directory and run:

```bash
cd /path/to/your/nextjs-project
njordscan
```

**What happens:**
1. 🔍 **Auto-detects** your framework (Next.js, React, Vite)
2. ⚡ **Quick analysis** of common vulnerabilities  
3. 🎨 **Beautiful terminal output** with results
4. 📊 **Interactive results** you can navigate

### 🎨 **Interactive Mode**
For the full experience:

```bash
njordscan --interactive
```

**Features:**
- 🧙‍♂️ **Setup wizard** for first-time users
- 🎨 **Theme selection** (Dark, Cyberpunk, Hacker, Professional)
- 📊 **Real-time progress** with animations
- 🔍 **Interactive results browser**

---

## 🎨 **Beautiful CLI Experience**

### 🌈 **Choose Your Theme**
```bash
# Cyberpunk theme for the adventurous
njordscan --theme cyberpunk

# Professional theme for enterprise
njordscan --theme professional

# Dark theme for late-night coding
njordscan --theme dark
```

### 📊 **Real-time Progress**
```bash
njordscan --show-progress
```

**You'll see:**
```
🛡️  NjordScan v1.0.0 - Security Analysis in Progress

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ 🔍 Analyzing: /your/nextjs/project                                        ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

📦 Framework Detection    ████████████████████████████████ 100% Next.js 13.5.0
🔒 Security Headers       ████████████████████████████████ 100% 3 issues found
📝 Static Code Analysis   ██████████████████░░░░░░░░░░░░░░  67% Analyzing...
📦 Dependencies           ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   0% Queued
⚙️  Configuration         ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   0% Queued
🏃 Runtime Testing        ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   0% Queued

💡 Tip: Use --deep for comprehensive AI-powered analysis
```

---

## 🎯 **Common Scan Types**

### ⚡ **Quick Scan** (30 seconds)
```bash
njordscan --mode quick
```
**Perfect for:**
- 🚀 **CI/CD pipelines**
- 📝 **Pull request checks**
- ⚡ **Rapid feedback**

### 🔍 **Standard Scan** (2-5 minutes)
```bash
njordscan --mode standard
```
**Perfect for:**
- 📅 **Daily development**
- 🔄 **Regular security checks**
- 🎯 **Balanced speed vs coverage**

### 🧠 **Deep AI Scan** (5-15 minutes)
```bash
njordscan --mode deep --ai-enhanced
```
**Perfect for:**
- 🚀 **Pre-production checks**
- 🔒 **Security audits**
- 🧠 **AI-powered analysis**

---

## 📊 **Understanding Results**

### 🎨 **Terminal Output**
```bash
🛡️  NjordScan Security Analysis Complete!

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                            📊 SECURITY SUMMARY                            ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

🎯 NjordScore: 7.8/10 (Good)          🕐 Scan Time: 2m 34s
📊 Total Issues: 12                   🧠 AI Enhanced: ✅
🔴 Critical: 1   🟠 High: 2   🟡 Medium: 5   🔵 Low: 4

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                           🔴 CRITICAL ISSUES                              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

🚨 NJORD-XSS-001: Potential XSS in React Component
   📁 File: components/UserProfile.tsx:42
   💡 Fix: Use proper input sanitization
   🔗 Learn: https://owasp.org/xss-prevention

🔴 View all issues: njordscan results
💡 Get help: njordscan explain NJORD-XSS-001
🛠️  Auto-fix: njordscan fix --interactive
```

### 🔍 **Interactive Results Browser**
```bash
njordscan results
```

**Navigation:**
- ⬆️⬇️ **Arrow keys** to navigate issues
- **Enter** to view detailed explanation
- **F** to filter by severity
- **S** to search issues
- **Q** to quit

---

## 🛠️ **Quick Fixes**

### 🎯 **Auto-Fix Mode**
```bash
njordscan fix --interactive
```

**What it does:**
1. 🔍 **Shows fixable issues**
2. 💡 **Suggests solutions**
3. 🛠️ **Applies fixes** with your approval
4. ✅ **Verifies fixes** work correctly

### 📚 **Learn About Issues**
```bash
# Get detailed explanation
njordscan explain NJORD-XSS-001

# View best practices
njordscan guide --framework nextjs

# Interactive tutorial
njordscan learn
```

---

## ⚙️ **Quick Configuration**

### 🧙‍♂️ **Setup Wizard**
```bash
njordscan setup
```

**Wizard steps:**
1. 🎯 **Framework detection** (Next.js, React, Vite)
2. 🔒 **Security level** (Basic, Standard, Advanced, Enterprise)
3. 🎨 **Theme preference** (Default, Dark, Cyberpunk, etc.)
4. 🔗 **IDE integration** setup
5. 🌟 **Community features** enrollment

### 📝 **Quick Config File**
Create `.njordscan.json` in your project root:

```json
{
  "framework": "nextjs",
  "security_level": "standard",
  "theme": "dark",
  "modules": {
    "headers": true,
    "static": true,
    "dependencies": true,
    "configs": true,
    "runtime": false,
    "ai": true
  },
  "ai_features": {
    "behavioral_analysis": true,
    "threat_intelligence": true
  }
}
```

---

## 🔗 **IDE Integration (1 minute)**

### 📝 **VS Code**
```bash
njordscan setup --ide vscode
```

**Auto-installs:**
- ✅ **VS Code extension**
- 🔍 **Real-time diagnostics**
- 💡 **Code completion**
- 🛠️ **Fix suggestions**

### 🧠 **Other IDEs**
```bash
# IntelliJ/WebStorm
njordscan setup --ide intellij

# Vim/Neovim
njordscan setup --ide vim

# Generic LSP
njordscan setup --ide lsp
```

---

## 🔄 **CI/CD Integration (2 minutes)**

### 🐙 **GitHub Actions**
```bash
njordscan setup --ci github
```

**Auto-creates:**
- 📄 `.github/workflows/njordscan.yml`
- 🔍 **PR security checks**
- 📊 **SARIF upload** to Security tab
- 💬 **PR comments** with results

### 🦊 **GitLab CI**
```bash
njordscan setup --ci gitlab
```

**Auto-creates:**
- 📄 `.gitlab-ci.yml` security stage
- 🔍 **Pipeline integration**
- 📊 **Security dashboard** integration

---

## 🌟 **Community Features**

### 🤝 **Join the Community**
```bash
njordscan community register
```

**Benefits:**
- 🛡️ **Community security rules**
- 🎯 **Threat intelligence** sharing
- 🏆 **Challenges and leaderboards**
- 👨‍🏫 **Mentorship opportunities**

### 📚 **Learn and Grow**
```bash
# Interactive tutorials
njordscan learn

# Security challenges
njordscan community challenges

# Get mentorship
njordscan community mentorship
```

---

## 🎯 **Next Steps**

### 📚 **Learn More**
1. 📖 **[User Guide](../user-guide/cli-reference.md)** - Complete CLI reference
2. 🛡️ **[Security Analysis](../security/vulnerability-types.md)** - What we detect
3. 🔌 **[Plugins](../plugins/overview.md)** - Extend functionality
4. 🔄 **[CI/CD Integration](../cicd/github-actions.md)** - Automate security

### 🛠️ **Advanced Usage**
```bash
# Performance tuning
njordscan --threads 8 --cache-strategy aggressive

# Custom reporting
njordscan --format html --output security-report.html

# Enterprise features
njordscan --mode enterprise --compliance sox
```

### 🌟 **Get Involved**
- 🤝 **[Contribute](../../CONTRIBUTING.md)** to the project
- 🛡️ **Share security rules** with the community
- 💬 **Join Discord** for real-time help
- 🐛 **Report issues** on GitHub

---

## 💡 **Pro Tips**

### ⚡ **Speed Tips**
```bash
# Cache results for faster re-scans
njordscan --cache-strategy intelligent

# Parallel processing
njordscan --threads $(nproc)

# Skip slow modules for quick checks
njordscan --skip runtime
```

### 🎯 **Accuracy Tips**
```bash
# Enable AI for better detection
njordscan --ai-enhanced

# Use framework-specific analysis
njordscan --framework nextjs

# Community rules for latest threats
njordscan --community-rules
```

### 📊 **Reporting Tips**
```bash
# Multiple formats at once
njordscan --format html,json,sarif

# Executive summary for management
njordscan --executive-summary

# Trend analysis
njordscan --compare-with previous-scan.json
```

---

## 🆘 **Need Help?**

### 💬 **Quick Help**
```bash
# Built-in help
njordscan --help

# Command-specific help
njordscan scan --help

# Interactive help
njordscan help --interactive
```

### 🌟 **Community Support**
- 💬 **Discord**: [https://discord.gg/njordscan](https://discord.gg/njordscan)
- 📚 **Documentation**: [https://njordscan.dev/docs](https://njordscan.dev/docs)
- 🐛 **Issues**: [GitHub Issues](https://github.com/nimdy/njordscan/issues)
- 💡 **Discussions**: [GitHub Discussions](https://github.com/nimdy/njordscan/discussions)

---

<div align="center">

## 🎉 **You're Ready to Secure Your Apps!**

**NjordScan is now protecting your applications. Happy coding! 🛡️**

[**📖 Full User Guide**](../user-guide/cli-reference.md) | [**🛡️ Security Features**](../security/vulnerability-types.md) | [**🔌 Plugins**](../plugins/overview.md) | [**💬 Get Help**](https://discord.gg/njordscan)

</div>
