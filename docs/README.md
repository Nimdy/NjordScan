# 📚 NjordScan Documentation

Welcome to the comprehensive documentation for NjordScan - the ultimate security scanner for modern JavaScript applications.

---

## 📖 **Documentation Structure**

### 🚀 **Getting Started**
- [**Quick Start Guide**](getting-started/quick-start.md) - Get up and running in 5 minutes
- [**Installation Guide**](getting-started/installation.md) - Detailed installation instructions
- [**First Scan Tutorial**](getting-started/first-scan.md) - Your first security scan (Coming Soon)
- [**Configuration Basics**](getting-started/configuration.md) - Essential configuration options (Coming Soon)

### 🔍 **User Guides**
- [**CLI Reference**](user-guide/cli-reference.md) - Complete command-line documentation
- [**Interactive Mode**](user-guide/interactive-mode.md) - Using the beautiful CLI interface
- [**IDE Integration**](user-guide/ide-integration.md) - Editor plugins and real-time analysis
- [**Report Formats**](user-guide/report-formats.md) - Understanding different output formats
- [**Configuration Guide**](user-guide/configuration.md) - Advanced configuration options

### 🛡️ **Security Analysis**
- [**Vulnerability Types**](security/vulnerability-types.md) - 25+ standardized vulnerability types aligned with OWASP Top 10 2021
- [**Framework Analysis**](security/framework-analysis.md) - Next.js, React, Vite specifics
- [**AI Security**](security/ai-security.md) - AI-specific vulnerability detection
- [**Custom Rules**](security/custom-rules.md) - Writing your own security rules
- [**False Positive Handling**](security/false-positives.md) - Managing and reducing false positives
- [**Enhanced Behavioral Analysis**](security/behavioral-analysis.md) - Multi-strategy sequence analysis and anomaly detection

### 🧠 **AI & Intelligence**
- [**AI Features Overview**](ai/overview.md) - AI-powered analysis capabilities
- [**Threat Intelligence**](ai/threat-intelligence.md) - Real-time CVE and MITRE ATT&CK data with graceful error handling
- [**Behavioral Analysis**](ai/behavioral-analysis.md) - Enhanced multi-strategy sequence analysis and anomaly detection
- [**Machine Learning**](ai/machine-learning.md) - How ML enhances detection
- [**AI Orchestrator**](ai/ai-orchestrator.md) - Comprehensive AI analysis with threat assessment and code understanding

### 🔌 **Plugin System**
- [**Plugin Overview**](plugins/overview.md) - Understanding the plugin ecosystem
- [**Using Plugins**](plugins/using-plugins.md) - Installing and managing plugins
- [**Plugin Development**](plugins/development.md) - Creating custom plugins
- [**Plugin API Reference**](plugins/api-reference.md) - Complete API documentation
- [**Publishing Plugins**](plugins/publishing.md) - Sharing with the community

### 🔄 **CI/CD Integration**
- [**GitHub Actions**](cicd/github-actions.md) - Complete GitHub integration
- [**GitLab CI/CD**](cicd/gitlab-ci.md) - GitLab pipeline integration
- [**Azure DevOps**](cicd/azure-devops.md) - Azure pipeline setup
- [**Jenkins**](cicd/jenkins.md) - Jenkins plugin and configuration
- [**Quality Gates**](cicd/quality-gates.md) - Automated security policies

### 🌟 **Community**
- [**Community Hub**](community/hub.md) - Joining the NjordScan community
- [**Contributing Rules**](community/contributing-rules.md) - Sharing security rules
- [**Mentorship Program**](community/mentorship.md) - Learning and teaching
- [**Challenges**](community/challenges.md) - Community security challenges

### 🛠️ **Development**
- [**Architecture Overview**](development/architecture.md) - System design and components
- [**API Reference**](development/api.md) - Complete API documentation
- [**Contributing Guide**](../CONTRIBUTING.md) - How to contribute to NjordScan
- [**Development Setup**](development/setup.md) - Setting up development environment (Coming Soon)
- [**Testing Guide**](development/testing.md) - Running and writing tests (Coming Soon)

### 📊 **Advanced Topics**
- [**Troubleshooting**](advanced/troubleshooting.md) - Common issues and solutions including plugin system and API rate limits
- [**Performance Tuning**](advanced/performance-tuning.md) - Optimizing scan performance (Coming Soon)
- [**Enterprise Deployment**](advanced/enterprise-deployment.md) - Large-scale deployments (Coming Soon)
- [**Security Hardening**](advanced/security-hardening.md) - Securing NjordScan itself (Coming Soon)
- [**System Validation**](advanced/system-validation.md) - Comprehensive system testing and validation

### 📋 **Reference**
- [**CLI Command Reference**](reference/cli-commands.md) - All available commands
- [**Configuration Reference**](reference/configuration.md) - Complete configuration options
- [**Error Codes**](reference/error-codes.md) - Understanding error messages
- [**Vulnerability Database**](reference/vulnerability-database.md) - Vulnerability classification
- [**Glossary**](reference/glossary.md) - Terms and definitions

---

## 🎯 **Quick Navigation**

### 🆕 **New to NjordScan?**
1. Start with [**Quick Start Guide**](getting-started/quick-start.md)
2. Follow [**First Scan Tutorial**](getting-started/first-scan.md)
3. Explore [**Interactive Mode**](user-guide/interactive-mode.md)
4. Set up [**IDE Integration**](user-guide/ide-integration.md)

### 🔧 **Setting Up CI/CD?**
1. Choose your platform: [**GitHub**](cicd/github-actions.md) | [**GitLab**](cicd/gitlab-ci.md) | [**Azure**](cicd/azure-devops.md) | [**Jenkins**](cicd/jenkins.md)
2. Configure [**Quality Gates**](cicd/quality-gates.md)
3. Review [**Report Formats**](user-guide/report-formats.md)

### 🔌 **Extending NjordScan?**
1. Browse [**Plugin Overview**](plugins/overview.md)
2. Learn [**Plugin Development**](plugins/development.md)
3. Check [**API Reference**](plugins/api-reference.md)
4. Consider [**Publishing**](plugins/publishing.md)

### 🛡️ **Security Focus?**
1. Understand [**Vulnerability Types**](security/vulnerability-types.md)
2. Learn [**Framework Analysis**](security/framework-analysis.md)
3. Explore [**AI Security**](security/ai-security.md)
4. Create [**Custom Rules**](security/custom-rules.md)

### 🌟 **Join Community?**
1. Visit [**Community Hub**](community/hub.md)
2. Contribute [**Security Rules**](community/contributing-rules.md)
3. Join [**Mentorship Program**](community/mentorship.md)
4. Participate in [**Challenges**](community/challenges.md)

---

## 📱 **Documentation Formats**

### 🌐 **Online Documentation**
- **Web Version**: [https://njordscan.dev/docs](https://njordscan.dev/docs)
- **Interactive Examples**: Code samples you can run
- **Search Functionality**: Find what you need quickly
- **Mobile Optimized**: Read on any device

### 📄 **Offline Documentation**
```bash
# Generate offline docs
njordscan docs generate --format html --output ./docs-offline

# Generate PDF version
njordscan docs generate --format pdf --output njordscan-docs.pdf

# Generate man pages
njordscan docs generate --format man --output /usr/local/man/man1/
```

### 🎥 **Video Tutorials**
- **YouTube Channel**: [NjordScan Tutorials](https://youtube.com/@njordscan)
- **Getting Started Playlist**: Step-by-step video guides
- **Advanced Topics**: Deep-dive technical content
- **Community Contributions**: User-generated content

---

## 🔍 **Search & Navigation**

### 🔎 **Built-in Search**
```bash
# Search documentation
njordscan docs search "configuration"

# Search with filters
njordscan docs search "plugin development" --category development

# Interactive search
njordscan docs search --interactive
```

### 🗂️ **Documentation Categories**

| Category | Description | Audience |
|----------|-------------|----------|
| **🚀 Getting Started** | Installation and first steps | New users |
| **📖 User Guides** | Day-to-day usage | All users |
| **🛡️ Security** | Vulnerability detection | Security professionals |
| **🧠 AI & Intelligence** | Advanced analysis features | Power users |
| **🔌 Plugins** | Extensibility and customization | Developers |
| **🔄 CI/CD** | Pipeline integration | DevOps engineers |
| **🌟 Community** | Collaboration and sharing | Community members |
| **🛠️ Development** | Contributing and development | Contributors |
| **📊 Advanced** | Enterprise and optimization | Advanced users |
| **📋 Reference** | Complete technical reference | All users |

---

## 🤝 **Contributing to Documentation**

### ✍️ **How to Contribute**
1. **Fork** the repository
2. **Edit** documentation files in the `docs/` directory
3. **Preview** changes locally
4. **Submit** a pull request

### 📝 **Documentation Standards**
- **Markdown Format** with GitHub Flavored Markdown
- **Clear Headings** with emoji prefixes
- **Code Examples** with proper syntax highlighting
- **Screenshots** for UI elements
- **Cross-references** between related topics

### 🎨 **Style Guide**
- **Tone**: Friendly but professional
- **Structure**: Logical flow with clear sections
- **Examples**: Real-world, practical examples
- **Accessibility**: Screen reader friendly
- **Mobile**: Responsive design considerations

---

## 📞 **Getting Help**

### 💬 **Community Support**
- **Discord Community**: [https://discord.gg/njordscan](https://discord.gg/njordscan)
- **GitHub Discussions**: [https://github.com/nimdy/njordscan/discussions](https://github.com/nimdy/njordscan/discussions)
- **Stack Overflow**: Tag your questions with `njordscan`

### 🐛 **Bug Reports**
- **Documentation Issues**: [GitHub Issues](https://github.com/nimdy/njordscan/issues)
- **Missing Content**: Use the "Documentation Request" template
- **Outdated Information**: Report via GitHub or Discord

### 💡 **Suggestions**
- **Content Ideas**: Share in GitHub Discussions
- **Structure Improvements**: Open an issue with your suggestions
- **New Sections**: Propose via the community channels

---

## 📊 **Documentation Metrics**

We track documentation usage to improve content:

### 📈 **Popular Topics**
1. **Quick Start Guide** - Most visited
2. **CLI Reference** - Most searched
3. **IDE Integration** - High engagement
4. **Plugin Development** - Growing interest
5. **CI/CD Integration** - Enterprise focus

### 🎯 **Improvement Areas**
- **Video Content** - Expanding tutorial library
- **Interactive Examples** - More hands-on content
- **Localization** - Multi-language support
- **Mobile Experience** - Better mobile navigation

---

## 🔄 **Documentation Versioning**

### 📚 **Version Strategy**
- **Latest**: Current stable version documentation
- **Previous**: Last major version for migration reference
- **Development**: Upcoming features (beta users)

### 🏷️ **Version Access**
```bash
# View specific version docs
njordscan docs --version 1.0.0

# Compare versions
njordscan docs diff --from 0.9.0 --to 1.0.0

# Migration guides
njordscan docs migration --from 0.9.0
```

---

<div align="center">

## 📚 **Start Learning Today!**

**Choose your path and dive into the comprehensive NjordScan documentation.**

[**🚀 Quick Start**](getting-started/quick-start.md) | [**📖 User Guide**](user-guide/cli-reference.md) | [**🛡️ Security**](security/vulnerability-types.md) | [**🔌 Plugins**](plugins/overview.md)

---

**📧 Documentation Feedback**: docs@njordscan.dev  
**🌟 Contribute**: [Edit on GitHub](https://github.com/nimdy/njordscan/tree/main/docs)

</div>
