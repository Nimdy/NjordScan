# 🤝 Contributing to NjordScan

We're thrilled that you're interested in contributing to NjordScan! This document provides guidelines and information for contributors.

## 🌟 **Ways to Contribute**

### 🔍 **Security Research**
- **Vulnerability Detection Rules** - Add new security patterns
- **Framework Analysis** - Improve Next.js, React, Vite support
- **Threat Intelligence** - Share threat patterns and IOCs
- **False Positive Reduction** - Improve detection accuracy

### 🛠️ **Development**
- **Core Features** - Enhance scanning capabilities
- **Performance Optimization** - Improve speed and efficiency
- **Plugin Development** - Create new plugins and integrations
- **AI/ML Enhancements** - Improve intelligent analysis

### 🎨 **User Experience**
- **CLI Improvements** - Enhance terminal interface
- **IDE Integration** - Improve editor plugins
- **Documentation** - Write guides and tutorials
- **Localization** - Translate to other languages

### 🌍 **Community**
- **Bug Reports** - Help identify and fix issues
- **Feature Requests** - Suggest new capabilities
- **Community Support** - Help other users
- **Content Creation** - Write blogs, create videos

---

## 🚀 **Getting Started**

### 📋 **Prerequisites**
- **Python 3.8+** installed
- **Git** for version control
- **Basic knowledge** of security concepts
- **Familiarity** with Next.js, React, or Vite (for framework-specific contributions)

### 🔧 **Development Setup**

1. **Fork and Clone**
```bash
git clone https://github.com/YOUR_USERNAME/njordscan.git
cd njordscan
```

2. **Create Virtual Environment**
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. **Install Dependencies**
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

4. **Verify Installation**
```bash
python -m pytest
python -m njordscan --help
```

5. **Create Feature Branch**
```bash
git checkout -b feature/your-amazing-feature
```

---

## 🎯 **Contribution Guidelines**

### 📝 **Code Standards**

#### **Python Code Style**
- Follow **PEP 8** style guidelines
- Use **Black** for code formatting
- Use **type hints** for all functions
- Write **docstrings** for all public methods
- Maximum line length: **88 characters**

```python
def analyze_vulnerability(
    code_snippet: str, 
    context: Dict[str, Any]
) -> List[Vulnerability]:
    """
    Analyze code snippet for security vulnerabilities.
    
    Args:
        code_snippet: The code to analyze
        context: Additional context for analysis
        
    Returns:
        List of detected vulnerabilities
    """
    pass
```

#### **Code Quality**
- **No linting errors** - Run `flake8` before committing
- **Type checking** - Run `mypy` for type validation
- **Test coverage** - Maintain >80% test coverage
- **Security focus** - All code should be security-conscious

### 🧪 **Testing Requirements**

#### **Test Types**
- **Unit Tests** - Test individual functions and methods
- **Integration Tests** - Test module interactions
- **Security Tests** - Test security rule effectiveness
- **Performance Tests** - Ensure performance standards

#### **Running Tests**
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=njordscan --cov-report=html

# Run specific test file
pytest tests/test_scanner.py

# Run security-specific tests
pytest tests/security/
```

#### **Writing Tests**
```python
import pytest
from njordscan.modules.headers import HeadersModule

class TestHeadersModule:
    def test_missing_security_headers(self):
        """Test detection of missing security headers."""
        module = HeadersModule(config={})
        headers = {"Content-Type": "text/html"}
        
        vulnerabilities = module.analyze_headers(headers)
        
        assert len(vulnerabilities) > 0
        assert any("X-Frame-Options" in vuln.title for vuln in vulnerabilities)
```

### 🔒 **Security Rule Development**

#### **Rule Structure**
```yaml
# security_rules/my_rule.yaml
rule_id: "NJORD-CUSTOM-001"
name: "Custom Security Rule"
description: "Detects custom security pattern"
severity: "medium"
confidence: "high"
category: "injection"
frameworks: ["nextjs", "react"]

pattern:
  type: "regex"
  value: "dangerous_pattern_here"
  
remediation:
  description: "How to fix this issue"
  code_example: |
    // Safe implementation
    const safe = sanitizeInput(userInput);

references:
  - "https://owasp.org/relevant-guide"
  - "https://cwe.mitre.org/data/definitions/XXX.html"

test_cases:
  positive:
    - "code that should trigger the rule"
  negative:
    - "code that should NOT trigger the rule"
```

#### **Rule Testing**
```python
def test_custom_rule():
    """Test custom security rule."""
    rule = load_rule("NJORD-CUSTOM-001")
    
    # Test positive case
    vulnerable_code = "dangerous_pattern_here"
    assert rule.matches(vulnerable_code)
    
    # Test negative case
    safe_code = "safe_implementation"
    assert not rule.matches(safe_code)
```

### 🔌 **Plugin Development**

#### **Plugin Structure**
```python
from njordscan.plugins.base import BasePlugin

class MyCustomPlugin(BasePlugin):
    """Custom security plugin."""
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "my_custom_plugin"
        self.version = "1.0.0"
    
    async def scan(self, target: str) -> List[Vulnerability]:
        """Implement custom scanning logic."""
        vulnerabilities = []
        
        # Your custom analysis logic here
        
        return vulnerabilities
    
    def supports_framework(self, framework: str) -> bool:
        """Check if plugin supports framework."""
        return framework in ["nextjs", "react"]
```

#### **Plugin Metadata**
```yaml
# plugin.yaml
name: "My Custom Plugin"
version: "1.0.0"
description: "Custom security analysis plugin"
author: "Your Name"
frameworks: ["nextjs", "react"]
categories: ["static_analysis"]

dependencies:
  python: ">=3.8"
  packages:
    - "requests>=2.25.0"

configuration:
  options:
    - name: "enable_deep_scan"
      type: "boolean"
      default: false
      description: "Enable deep scanning mode"
```

---

## 📋 **Pull Request Process**

### 1️⃣ **Before Submitting**
- [ ] **Code follows style guidelines**
- [ ] **All tests pass**
- [ ] **No linting errors**
- [ ] **Documentation updated**
- [ ] **Security implications considered**

### 2️⃣ **PR Description Template**
```markdown
## 🎯 **What does this PR do?**
Brief description of changes

## 🔍 **Type of Change**
- [ ] Bug fix
- [ ] New feature
- [ ] Security improvement
- [ ] Performance optimization
- [ ] Documentation update
- [ ] Breaking change

## 🧪 **Testing**
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed

## 🔒 **Security Checklist**
- [ ] No hardcoded secrets
- [ ] Input validation implemented
- [ ] Security implications reviewed
- [ ] Threat model updated (if applicable)

## 📚 **Documentation**
- [ ] Code comments added
- [ ] README updated
- [ ] API documentation updated
- [ ] User guide updated (if applicable)
```

### 3️⃣ **Review Process**
1. **Automated Checks** - CI/CD pipeline runs
2. **Security Review** - Security team reviews changes
3. **Code Review** - Maintainers review implementation
4. **Testing** - QA team tests functionality
5. **Approval** - Maintainers approve and merge

---

## 🏷️ **Issue Guidelines**

### 🐛 **Bug Reports**
Use the bug report template:

```markdown
## 🐛 **Bug Description**
Clear description of the bug

## 🔄 **Reproduction Steps**
1. Step one
2. Step two
3. Bug occurs

## 💻 **Environment**
- OS: [e.g., Windows 10, macOS 12, Ubuntu 20.04]
- Python version: [e.g., 3.9.7]
- NjordScan version: [e.g., 1.0.0]
- Framework: [e.g., Next.js 13.0.0]

## 🎯 **Expected Behavior**
What should have happened

## 📸 **Screenshots**
If applicable, add screenshots

## 📋 **Additional Context**
Any other relevant information
```

### 💡 **Feature Requests**
Use the feature request template:

```markdown
## 🎯 **Feature Description**
Clear description of the proposed feature

## 🔍 **Problem Statement**
What problem does this solve?

## 💡 **Proposed Solution**
How should this feature work?

## 🎨 **User Experience**
How will users interact with this feature?

## 🔒 **Security Considerations**
Any security implications?

## 📈 **Success Metrics**
How will we measure success?
```

---

## 🏆 **Recognition**

### 🎖️ **Contributor Levels**
- **🌱 New Contributor** - First contribution
- **🔧 Regular Contributor** - 5+ contributions
- **🏅 Core Contributor** - 20+ contributions
- **🌟 Maintainer** - Ongoing project leadership
- **🛡️ Security Expert** - Security-focused contributions

### 🎁 **Rewards**
- **GitHub Badge** on profile
- **Hall of Fame** recognition
- **Swag Package** for significant contributions
- **Conference Speaking** opportunities
- **Direct Collaboration** with core team

### 📊 **Contribution Tracking**
We track contributions in multiple ways:
- **Code Contributions** - Pull requests merged
- **Security Research** - Vulnerabilities found/rules added
- **Community Support** - Issues helped, questions answered
- **Documentation** - Guides written, tutorials created

---

## 🤔 **Getting Help**

### 💬 **Communication Channels**
- **Discord**: [https://discord.gg/njordscan](https://discord.gg/njordscan)
- **GitHub Discussions**: For feature discussions
- **GitHub Issues**: For bug reports
- **Email**: security@njordscan.dev for security issues

### 📚 **Resources**
- **Developer Documentation**: [https://njordscan.dev/dev-docs](https://njordscan.dev/dev-docs)
- **API Reference**: [https://njordscan.dev/api](https://njordscan.dev/api)
- **Plugin Development Guide**: [https://njordscan.dev/plugins](https://njordscan.dev/plugins)
- **Security Rule Writing**: [https://njordscan.dev/rules](https://njordscan.dev/rules)

### 👥 **Mentorship**
New to security or open source? We offer:
- **Mentor Assignment** for new contributors
- **Guided First Contribution** program
- **Regular Office Hours** with maintainers
- **Learning Resources** and tutorials

---

## 📜 **Code of Conduct**

### 🤝 **Our Pledge**
We pledge to make participation in our project a harassment-free experience for everyone, regardless of:
- Age, body size, disability, ethnicity
- Gender identity and expression
- Level of experience, education, socio-economic status
- Nationality, personal appearance, race, religion
- Sexual identity and orientation

### ✅ **Expected Behavior**
- **Be respectful** and inclusive
- **Be collaborative** and helpful
- **Be constructive** in feedback
- **Be patient** with newcomers
- **Focus on what's best** for the community

### ❌ **Unacceptable Behavior**
- Harassment or discriminatory language
- Personal attacks or trolling
- Public or private harassment
- Publishing private information
- Unprofessional conduct

### 🚨 **Reporting**
Report violations to: conduct@njordscan.dev

---

## 📄 **License**

By contributing to NjordScan, you agree that your contributions will be licensed under the MIT License.

---

## 🙏 **Thank You!**

Every contribution makes NjordScan better and helps secure applications worldwide. Whether you're fixing a typo, adding a feature, or reporting a bug, your contribution matters!

**Together, we're making the web more secure! 🛡️**

---

<div align="center">

**Ready to contribute?** 

[**Start Contributing**](https://github.com/nimdy/njordscan/fork) | [**Join Discord**](https://discord.gg/njordscan) | [**Read Dev Docs**](https://njordscan.dev/dev-docs)

</div>
