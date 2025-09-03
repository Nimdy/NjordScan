"""
NjordScan v1.0.0 - The Ultimate Security Scanner
Professional-grade security scanner for Next.js, React, and Vite applications

This setup.py provides comprehensive installation and configuration for NjordScan,
including all advanced features, AI capabilities, and enterprise integrations.
"""

import os
import sys
from setuptools import setup, find_packages
from setuptools.command.install import install

# Ensure Python version compatibility
if sys.version_info < (3, 8):
    sys.exit("NjordScan requires Python 3.8 or higher")

# Read long description from README
def read_file(filename):
    """Read file content safely."""
    try:
        with open(filename, "r", encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return f"File {filename} not found"
    except Exception as e:
        return f"Error reading {filename}: {e}"

# Read requirements from requirements.txt
def read_requirements(filename="requirements.txt"):
    """Parse requirements file and return list of dependencies."""
    try:
        with open(filename, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        
        requirements = []
        for line in lines:
            line = line.strip()
            # Skip empty lines, comments, and section headers
            if line and not line.startswith("#") and not line.startswith("="):
                # Handle inline comments
                if "#" in line:
                    line = line.split("#")[0].strip()
                if line:
                    requirements.append(line)
        
        return requirements
    except FileNotFoundError:
        print(f"Warning: {filename} not found, using minimal requirements")
        return [
            "click>=8.0.0",
            "rich>=13.0.0",
            "aiohttp>=3.8.0",
            "requests>=2.28.0",
            "pyyaml>=6.0",
            "jinja2>=3.1.0"
        ]

# Custom install command for post-installation setup
class CustomInstallCommand(install):
    """Custom installation command to handle post-install setup."""
    
    def run(self):
        # Run the standard installation
        install.run(self)
        
        # Post-installation setup
        self.post_install()
    
    def post_install(self):
        """Perform post-installation setup."""
        print("\n" + "="*60)
        print("🛡️  NjordScan Installation Complete!")
        print("="*60)
        print("\n🚀 Quick Start:")
        print("   njordscan --help")
        print("   njordscan setup")
        print("   njordscan scan . --mode standard")
        print("\n📚 Documentation:")
        print("   https://njordscan.dev/docs")
        print("\n💬 Community:")
        print("   https://discord.gg/njordscan")
        print("\n" + "="*60)

# Read version from njordscan/__init__.py
def get_version():
    """Extract version from package __init__.py."""
    version_file = os.path.join("njordscan", "__init__.py")
    try:
        with open(version_file, "r") as f:
            for line in f:
                if line.startswith("__version__"):
                    return line.split('"')[1]
    except FileNotFoundError:
        pass
    return "1.0.0"  # Default version

# Package configuration
setup(
    # Basic package information
    name="njordscan",
    version=get_version(),
    author="NjordScan Contributors",
    author_email="info@njordscan.dev",
    maintainer="Nimdy",
    maintainer_email="info@hackme.ai",
    
    # Package description
    description="The Ultimate Security Scanner for Next.js, React, and Vite Applications",
    long_description=read_file("README.md"),
    long_description_content_type="text/markdown",
    
    # URLs and links
    url="https://github.com/nimdy/njordscan",
    project_urls={
        "Homepage": "https://njordscan.dev",
        "Documentation": "https://njordscan.dev/docs",
        "Repository": "https://github.com/nimdy/njordscan",
        "Bug Reports": "https://github.com/nimdy/njordscan/issues",
        "Discussions": "https://github.com/nimdy/njordscan/discussions",
        "Discord": "https://discord.gg/njordscan",
        "Security": "https://github.com/nimdy/njordscan/security",
        "Changelog": "https://github.com/nimdy/njordscan/blob/main/CHANGELOG.md",
        "Contributing": "https://github.com/nimdy/njordscan/blob/main/CONTRIBUTING.md",
    },
    
    # Package discovery and structure
    packages=find_packages(exclude=["tests*", "docs*", "examples*"]),
    
    # Python version requirements
    python_requires=">=3.8",
    
    # Dependencies
    install_requires=read_requirements(),
    
    # Optional dependencies for different use cases
    extras_require={
        # Development dependencies
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.7.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
            "isort>=5.12.0",
            "pre-commit>=3.3.0",
        ],
        
        # Documentation dependencies
        "docs": [
            "mkdocs>=1.5.0",
            "mkdocs-material>=9.2.0",
            "mkdocs-mermaid2-plugin>=1.1.0",
        ],
        
        # AI and Machine Learning features
        "ai": [
            "scikit-learn>=1.3.0",
            "numpy>=1.24.0",
            "pandas>=2.0.0",
            "nltk>=3.8.0",
            "textblob>=0.17.0",
        ],
        
        # Enterprise features
        "enterprise": [
            "ldap3>=2.9.0",
            "python-saml>=1.15.0",
            "redis>=4.5.0",
            "sqlalchemy>=1.4.0",
        ],
        
        # Performance optimization
        "performance": [
            "cython>=3.0.0",
            "numba>=0.57.0",
            "ujson>=5.8.0",
        ],
        
        # All optional dependencies
        "all": [
            "pytest>=7.4.0", "pytest-asyncio>=0.21.0", "pytest-cov>=4.1.0",
            "black>=23.7.0", "flake8>=6.0.0", "mypy>=1.5.0", "isort>=5.12.0",
            "mkdocs>=1.5.0", "mkdocs-material>=9.2.0",
            "scikit-learn>=1.3.0", "numpy>=1.24.0", "pandas>=2.0.0",
            "ldap3>=2.9.0", "redis>=4.5.0", "sqlalchemy>=1.4.0",
            "cython>=3.0.0", "ujson>=5.8.0",
        ],
    },
    
    # Package classification
    classifiers=[
        # Development status
        "Development Status :: 5 - Production/Stable",
        
        # Audience and topic
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Software Development :: Libraries :: Python Modules",
        
        # License
        "License :: OSI Approved :: MIT License",
        
        # Operating systems
        "Operating System :: OS Independent",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        
        # Python versions
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3 :: Only",
        
        # Framework support
        "Framework :: AsyncIO",
        "Framework :: Django",
        
        # Additional categories
        "Environment :: Console",
        "Environment :: Web Environment",
        "Natural Language :: English",
        "Typing :: Typed",
    ],
    
    # Keywords for PyPI search
    keywords=[
        "security", "scanner", "vulnerability", "nextjs", "react", "vite",
        "web-security", "static-analysis", "dynamic-analysis", "sast", "dast",
        "owasp", "cybersecurity", "penetration-testing", "security-audit",
        "ai-security", "machine-learning", "threat-intelligence", "devsecops",
        "ci-cd", "github-actions", "gitlab-ci", "azure-devops", "jenkins",
        "xss", "sql-injection", "csrf", "ssrf", "authentication", "authorization"
    ],
    
    # Console scripts and entry points
    entry_points={
        "console_scripts": [
            "njordscan=njordscan.cli:main",
            "njord=njordscan.cli:main",  # Short alias
        ],
        
        # Plugin entry points for extensibility
        "njordscan.plugins": [
            "nextjs = njordscan.frameworks.nextjs_analyzer:NextJSAnalyzer",
            "react = njordscan.frameworks.react_analyzer:ReactAnalyzer",
            "vite = njordscan.frameworks.vite_analyzer:ViteAnalyzer",
        ],
        
        "njordscan.modules": [
            "headers = njordscan.modules.headers:HeadersModule",
            "static = njordscan.modules.code_static:CodeStaticModule",
            "dependencies = njordscan.modules.dependencies:DependenciesModule",
            "configs = njordscan.modules.configs:ConfigsModule",
            "runtime = njordscan.modules.runtime:RuntimeModule",
            "ai = njordscan.modules.ai_endpoints:AIEndpointsModule",
        ],
        
        "njordscan.reporters": [
            "terminal = njordscan.report.formatter:TerminalReporter",
            "html = njordscan.report.formatter:HTMLReporter",
            "json = njordscan.report.formatter:JSONReporter",
            "sarif = njordscan.report.formatter:SARIFReporter",
        ],
    },
    
    # Package data and resources
    include_package_data=True,
    package_data={
        "njordscan": [
            "data/*.yaml",
            "data/*.json",
            "data/*.txt",
            "templates/*.j2",
            "templates/*.html",
            "static/css/*.css",
            "static/js/*.js",
            "static/images/*",
        ],
    },
    
    # Additional data files
    data_files=[
        ("share/njordscan/docs", ["README.md", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md"]),
        ("share/njordscan/examples", ["examples/basic_scan.py"] if os.path.exists("examples/basic_scan.py") else []),
    ],
    
    # Zip safety
    zip_safe=False,
    
    # Custom install command
    cmdclass={
        "install": CustomInstallCommand,
    },
    
    # Platform-specific requirements
    platforms=["any"],
    
    # Minimum setuptools version
    setup_requires=["setuptools>=45.0"],
    
    # Tests
    test_suite="tests",
    tests_require=[
        "pytest>=7.4.0",
        "pytest-asyncio>=0.21.0",
        "pytest-cov>=4.1.0",
    ],
)

# Post-setup information
if __name__ == "__main__":
    print("\n" + "="*60)
    print("🛡️  NjordScan - The Ultimate Security Scanner")
    print("="*60)
    print("\n✨ Features:")
    print("   🧠 AI-Powered Vulnerability Detection")
    print("   ⚛️  Framework-Specific Analysis (Next.js, React, Vite)")
    print("   🔍 Static & Dynamic Security Testing")
    print("   📊 Beautiful Reports & Dashboards")
    print("   🔌 Extensible Plugin System")
    print("   🌟 Community-Driven Intelligence")
    print("   🔄 CI/CD Integration (GitHub, GitLab, Azure)")
    print("   🎨 Amazing Developer Experience")
    print("\n🚀 Get Started:")
    print("   pip install njordscan")
    print("   njordscan setup")
    print("   njordscan scan . --mode standard")
    print("\n📚 Learn More:")
    print("   Documentation: https://njordscan.dev/docs")
    print("   Community: https://discord.gg/njordscan")
    print("   Repository: https://github.com/nimdy/njordscan")
    print("\n" + "="*60)