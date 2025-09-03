# 📚 API Reference

Complete API reference for NjordScan's core components, modules, and interfaces.

---

## 🎯 **Core API**

### **Scanner Class**
**Location**: `njordscan.scanner.ScanOrchestrator`

Main orchestrator for security scanning operations.

```python
from njordscan import ScanOrchestrator, Config

# Initialize scanner
config = Config(target="./my-project", mode="standard")
scanner = ScanOrchestrator(config)

# Run scan
results = await scanner.scan()
```

#### **Constructor**
```python
def __init__(self, config: Config):
    """
    Initialize the scan orchestrator.
    
    Args:
        config: Configuration object with scan parameters
    """
```

#### **Methods**
```python
async def scan(self) -> ScanResults:
    """
    Perform security scan on configured target.
    
    Returns:
        ScanResults: Complete scan results with vulnerabilities
    """

def get_scan_summary(self) -> Dict[str, Any]:
    """
    Get summary of scan results.
    
    Returns:
        Dict containing scan statistics and summary
    """
```

---

## 🔧 **Configuration API**

### **Config Class**
**Location**: `njordscan.config.Config`

Configuration management for scan parameters.

```python
from njordscan import Config

# Create configuration
config = Config(
    target="./my-project",
    mode="standard",
    framework="nextjs",
    report_format="json",
    verbose=True
)
```

#### **Constructor Parameters**
```python
def __init__(self, 
             target: str = ".",
             mode: str = "standard",
             framework: str = "auto",
             report_format: str = "terminal",
             output_file: Optional[str] = None,
             verbose: bool = False,
             quiet: bool = False,
             **kwargs):
    """
    Initialize configuration.
    
    Args:
        target: Target directory or URL to scan
        mode: Scan mode (quick, standard, deep, enterprise)
        framework: Framework to target (auto, nextjs, react, vite)
        report_format: Output format (terminal, html, json, sarif)
        output_file: Output file path
        verbose: Enable verbose output
        quiet: Enable quiet mode
        **kwargs: Additional configuration options
    """
```

#### **Configuration Properties**
```python
# Scan configuration
config.target: str                    # Scan target
config.mode: str                      # Scan mode
config.framework: str                 # Target framework
config.report_format: str             # Output format

# Module configuration
config.modules: Dict[str, bool]       # Enable/disable modules
config.skip_modules: List[str]        # Modules to skip
config.only_modules: List[str]        # Only run these modules

# Performance configuration
config.threads: int                   # Number of threads
config.timeout: int                   # Scan timeout
config.memory_limit: int              # Memory limit

# AI configuration
config.ai_enhanced: bool              # Enable AI features
config.behavioral_analysis: bool      # Enable behavioral analysis
config.threat_intel: bool             # Enable threat intelligence
```

---

## 🛡️ **Vulnerability API**

### **Vulnerability Class**
**Location**: `njordscan.vulnerability.Vulnerability`

Standardized vulnerability representation.

```python
from njordscan import Vulnerability, Severity, Confidence

# Create vulnerability
vuln = Vulnerability(
    id="NJORD-XSS-001",
    title="Cross-Site Scripting Vulnerability",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="User input is not properly sanitized",
    fix="Sanitize user input using proper escaping",
    reference="https://owasp.org/xss",
    file_path="src/components/UserInput.jsx",
    line_number=42
)
```

#### **Vulnerability Properties**
```python
vuln.id: str                          # Unique vulnerability ID
vuln.title: str                       # Vulnerability title
vuln.severity: Severity               # Severity level
vuln.confidence: Confidence           # Confidence level
vuln.description: str                 # Detailed description
vuln.fix: str                         # Fix recommendation
vuln.reference: str                   # Reference URL
vuln.vuln_type: str                   # Vulnerability type
vuln.location: str                    # Location description
vuln.file_path: Optional[str]         # File path
vuln.line_number: Optional[int]       # Line number
vuln.code_snippet: Optional[str]      # Code snippet
vuln.framework: str                   # Target framework
vuln.module: str                      # Detecting module
vuln.metadata: Dict[str, Any]         # Additional metadata
```

### **Severity Enum**
```python
class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
```

### **Confidence Enum**
```python
class Confidence(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
```

---

## 🔍 **Module API**

### **BaseModule Class**
**Location**: `njordscan.modules.base.BaseModule`

Abstract base class for all scanning modules.

```python
from njordscan.modules.base import BaseModule
from njordscan.vulnerability import Vulnerability

class CustomModule(BaseModule):
    """Custom security scanning module."""
    
    async def scan(self, target: str) -> List[Vulnerability]:
        """Implement custom scanning logic."""
        vulnerabilities = []
        
        # Your scanning logic here
        
        return vulnerabilities
```

#### **Abstract Methods**
```python
async def scan(self, target: str) -> List[Vulnerability]:
    """
    Main scan method that must be implemented.
    
    Args:
        target: Target URL or directory path
        
    Returns:
        List of Vulnerability objects
    """
    pass
```

#### **Helper Methods**
```python
def should_run(self, mode: str) -> bool:
    """
    Determine if module should run based on scan mode.
    
    Args:
        mode: Scan mode (static, dynamic, full)
        
    Returns:
        Boolean indicating if module should run
    """

def create_vulnerability(self, 
                        title: str,
                        description: str,
                        severity: str,
                        confidence: str = "medium",
                        vuln_type: str = "",
                        file_path: Optional[str] = None,
                        line_number: Optional[int] = None,
                        code_snippet: Optional[str] = None,
                        fix: Optional[str] = None,
                        reference: Optional[str] = None,
                        metadata: Optional[Dict[str, Any]] = None) -> Vulnerability:
    """
    Create a standardized vulnerability object.
    
    Args:
        title: Vulnerability title
        description: Detailed description
        severity: Severity level (critical, high, medium, low, info)
        confidence: Confidence level (high, medium, low)
        vuln_type: Type of vulnerability
        file_path: File path where found
        line_number: Line number where found
        code_snippet: Code snippet
        fix: Fix recommendation
        reference: Reference URL
        metadata: Additional metadata
        
    Returns:
        Vulnerability object
    """

def get_file_content(self, file_path: str) -> Optional[str]:
    """
    Safely read file content.
    
    Args:
        file_path: Path to file
        
    Returns:
        File content or None if error
    """

def find_files_by_pattern(self, directory: str, patterns: List[str]) -> List[Path]:
    """
    Find files matching given patterns.
    
    Args:
        directory: Directory to search
        patterns: List of glob patterns
        
    Returns:
        List of matching file paths
    """
```

---

## 🔍 **Core Modules API**

### **HeadersModule**
**Location**: `njordscan.modules.headers.HeadersModule`

Scans for missing or misconfigured HTTP security headers.

```python
from njordscan.modules.headers import HeadersModule

# Initialize module
headers_module = HeadersModule(config, vuln_id_generator)

# Scan for header vulnerabilities
vulnerabilities = await headers_module.scan("https://example.com")
```

#### **Required Headers Checked**
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Strict-Transport-Security`
- `Referrer-Policy`
- `X-XSS-Protection`
- `Permissions-Policy`

### **CodeStaticModule**
**Location**: `njordscan.modules.code_static.CodeStaticModule`

Performs static code analysis for common vulnerabilities.

```python
from njordscan.modules.code_static import CodeStaticModule

# Initialize module
static_module = CodeStaticModule(config, vuln_id_generator)

# Scan for static code vulnerabilities
vulnerabilities = await static_module.scan("./src")
```

#### **Vulnerability Types Detected**
- Cross-Site Scripting (XSS)
- SQL Injection
- Command Injection
- Server-Side Request Forgery (SSRF)
- Insecure Direct Object Reference (IDOR)
- Hardcoded Secrets
- Insecure Random Number Generation

### **DependenciesModule**
**Location**: `njordscan.modules.dependencies.DependenciesModule`

Scans package dependencies for known vulnerabilities.

```python
from njordscan.modules.dependencies import DependenciesModule

# Initialize module
deps_module = DependenciesModule(config, vuln_id_generator)

# Scan dependencies
vulnerabilities = await deps_module.scan("./package.json")
```

#### **Checks Performed**
- Known CVE vulnerabilities
- Outdated packages
- License compliance
- Typosquatting detection
- Malicious package detection

### **ConfigsModule**
**Location**: `njordscan.modules.configs.ConfigsModule`

Analyzes configuration files for security issues.

```python
from njordscan.modules.configs import ConfigsModule

# Initialize module
configs_module = ConfigsModule(config, vuln_id_generator)

# Scan configuration files
vulnerabilities = await configs_module.scan("./config")
```

#### **Configuration Files Analyzed**
- `package.json`
- `next.config.js`
- `vite.config.js`
- `.env` files
- `tsconfig.json`
- `webpack.config.js`

### **RuntimeModule**
**Location**: `njordscan/modules.runtime.RuntimeModule`

Performs dynamic analysis of running applications.

```python
from njordscan.modules.runtime import RuntimeModule

# Initialize module
runtime_module = RuntimeModule(config, vuln_id_generator)

# Scan running application
vulnerabilities = await runtime_module.scan("https://example.com")
```

#### **Runtime Tests**
- HTTP security headers
- SSL/TLS configuration
- Authentication bypass
- Session management
- Input validation
- Error handling

### **AIEndpointsModule**
**Location**: `njordscan.modules.ai_endpoints.AIEndpointsModule`

Analyzes AI-specific vulnerabilities and configurations.

```python
from njordscan.modules.ai_endpoints import AIEndpointsModule

# Initialize module
ai_module = AIEndpointsModule(config, vuln_id_generator)

# Scan AI endpoints
vulnerabilities = await ai_module.scan("./src/ai")
```

#### **AI-Specific Checks**
- API key exposure
- Prompt injection vulnerabilities
- Unsafe AI usage patterns
- AI configuration issues
- Data privacy concerns

---

## ⚛️ **Framework Analyzers API**

### **FrameworkDetector**
**Location**: `njordscan.frameworks.framework_detector.FrameworkDetector`

Intelligent framework detection system.

```python
from njordscan.frameworks import FrameworkDetector

# Initialize detector
detector = FrameworkDetector()

# Detect framework
result = detector.detect_framework(Path("./my-project"))
print(f"Framework: {result.framework}")
print(f"Version: {result.version}")
print(f"Features: {result.features}")
```

#### **DetectionResult**
```python
@dataclass
class FrameworkDetectionResult:
    framework: str                    # Detected framework
    version: str                      # Framework version
    confidence: float                 # Detection confidence
    features: Set[str]                # Detected features
    files_analyzed: List[str]         # Files that were analyzed
    detection_method: str             # Method used for detection
```

### **NextJSAnalyzer**
**Location**: `njordscan.frameworks.nextjs_analyzer.NextJSAnalyzer`

Advanced security analyzer for Next.js applications.

```python
from njordscan.frameworks import NextJSAnalyzer

# Initialize analyzer
analyzer = NextJSAnalyzer()

# Analyze Next.js project
vulnerabilities = analyzer.analyze_project(Path("./nextjs-project"))
```

#### **Next.js Specific Checks**
- SSRF in image optimization
- Exposed API routes
- Server-side XSS in SSR
- Information disclosure in getServerSideProps
- Authentication bypass in middleware

### **ReactAnalyzer**
**Location**: `njordscan.frameworks.react_analyzer.ReactAnalyzer`

Security analyzer for React applications.

```python
from njordscan.frameworks import ReactAnalyzer

# Initialize analyzer
analyzer = ReactAnalyzer()

# Analyze React project
vulnerabilities = analyzer.analyze_project(Path("./react-project"))
```

#### **React Specific Checks**
- XSS prevention in JSX
- State management security
- Component security patterns
- Hook security analysis
- Virtual DOM security implications

### **ViteAnalyzer**
**Location**: `njordscan.frameworks.vite_analyzer.ViteAnalyzer`

Security analyzer for Vite applications.

```python
from njordscan.frameworks import ViteAnalyzer

# Initialize analyzer
analyzer = ViteAnalyzer()

# Analyze Vite project
vulnerabilities = analyzer.analyze_project(Path("./vite-project"))
```

#### **Vite Specific Checks**
- Build process security
- Development server security
- Plugin security validation
- Asset handling security
- Hot module replacement security

---

## 🔌 **Plugin API**

### **PluginInterface**
**Location**: `njordscan.plugins_v2.plugin_manager.PluginInterface`

Base interface for all plugins.

```python
from njordscan.plugins_v2 import PluginInterface, PluginMetadata

class CustomPlugin(PluginInterface):
    """Custom security plugin."""
    
    async def initialize(self) -> bool:
        """Initialize the plugin."""
        return True
    
    async def activate(self) -> bool:
        """Activate the plugin."""
        return True
    
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            id="custom-plugin",
            name="Custom Security Plugin",
            version="1.0.0",
            description="Custom security analysis plugin",
            author="Your Name",
            plugin_type=PluginType.SCANNER
        )
```

#### **Plugin Methods**
```python
async def initialize(self) -> bool:
    """Initialize the plugin. Return True if successful."""

async def activate(self) -> bool:
    """Activate the plugin. Return True if successful."""

async def deactivate(self) -> bool:
    """Deactivate the plugin. Return True if successful."""

async def cleanup(self) -> bool:
    """Cleanup plugin resources. Return True if successful."""

def get_metadata(self) -> PluginMetadata:
    """Get plugin metadata."""

def register_service(self, service_name: str, service: Any):
    """Register a service provided by this plugin."""

def get_service(self, service_name: str) -> Any:
    """Get a service by name."""

def register_hook(self, hook_name: str, callback: Callable):
    """Register a hook callback."""
```

### **PluginManager**
**Location**: `njordscan.plugins_v2.plugin_manager.PluginManager`

Advanced plugin management system.

```python
from njordscan.plugins_v2 import PluginManager

# Initialize plugin manager
plugin_manager = PluginManager()

# Load plugins
await plugin_manager.initialize()

# Get plugin
plugin = plugin_manager.get_plugin("plugin-name")

# Register plugin
plugin_manager.register_plugin(plugin_instance)
```

#### **PluginManager Methods**
```python
async def initialize(self):
    """Initialize the plugin manager."""

async def load_plugin(self, plugin_path: str) -> bool:
    """Load a plugin from file path."""

async def unload_plugin(self, plugin_id: str) -> bool:
    """Unload a plugin by ID."""

def get_plugin(self, plugin_id: str) -> Optional[PluginInstance]:
    """Get plugin instance by ID."""

def list_plugins(self) -> List[PluginInstance]:
    """List all loaded plugins."""

def register_plugin(self, plugin: PluginInterface):
    """Register a plugin instance."""
```

---

## 📊 **Reporting API**

### **ReportFormatter**
**Location**: `njordscan.report.formatter.ReportFormatter`

Formats scan results into various output formats.

```python
from njordscan.report.formatter import ReportFormatter

# Initialize formatter
formatter = ReportFormatter(config)

# Format results
html_report = formatter.format_report(results, "html")
json_report = formatter.format_report(results, "json")
```

#### **Supported Formats**
- `terminal`: Rich console output
- `html`: Interactive web reports
- `json`: Machine-readable format
- `sarif`: GitHub Security tab integration
- `csv`: Spreadsheet-compatible format
- `xml`: Enterprise integration format

#### **ReportFormatter Methods**
```python
def format_report(self, results: ScanResults, format_type: str) -> str:
    """
    Format scan results into specified format.
    
    Args:
        results: Scan results to format
        format_type: Output format type
        
    Returns:
        Formatted report string
    """

def format_vulnerability(self, vuln: Vulnerability, format_type: str) -> str:
    """
    Format single vulnerability.
    
    Args:
        vuln: Vulnerability to format
        format_type: Output format type
        
    Returns:
        Formatted vulnerability string
    """
```

---

## 🧠 **Intelligence API**

### **IntelligenceOrchestrator**
**Location**: `njordscan.intelligence.intelligence_orchestrator.IntelligenceOrchestrator`

Master security intelligence orchestrator.

```python
from njordscan.intelligence import IntelligenceOrchestrator

# Initialize orchestrator
intel_orchestrator = IntelligenceOrchestrator()

# Perform intelligence analysis
report = await intel_orchestrator.analyze_vulnerabilities(
    vulnerabilities=vulnerabilities,
    context=analysis_context
)
```

#### **IntelligenceOrchestrator Methods**
```python
async def analyze_vulnerabilities(self, 
                                vulnerabilities: List[Vulnerability],
                                context: Dict[str, Any] = None) -> IntelligenceReport:
    """
    Perform comprehensive intelligence analysis.
    
    Args:
        vulnerabilities: List of vulnerabilities to analyze
        context: Additional analysis context
        
    Returns:
        Intelligence analysis report
    """

async def correlate_threats(self, 
                          indicators: List[ThreatIndicator]) -> CorrelationResult:
    """
    Correlate threat indicators.
    
    Args:
        indicators: List of threat indicators
        
    Returns:
        Correlation analysis result
    """
```

### **AISecurityOrchestrator**
**Location**: `njordscan.ai.ai_orchestrator.AISecurityOrchestrator`

AI-powered security analysis orchestrator.

```python
from njordscan.ai import AISecurityOrchestrator

# Initialize AI orchestrator
ai_orchestrator = AISecurityOrchestrator()

# Perform AI analysis
result = await ai_orchestrator.perform_comprehensive_analysis(
    target="./my-project",
    data=scan_data
)
```

#### **AISecurityOrchestrator Methods**
```python
async def perform_comprehensive_analysis(self, 
                                       target: str, 
                                       data: Dict[str, Any],
                                       context: Dict[str, Any] = None) -> AIAnalysisResult:
    """
    Perform comprehensive AI-powered analysis.
    
    Args:
        target: Analysis target
        data: Scan data to analyze
        context: Additional context
        
    Returns:
        AI analysis result
    """
```

---

## ⚡ **Performance API**

### **PerformanceOrchestrator**
**Location**: `njordscan.performance.performance_orchestrator.PerformanceOrchestrator`

Performance optimization orchestrator.

```python
from njordscan.performance import PerformanceOrchestrator

# Initialize performance orchestrator
perf_orchestrator = PerformanceOrchestrator()

# Optimize scan performance
optimized_config = perf_orchestrator.optimize_scan_config(config)
```

#### **PerformanceOrchestrator Methods**
```python
def optimize_scan_config(self, config: Config) -> Config:
    """
    Optimize scan configuration for performance.
    
    Args:
        config: Original configuration
        
    Returns:
        Optimized configuration
    """

def get_performance_metrics(self) -> Dict[str, Any]:
    """
    Get current performance metrics.
    
    Returns:
        Performance metrics dictionary
    """
```

### **CacheManager**
**Location**: `njordscan.cache.CacheManager`

Intelligent caching system.

```python
from njordscan.cache import CacheManager

# Initialize cache manager
cache_manager = CacheManager(enabled=True)

# Cache scan results
cache_manager.set("scan_results", results, ttl=3600)

# Retrieve cached results
cached_results = cache_manager.get("scan_results")
```

#### **CacheManager Methods**
```python
def set(self, key: str, value: Any, ttl: int = None):
    """
    Set cache value.
    
    Args:
        key: Cache key
        value: Value to cache
        ttl: Time to live in seconds
    """

def get(self, key: str) -> Optional[Any]:
    """
    Get cached value.
    
    Args:
        key: Cache key
        
    Returns:
        Cached value or None
    """

def clear(self):
    """Clear all cache entries."""

def get_stats(self) -> Dict[str, Any]:
    """
    Get cache statistics.
    
    Returns:
        Cache statistics dictionary
    """
```

---

## 🔧 **Utility API**

### **NjordScore**
**Location**: `njordscan.utils.NjordScore`

Security scoring system.

```python
from njordscan.utils import NjordScore

# Initialize scoring system
score = NjordScore()

# Calculate security score
security_score = score.calculate_score(vulnerabilities)
print(f"Security Score: {security_score.score}/10")
```

#### **NjordScore Methods**
```python
def calculate_score(self, vulnerabilities: List[Vulnerability]) -> SecurityScore:
    """
    Calculate security score from vulnerabilities.
    
    Args:
        vulnerabilities: List of vulnerabilities
        
    Returns:
        Security score object
    """
```

### **Framework Detection Utilities**
**Location**: `njordscan.utils`

```python
from njordscan.utils import detect_framework

# Detect framework from directory
framework = detect_framework("./my-project")
print(f"Detected framework: {framework}")

# Detect framework from URL
framework = detect_framework("https://example.com")
```

---

## 📝 **Usage Examples**

### **Basic Scanning**
```python
import asyncio
from njordscan import ScanOrchestrator, Config

async def main():
    # Create configuration
    config = Config(
        target="./my-nextjs-project",
        mode="standard",
        framework="nextjs",
        report_format="json"
    )
    
    # Initialize scanner
    scanner = ScanOrchestrator(config)
    
    # Run scan
    results = await scanner.scan()
    
    # Print results
    print(f"Found {len(results.vulnerabilities)} vulnerabilities")
    for vuln in results.vulnerabilities:
        print(f"- {vuln.title} ({vuln.severity.value})")

if __name__ == "__main__":
    asyncio.run(main())
```

### **Custom Module Development**
```python
import asyncio
from njordscan.modules.base import BaseModule
from njordscan.vulnerability import Vulnerability, Severity, Confidence

class CustomSecurityModule(BaseModule):
    """Custom security scanning module."""
    
    async def scan(self, target: str) -> List[Vulnerability]:
        """Scan for custom security issues."""
        vulnerabilities = []
        
        # Your custom scanning logic here
        if self._check_custom_vulnerability(target):
            vuln = self.create_vulnerability(
                title="Custom Security Issue",
                description="Description of the custom security issue",
                severity="high",
                confidence="medium",
                vuln_type="custom",
                file_path=target,
                fix="Custom fix recommendation"
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _check_custom_vulnerability(self, target: str) -> bool:
        """Check for custom vulnerability."""
        # Your custom logic here
        return True

# Use custom module
async def main():
    config = Config(target="./my-project")
    vuln_id_generator = VulnerabilityIdGenerator()
    
    custom_module = CustomSecurityModule(config, vuln_id_generator)
    vulnerabilities = await custom_module.scan("./my-project")
    
    print(f"Found {len(vulnerabilities)} custom vulnerabilities")

if __name__ == "__main__":
    asyncio.run(main())
```

### **Plugin Development**
```python
from njordscan.plugins_v2 import PluginInterface, PluginMetadata, PluginType

class CustomPlugin(PluginInterface):
    """Custom security plugin."""
    
    async def initialize(self) -> bool:
        """Initialize the plugin."""
        self.logger.info("Custom plugin initialized")
        return True
    
    async def activate(self) -> bool:
        """Activate the plugin."""
        self.logger.info("Custom plugin activated")
        return True
    
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            id="custom-security-plugin",
            name="Custom Security Plugin",
            version="1.0.0",
            description="Custom security analysis plugin",
            author="Your Name",
            plugin_type=PluginType.SCANNER,
            frameworks=["nextjs", "react"],
            categories=["static_analysis"]
        )
    
    async def scan(self, target: str) -> List[Vulnerability]:
        """Perform custom security scan."""
        # Your custom scanning logic here
        return []
```

---

<div align="center">

## 📚 **API Reference Complete**

**This API reference covers all major components of NjordScan's architecture and provides examples for common use cases.**

[**🏗️ Architecture Overview**](architecture.md) | [**📋 CLI Reference**](../user-guide/cli-reference.md) | [**🛡️ Security Features**](../security/vulnerability-types.md)

</div>
