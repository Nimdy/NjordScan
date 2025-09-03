"""
🛡️ Enhanced Configuration Management for NjordScan v1.0.0

Comprehensive configuration handling with support for all advanced features including
AI-powered analysis, community features, enterprise settings, and performance optimization.
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, field, asdict
from enum import Enum

# Optional TOML support
try:
    import toml
    TOML_AVAILABLE = True
except ImportError:
    TOML_AVAILABLE = False

class ScanMode(Enum):
    """Available scanning modes."""
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    ENTERPRISE = "enterprise"

class Theme(Enum):
    """UI themes."""
    DEFAULT = "default"
    DARK = "dark"
    CYBERPUNK = "cyberpunk"
    HACKER = "hacker"
    PROFESSIONAL = "professional"

@dataclass
class AIConfig:
    """AI-powered analysis configuration."""
    enabled: bool = False
    behavioral_analysis: bool = False
    threat_intelligence: bool = False
    confidence_threshold: float = 0.7

@dataclass
class CommunityConfig:
    """Community features configuration."""
    enabled: bool = False
    share_anonymous_stats: bool = True
    download_community_rules: bool = True
    user_token: Optional[str] = None

@dataclass
class PerformanceConfig:
    """Performance optimization configuration."""
    max_threads: int = 4
    memory_limit_mb: int = 2048
    timeout_seconds: int = 300
    cache_strategy: str = "intelligent"

@dataclass
class Config:
    """Enhanced configuration class for NjordScan."""
    
    # Core settings
    target: str = "."
    mode: str = "standard"
    framework: str = "auto"
    security_level: str = "standard"
    
    # Output and reporting
    report_format: str = "terminal"
    output_file: Optional[str] = None
    min_severity: str = "info"
    verbose: bool = False
    quiet: bool = False
    no_color: bool = False
    
    # UI and experience
    theme: str = "default"
    interactive: bool = False
    show_progress: bool = True
    
    # Scanning behavior
    use_cache: bool = True
    force_scan: bool = False
    include_tests: bool = False
    pentest_mode: bool = False
    
    # Performance settings
    max_concurrent: int = 10
    timeout: int = 300
    rate_limit: float = 1.0
    memory_limit: Optional[int] = None
    threads: Optional[int] = None
    
    # Advanced features
    ai_enhanced: bool = False
    behavioral_analysis: bool = False
    threat_intel: bool = False
    community_rules: bool = False
    
    # CI/CD settings
    ci_mode: bool = False
    fail_on: Optional[str] = None
    quality_gate: Optional[str] = None
    
    # Module control
    skip_modules: List[str] = field(default_factory=list)
    only_modules: List[str] = field(default_factory=list)
    
    # Advanced configurations
    ai_config: AIConfig = field(default_factory=AIConfig)
    community_config: CommunityConfig = field(default_factory=CommunityConfig)
    performance_config: PerformanceConfig = field(default_factory=PerformanceConfig)
    
    # Additional settings
    cache_strategy: str = "intelligent"
    include_remediation: bool = True
    executive_summary: bool = False
    
    # Plugin settings
    plugins: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # Path exclusions
    exclude_paths: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Post-initialization validation and setup."""
        # Set up AI config based on flags
        if self.ai_enhanced:
            self.ai_config.enabled = True
        if self.behavioral_analysis:
            self.ai_config.behavioral_analysis = True
        if self.threat_intel:
            self.ai_config.threat_intelligence = True
        if self.community_rules:
            self.community_config.enabled = True
        
        # Set up performance config
        if self.threads:
            self.performance_config.max_threads = self.threads
        if self.memory_limit:
            self.performance_config.memory_limit_mb = self.memory_limit
        if self.timeout:
            self.performance_config.timeout_seconds = self.timeout
        
        # Set up default exclusions
        if not self.exclude_paths:
            self.exclude_paths = [
                "node_modules/**",
                ".git/**", 
                ".next/**",
                "dist/**",
                "build/**",
                "coverage/**",
                "*.min.js"
            ]
        
        # Run validation and setup
        self._validate_config()
        self._load_framework_configs()
        self._setup_default_modules()
        self._setup_default_exclusions()
        self._setup_default_plugins()
    
    # Custom rules
    custom_rules_file: Optional[str] = None
    
    # Output filtering
    max_issues_per_type: int = 50  # Limit issues per vulnerability type
    hide_info_issues: bool = False
    
    def _validate_config(self):
        """Validate configuration values."""
        # Validate mode
        valid_modes = ['quick', 'standard', 'deep', 'enterprise', 'static', 'dynamic', 'full']
        if self.mode not in valid_modes:
            raise ValueError(f"Invalid mode: {self.mode}. Must be one of {valid_modes}")
        
        # Validate framework
        valid_frameworks = ['nextjs', 'react', 'vite', 'auto']
        if self.framework not in valid_frameworks:
            raise ValueError(f"Invalid framework: {self.framework}. Must be one of {valid_frameworks}")
        
        # Validate report format
        valid_formats = ['terminal', 'text', 'json', 'html', 'sarif', 'csv', 'xml']
        if self.report_format not in valid_formats:
            raise ValueError(f"Invalid report format: {self.report_format}. Must be one of {valid_formats}")
        
        # Validate severity
        valid_severities = ['info', 'low', 'medium', 'high', 'critical']
        if self.min_severity not in valid_severities:
            raise ValueError(f"Invalid severity: {self.min_severity}. Must be one of {valid_severities}")
        
        # Validate performance settings
        if self.max_concurrent < 1:
            raise ValueError("max_concurrent must be >= 1")
        
        if self.timeout < 1:
            raise ValueError("timeout must be >= 1")
        
        if self.rate_limit <= 0:
            raise ValueError("rate_limit must be > 0")
        
        # Validate paths
        if self.target and not self.target.startswith(('http://', 'https://')):
            target_path = Path(self.target)
            if not target_path.exists():
                raise ValueError(f"Target directory does not exist: {self.target}")
    
    def _load_framework_configs(self):
        """Load framework-specific configurations."""
        
        # Next.js configuration
        nextjs_config = {
            "config_files": [
                "next.config.js", "next.config.ts", "next.config.mjs",
                "middleware.js", "middleware.ts"
            ],
            "env_files": [
                ".env.local", ".env.development", ".env.production", ".env"
            ],
            "api_patterns": [
                "pages/api/**/*.js", "pages/api/**/*.ts",
                "app/api/**/*.js", "app/api/**/*.ts"
            ],
            "security_headers": [
                "Content-Security-Policy", "X-Frame-Options",
                "X-Content-Type-Options", "Referrer-Policy"
            ],
            "vulnerable_patterns": {
                "ssrf": [
                    r"_next/image.*url=.*",
                    r"getServerSideProps.*fetch.*req\."
                ],
                "xss": [
                    r"dangerouslySetInnerHTML",
                    r"router\.push.*\$\{.*\}"
                ],
                "secrets": [
                    r"NEXT_PUBLIC_.*['\"]?\s*[:=]\s*['\"][^'\"]{20,}['\"]"
                ]
            }
        }
        
        # React configuration
        react_config = {
            "config_files": [
                "package.json", "webpack.config.js", "craco.config.js",
                "react-scripts.config.js"
            ],
            "build_files": [
                "build/**/*.js", "dist/**/*.js"
            ],
            "vulnerable_patterns": {
                "xss": [
                    r"dangerouslySetInnerHTML",
                    r"innerHTML\s*=.*\+.*",
                    r"React\.createElement.*script"
                ],
                "code_injection": [
                    r"eval\(",
                    r"Function\(",
                    r"setTimeout.*\$\{.*\}"
                ]
            }
        }
        
        # Vite configuration
        vite_config = {
            "config_files": [
                "vite.config.js", "vite.config.ts", "vite.config.mjs"
            ],
            "dev_files": [
                "src/**/*.js", "src/**/*.ts", "src/**/*.jsx", "src/**/*.tsx"
            ],
            "vulnerable_patterns": {
                "dev_exposure": [
                    r"import\.meta\.hot",
                    r"server\.hmr"
                ],
                "fs_access": [
                    r"fs\.allow.*\.\./",
                    r"server\.fs\.allow"
                ],
                "proxy_issues": [
                    r"server\.proxy.*target.*"
                ]
            }
        }
        
        self.framework_configs = {
            "nextjs": nextjs_config,
            "react": react_config,
            "vite": vite_config
        }
    
    def _setup_default_modules(self):
        """Setup default enabled modules based on mode."""
        # New system uses only_modules and skip_modules instead
        pass
    
    def _setup_default_exclusions(self):
        """Setup default path exclusions."""
        if not self.exclude_paths:
            self.exclude_paths = [
                "node_modules/**",
                ".git/**",
                ".next/**",
                "dist/**",
                "build/**",
                "__pycache__/**",
                ".pytest_cache/**",
                "coverage/**",
                ".nyc_output/**",
                "vendor/**",
                ".svn/**",
                ".hg/**",
                "*.min.js",
                "*.min.css",
                "*.map"
            ]
    
    def _setup_default_plugins(self):
        """Setup default plugin configurations."""
        if not self.plugins:
            self.plugins = {
                "nextjs_advanced": {
                    "enabled": True,
                    "config": {
                        "scan_api_routes": True,
                        "check_middleware": True,
                        "deep_scan_components": False
                    }
                }
            }
    
    def get_framework_config(self, framework: str = None) -> Dict[str, Any]:
        """Get configuration for a specific framework."""
        framework = framework or self.framework
        return self.framework_configs.get(framework, {})
    
    def is_module_enabled(self, module_name: str) -> bool:
        """Check if a module is enabled."""
        # If only_modules is specified, only those are enabled
        if self.only_modules:
            return module_name in self.only_modules
        
        # Otherwise, all modules are enabled except skipped ones
        return module_name not in self.skip_modules
    
    def is_plugin_enabled(self, plugin_name: str) -> bool:
        """Check if a plugin is enabled."""
        plugin_config = self.plugins.get(plugin_name, {})
        return plugin_config.get('enabled', False)
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of issues."""
        issues = []
        
        # Validate target
        if not self.target:
            issues.append("Target cannot be empty")
        
        # Validate mode
        valid_modes = ['quick', 'standard', 'deep', 'enterprise']
        if self.mode not in valid_modes:
            issues.append(f"Mode must be one of: {', '.join(valid_modes)}")
        
        # Validate framework
        valid_frameworks = ['nextjs', 'react', 'vite', 'auto']
        if self.framework not in valid_frameworks:
            issues.append(f"Framework must be one of: {', '.join(valid_frameworks)}")
        
        # Validate report format
        valid_formats = ['terminal', 'text', 'json', 'html', 'sarif', 'csv', 'xml']
        if self.report_format not in valid_formats:
            issues.append(f"Report format must be one of: {', '.join(valid_formats)}")
        
        # Validate severity
        valid_severities = ['info', 'low', 'medium', 'high', 'critical']
        if self.min_severity not in valid_severities:
            issues.append(f"Minimum severity must be one of: {', '.join(valid_severities)}")
        
        return issues
    
    def get_plugin_config(self, plugin_name: str) -> Dict[str, Any]:
        """Get configuration for a specific plugin."""
        return self.plugins.get(plugin_name, {})
    
    def should_exclude_path(self, file_path: Union[str, Path]) -> bool:
        """Check if a path should be excluded from scanning."""
        file_path_str = str(file_path)
        
        for pattern in self.exclude_paths:
            # Simple glob-style matching
            if pattern.endswith('/**'):
                dir_pattern = pattern[:-3]
                if dir_pattern in file_path_str:
                    return True
            elif pattern.endswith('/*'):
                dir_pattern = pattern[:-2]
                if file_path_str.startswith(dir_pattern):
                    return True
            elif '*' in pattern:
                # Basic wildcard matching
                import fnmatch
                if fnmatch.fnmatch(file_path_str, pattern):
                    return True
            else:
                if pattern in file_path_str:
                    return True
        
        return False
    
    def get_severity_weight(self, severity: str) -> int:
        """Get numeric weight for severity level."""
        weights = {
            'info': 1,
            'low': 2,
            'medium': 3,
            'high': 4,
            'critical': 5
        }
        return weights.get(severity.lower(), 1)
    
    def should_report_severity(self, severity: str) -> bool:
        """Check if severity level should be reported."""
        min_weight = self.get_severity_weight(self.min_severity)
        severity_weight = self.get_severity_weight(severity)
        return severity_weight >= min_weight
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary for serialization."""
        return {
            "target": self.target,
            "mode": self.mode,
            "framework": self.framework,
            "report_format": self.report_format,
            "output_file": self.output_file,
            "include_remediation": self.include_remediation,
            "min_severity": self.min_severity,
            "pentest_mode": self.pentest_mode,
            "verbose": self.verbose,
            "use_cache": self.use_cache,
            "force_scan": self.force_scan,
            "include_tests": self.include_tests,
            "max_concurrent": self.max_concurrent,
            "timeout": self.timeout,
            "rate_limit": self.rate_limit,
            "only_modules": self.only_modules,
            "skip_modules": self.skip_modules,
            "plugins": self.plugins,
            "exclude_paths": self.exclude_paths,
            "custom_rules_file": self.custom_rules_file,
            "max_issues_per_type": self.max_issues_per_type,
            "hide_info_issues": self.hide_info_issues
        }
    
    @classmethod
    def from_file(cls, config_file: str) -> 'Config':
        """Load configuration from file."""
        config_path = Path(config_file)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_file}")
        
        with open(config_path, 'r') as f:
            if config_path.suffix.lower() in ['.yaml', '.yml']:
                data = yaml.safe_load(f)
            else:
                data = json.load(f)
        
        # Filter out None values and unknown keys
        known_keys = {field.name for field in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in known_keys and v is not None}
        
        return cls(**filtered_data)
    
    @classmethod
    def load_from_file(cls, config_file: str) -> 'Config':
        """Alias for from_file method for backward compatibility."""
        return cls.from_file(config_file)
    
    @classmethod
    def from_env(cls) -> 'Config':
        """Load configuration from environment variables."""
        env_mapping = {
            'NJORDSCAN_TARGET': 'target',
            'NJORDSCAN_MODE': 'mode',
            'NJORDSCAN_FRAMEWORK': 'framework',
            'NJORDSCAN_REPORT_FORMAT': 'report_format',
            'NJORDSCAN_OUTPUT_FILE': 'output_file',
            'NJORDSCAN_PENTEST_MODE': 'pentest_mode',
            'NJORDSCAN_VERBOSE': 'verbose',
            'NJORDSCAN_NO_CACHE': 'use_cache',
            'NJORDSCAN_MAX_CONCURRENT': 'max_concurrent',
            'NJORDSCAN_TIMEOUT': 'timeout'
        }
        
        config_data = {}
        for env_var, config_key in env_mapping.items():
            if env_var in os.environ:
                value = os.environ[env_var]
                
                # Type conversion
                if config_key in ['pentest_mode', 'verbose', 'suggest_fixes']:
                    config_data[config_key] = value.lower() in ['true', '1', 'yes', 'on']
                elif config_key == 'use_cache' and env_var == 'NJORDSCAN_NO_CACHE':
                    config_data[config_key] = not (value.lower() in ['true', '1', 'yes', 'on'])
                elif config_key in ['max_concurrent', 'timeout']:
                    config_data[config_key] = int(value)
                elif config_key == 'rate_limit':
                    config_data[config_key] = float(value)
                else:
                    config_data[config_key] = value
        
        return cls(**config_data)
    
    def save_to_file(self, config_file: str):
        """Save current configuration to file."""
        config_path = Path(config_file)
        config_data = self.to_dict()
        
        with open(config_path, 'w') as f:
            if config_path.suffix.lower() in ['.yaml', '.yml']:
                yaml.dump(config_data, f, default_flow_style=False, indent=2)
            else:
                json.dump(config_data, f, indent=2)
    
    def display(self):
        """Display current configuration in a formatted way."""
        from rich.console import Console
        from rich.table import Table
        
        console = Console()
        
        table = Table(title="NjordScan Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")
        
        config_dict = self.to_dict()
        for key, value in config_dict.items():
            if value is not None:
                table.add_row(key.replace('_', ' ').title(), str(value))
        
        console.print(table)