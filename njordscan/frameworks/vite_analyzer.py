"""
Advanced Vite Security Analyzer

Provides deep security analysis specifically for Vite applications.
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import logging

from .base_framework_analyzer import BaseFrameworkAnalyzer, FrameworkVulnerability, FrameworkContext

logger = logging.getLogger(__name__)

class ViteAnalyzer(BaseFrameworkAnalyzer):
    """Advanced security analyzer for Vite applications."""
    
    def __init__(self):
        super().__init__("vite")
        
        # Vite specific file patterns
        self.file_patterns = {
            'config': [r'vite\.config\.(js|ts|mjs)$', r'vitest\.config\.(js|ts)$'],
            'env': [r'\.env\..*$', r'\.env$'],
            'src': [r'src/.*\.(js|jsx|ts|tsx|vue|svelte)$'],
            'public': [r'public/.*$'],
            'build': [r'dist/.*$', r'build/.*$']
        }
        
        # Vite specific security patterns
        self.vite_patterns = {
            'env_exposure': [
                r'import\.meta\.env\.VITE_[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD)',
                r'VITE_[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD)\s*=',
                r'import\.meta\.env\.VITE_.*[\'"`][a-zA-Z0-9+/=]{20,}[\'"`]'
            ],
            'hmr_production': [
                r'import\.meta\.hot(?!\s*&&\s*import\.meta\.env\.DEV)',
                r'if\s*\(\s*import\.meta\.hot\s*\)(?!.*import\.meta\.env\.DEV)',
                r'module\.hot(?!\s*&&\s*process\.env\.NODE_ENV.*development)'
            ],
            'unsafe_dynamic_imports': [
                r'import\s*\(\s*[\'"`]\.\./\.\./.*[\'"`]\s*\)',
                r'import\s*\(\s*.*\$\{[^}]*\}.*\)',
                r'import\s*\(\s*[^)]*req\.(query|body|params)',
            ],
            'build_exposure': [
                r'define\s*:\s*\{[^}]*process\.env[^}]*\}',
                r'VITE_.*:\s*JSON\.stringify\s*\(\s*process\.env',
                r'global\s*:\s*globalThis'
            ],
            'dev_server_issues': [
                r'server\s*:\s*\{[^}]*host\s*:\s*[\'"`]0\.0\.0\.0[\'"`]',
                r'server\s*:\s*\{[^}]*host\s*:\s*true',
                r'server\s*:\s*\{[^}]*cors\s*:\s*true'
            ],
            'plugin_security': [
                r'plugins\s*:\s*\[[^\]]*require\s*\([^)]*\$\{',
                r'plugins\s*:\s*\[[^\]]*import\s*\([^)]*user',
                r'rollupOptions\s*:\s*\{[^}]*external\s*:\s*function'
            ]
        }
        
        # Vite specific security features
        self.vite_security_features = {
            'csp_plugins': ['vite-plugin-csp', '@vitejs/plugin-csp'],
            'security_headers': ['vite-plugin-headers', 'vite-plugin-helmet'],
            'env_validation': ['vite-plugin-env-validation', '@t3-oss/env-core'],
            'bundle_analysis': ['vite-bundle-analyzer', 'rollup-plugin-analyzer'],
            'minification': ['terser', 'esbuild']
        }
        
        # Framework integrations with Vite
        self.vite_frameworks = {
            'react': ['@vitejs/plugin-react', '@vitejs/plugin-react-swc'],
            'vue': ['@vitejs/plugin-vue', '@vitejs/plugin-vue-jsx'],
            'svelte': ['@sveltejs/vite-plugin-svelte'],
            'solid': ['vite-plugin-solid'],
            'preact': ['@preact/preset-vite']
        }
    
    def analyze_project(self, project_path: Path) -> List[FrameworkVulnerability]:
        """Analyze Vite project for security vulnerabilities."""
        
        vulnerabilities = []
        context = self.create_framework_context(project_path)
        
        # Analyze Vite configuration
        vulnerabilities.extend(self._analyze_vite_config(context))
        
        # Analyze environment files
        vulnerabilities.extend(self._analyze_vite_env_files(project_path, context))
        
        # Analyze source directory
        src_dir = project_path / 'src'
        if src_dir.exists():
            vulnerabilities.extend(self._analyze_vite_src_directory(src_dir, context))
        
        # Analyze public directory
        public_dir = project_path / 'public'
        if public_dir.exists():
            vulnerabilities.extend(self._analyze_vite_public_directory(public_dir, context))
        
        # Analyze build output if present
        vulnerabilities.extend(self._analyze_vite_build_output(project_path, context))
        
        # Analyze package.json for Vite specific issues
        vulnerabilities.extend(self._analyze_package_json_vite(context))
        
        # Check Vite security best practices
        vulnerabilities.extend(self._check_vite_security_practices(project_path, context))
        
        return vulnerabilities
    
    def detect_framework_features(self, context: FrameworkContext) -> Set[str]:
        """Detect Vite specific features."""
        features = set()
        
        if context.package_json:
            dependencies = {**context.dependencies, **context.dev_dependencies}
            
            # Check for Vite
            if 'vite' in dependencies:
                features.add('vite')
                
                # Version-specific features
                vite_version = dependencies['vite']
                if any(v in vite_version for v in ['4.', '5.']):
                    features.add(f'vite_{vite_version.split(".")[0]}')
            
            # Check for Vite plugins
            vite_plugins = [
                '@vitejs/plugin-react', '@vitejs/plugin-vue', '@vitejs/plugin-legacy',
                'vite-plugin-pwa', 'vite-plugin-windicss', 'vite-plugin-eslint',
                'vite-plugin-mock', 'vite-plugin-components'
            ]
            
            for plugin in vite_plugins:
                if plugin in dependencies:
                    plugin_name = plugin.replace('@vitejs/plugin-', '').replace('vite-plugin-', '')
                    features.add(f'plugin_{plugin_name}')
            
            # Check for framework integrations
            for framework, plugins in self.vite_frameworks.items():
                if any(plugin in dependencies for plugin in plugins):
                    features.add(f'{framework}_integration')
            
            # Check for build tools
            if 'vitest' in dependencies:
                features.add('vitest_testing')
            
            if 'storybook' in str(dependencies):
                features.add('storybook_integration')
        
        # Check for configuration files
        if context.project_root:
            config_files = [
                'vite.config.js', 'vite.config.ts', 'vite.config.mjs',
                'vitest.config.js', 'vitest.config.ts'
            ]
            
            for config_file in config_files:
                if (context.project_root / config_file).exists():
                    features.add('config_present')
                    break
        
        return features
    
    def _analyze_framework_specific(self, file_path: Path, content: str, 
                                  context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze Vite specific security patterns."""
        
        vulnerabilities = []
        
        # Determine file type for context-aware analysis
        file_type = self._determine_vite_file_type(file_path, content)
        
        # Analyze based on file type
        if file_type == 'config':
            vulnerabilities.extend(self._analyze_vite_config_file(file_path, content, context))
        elif file_type == 'env':
            vulnerabilities.extend(self._analyze_vite_env_file(file_path, content, context))
        elif file_type == 'src':
            vulnerabilities.extend(self._analyze_vite_src_file(file_path, content, context))
        
        # General Vite pattern analysis
        vulnerabilities.extend(self._analyze_vite_patterns(file_path, content, context))
        
        return vulnerabilities
    
    def _determine_vite_file_type(self, file_path: Path, content: str) -> str:
        """Determine the type of Vite-related file."""
        
        path_str = str(file_path).lower()
        
        if 'vite.config' in path_str or 'vitest.config' in path_str:
            return 'config'
        elif '.env' in path_str:
            return 'env'
        elif '/src/' in path_str:
            return 'src'
        elif '/public/' in path_str:
            return 'public'
        elif '/dist/' in path_str or '/build/' in path_str:
            return 'build'
        
        return 'unknown'
    
    def _analyze_vite_config_file(self, file_path: Path, content: str, 
                                 context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze Vite configuration file for security issues."""
        
        vulnerabilities = []
        
        # Check for insecure development server configuration
        dev_server_patterns = self.vite_patterns['dev_server_issues']
        for pattern in dev_server_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                issue_type = "host binding" if "host" in match.group() else "CORS configuration"
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"vite_dev_server_{hash(str(match.group()))}",
                    title=f"Insecure Development Server {issue_type.title()}",
                    description=f"Development server has insecure {issue_type}",
                    severity="medium",
                    confidence="high",
                    framework="vite",
                    category="configuration",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    fix_suggestion=f"Review and secure development server {issue_type}"
                ))
        
        # Check for build exposure issues
        build_exposure_patterns = self.vite_patterns['build_exposure']
        for pattern in build_exposure_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"vite_build_exposure_{hash(str(match.group()))}",
                    title="Build Configuration Exposure",
                    description="Build configuration may expose sensitive information",
                    severity="medium",
                    confidence="medium",
                    framework="vite",
                    category="configuration",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    fix_suggestion="Review build configuration for sensitive data exposure"
                ))
        
        # Check for plugin security issues
        plugin_security_patterns = self.vite_patterns['plugin_security']
        for pattern in plugin_security_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"vite_plugin_security_{hash(str(match.group()))}",
                    title="Insecure Plugin Configuration",
                    description="Plugin configuration may have security implications",
                    severity="medium",
                    confidence="medium",
                    framework="vite",
                    category="configuration",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    fix_suggestion="Review plugin configuration for security issues"
                ))
        
        # Check for missing security plugins
        if not self._has_security_plugins(content, context):
            vulnerabilities.append(FrameworkVulnerability(
                id="vite_missing_security_plugins",
                title="Missing Security Plugins",
                description="Vite configuration lacks security-focused plugins",
                severity="low",
                confidence="medium",
                framework="vite",
                category="configuration",
                file_path=str(file_path),
                fix_suggestion="Consider adding security plugins like CSP or security headers"
            ))
        
        return vulnerabilities
    
    def _analyze_vite_env_file(self, file_path: Path, content: str, 
                              context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze Vite environment file for security issues."""
        
        vulnerabilities = []
        
        # Check for exposed secrets in VITE_ variables
        env_exposure_patterns = self.vite_patterns['env_exposure']
        for pattern in env_exposure_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"vite_env_exposure_{hash(str(match.group()))}",
                    title="Secret in Public Environment Variable",
                    description="VITE_ prefixed variables are exposed to the client",
                    severity="critical",
                    confidence="high",
                    framework="vite",
                    category="environment",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet="***REDACTED***",
                    affects_client_side=True,
                    fix_suggestion="Remove VITE_ prefix from secret variables or use server-side variables"
                ))
        
        # Check for production secrets in development env files
        if '.env.development' in str(file_path) or '.env.local' in str(file_path):
            prod_patterns = [
                r'PROD|PRODUCTION',
                r'API_KEY.*[a-zA-Z0-9]{20,}',
                r'SECRET.*[a-zA-Z0-9]{20,}'
            ]
            
            for pattern in prod_patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_number = content[:match.start()].count('\n') + 1
                    
                    vulnerabilities.append(FrameworkVulnerability(
                        id=f"vite_dev_prod_secret_{hash(str(match.group()))}",
                        title="Production Secret in Development Environment",
                        description="Production credentials found in development environment file",
                        severity="high",
                        confidence="medium",
                        framework="vite",
                        category="environment",
                        file_path=str(file_path),
                        line_number=line_number,
                        code_snippet="***REDACTED***",
                        fix_suggestion="Use separate environment files for different environments"
                    ))
        
        return vulnerabilities
    
    def _analyze_vite_src_file(self, file_path: Path, content: str, 
                              context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze Vite source file for security issues."""
        
        vulnerabilities = []
        
        # Check for HMR code in production
        hmr_patterns = self.vite_patterns['hmr_production']
        for pattern in hmr_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"vite_hmr_production_{hash(str(match.group()))}",
                    title="HMR Code in Production Build",
                    description="Hot Module Replacement code may be included in production",
                    severity="low",
                    confidence="medium",
                    framework="vite",
                    category="build",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    fix_suggestion="Ensure HMR code is properly tree-shaken in production"
                ))
        
        # Check for unsafe dynamic imports
        unsafe_import_patterns = self.vite_patterns['unsafe_dynamic_imports']
        for pattern in unsafe_import_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"vite_unsafe_import_{hash(str(match.group()))}",
                    title="Unsafe Dynamic Import",
                    description="Dynamic import with user-controlled or unsafe path",
                    severity="high",
                    confidence="high",
                    framework="vite",
                    category="import",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    requires_user_input=True,
                    attack_vector="path_traversal",
                    fix_suggestion="Validate and sanitize import paths"
                ))
        
        # Check for environment variable misuse
        env_misuse_patterns = [
            r'import\.meta\.env\.VITE_.*(?:SECRET|KEY|TOKEN|PASSWORD)',
            r'console\.log\s*\(\s*import\.meta\.env',
            r'alert\s*\(\s*import\.meta\.env'
        ]
        
        for pattern in env_misuse_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                issue_type = "secret exposure" if any(word in match.group().upper() 
                                                    for word in ['SECRET', 'KEY', 'TOKEN', 'PASSWORD']) else "debug logging"
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"vite_env_misuse_{hash(str(match.group()))}",
                    title=f"Environment Variable {issue_type.title()}",
                    description=f"Potential {issue_type} of environment variables",
                    severity="medium" if issue_type == "secret exposure" else "low",
                    confidence="high",
                    framework="vite",
                    category="environment",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    affects_client_side=True,
                    fix_suggestion="Avoid exposing sensitive environment variables or debug information"
                ))
        
        return vulnerabilities
    
    def _analyze_vite_patterns(self, file_path: Path, content: str, 
                              context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze general Vite security patterns."""
        
        vulnerabilities = []
        
        # Check all Vite specific patterns
        for category, patterns in self.vite_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    line_number = content[:match.start()].count('\n') + 1
                    
                    vulnerability = self._create_vite_pattern_vulnerability(
                        category, pattern, match, file_path, line_number, content
                    )
                    
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _create_vite_pattern_vulnerability(self, category: str, pattern: str, match, 
                                          file_path: Path, line_number: int, content: str) -> Optional[FrameworkVulnerability]:
        """Create vulnerability from Vite pattern match."""
        
        pattern_configs = {
            'env_exposure': {
                'title': 'Environment Variable Exposure',
                'description': 'VITE_ prefixed environment variables are exposed to client',
                'severity': 'high',
                'category': 'environment'
            },
            'hmr_production': {
                'title': 'HMR Code in Production',
                'description': 'Hot Module Replacement code in production build',
                'severity': 'low',
                'category': 'build'
            },
            'unsafe_dynamic_imports': {
                'title': 'Unsafe Dynamic Import',
                'description': 'Dynamic import with potentially unsafe path',
                'severity': 'high',
                'category': 'import'
            },
            'build_exposure': {
                'title': 'Build Configuration Exposure',
                'description': 'Build configuration may expose sensitive information',
                'severity': 'medium',
                'category': 'configuration'
            },
            'dev_server_issues': {
                'title': 'Development Server Security Issue',
                'description': 'Insecure development server configuration',
                'severity': 'medium',
                'category': 'configuration'
            },
            'plugin_security': {
                'title': 'Plugin Security Issue',
                'description': 'Plugin configuration security concern',
                'severity': 'medium',
                'category': 'configuration'
            }
        }
        
        config = pattern_configs.get(category)
        if not config:
            return None
        
        return FrameworkVulnerability(
            id=f"vite_{category}_{hash(str(match.group()))}",
            title=config['title'],
            description=config['description'],
            severity=config['severity'],
            confidence="medium",
            framework="vite",
            category=config['category'],
            file_path=str(file_path),
            line_number=line_number,
            code_snippet=self._extract_code_snippet(content, match),
            fix_suggestion=self._get_vite_fix_suggestion(category)
        )
    
    def _get_vite_fix_suggestion(self, category: str) -> str:
        """Get fix suggestion for Vite vulnerability category."""
        
        suggestions = {
            'env_exposure': 'Remove VITE_ prefix from secrets or use server-side environment variables',
            'hmr_production': 'Ensure HMR code is excluded from production builds',
            'unsafe_dynamic_imports': 'Validate and sanitize dynamic import paths',
            'build_exposure': 'Review build configuration for sensitive data exposure',
            'dev_server_issues': 'Secure development server configuration',
            'plugin_security': 'Review plugin configurations for security implications'
        }
        
        return suggestions.get(category, 'Review and address the Vite security issue')
    
    def _analyze_vite_config(self, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze Vite configuration for security issues."""
        
        vulnerabilities = []
        
        # Find Vite config files
        config_files = [
            context.project_root / 'vite.config.js',
            context.project_root / 'vite.config.ts',
            context.project_root / 'vite.config.mjs',
            context.project_root / 'vitest.config.js',
            context.project_root / 'vitest.config.ts'
        ]
        
        for config_file in config_files:
            if config_file.exists():
                try:
                    content = config_file.read_text(encoding='utf-8')
                    vulnerabilities.extend(self._analyze_vite_config_content(config_file, content, context))
                except Exception as e:
                    logger.error(f"Error reading Vite config {config_file}: {e}")
        
        return vulnerabilities
    
    def _analyze_vite_config_content(self, config_file: Path, content: str, 
                                    context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze Vite configuration file content."""
        
        vulnerabilities = []
        
        # Check for missing build optimizations
        if not re.search(r'build\s*:\s*\{[^}]*minify', content, re.IGNORECASE | re.DOTALL):
            vulnerabilities.append(FrameworkVulnerability(
                id="vite_no_minification",
                title="Build Minification Not Configured",
                description="Vite build configuration lacks explicit minification settings",
                severity="low",
                confidence="medium",
                framework="vite",
                category="configuration",
                file_path=str(config_file),
                fix_suggestion="Configure build minification for production"
            ))
        
        # Check for source maps in production
        if re.search(r'build\s*:\s*\{[^}]*sourcemap\s*:\s*true', content, re.IGNORECASE | re.DOTALL):
            vulnerabilities.append(FrameworkVulnerability(
                id="vite_sourcemap_production",
                title="Source Maps Enabled in Production",
                description="Source maps may expose source code in production builds",
                severity="low",
                confidence="high",
                framework="vite",
                category="configuration",
                file_path=str(config_file),
                fix_suggestion="Disable source maps for production builds"
            ))
        
        # Check for insecure proxy configuration
        proxy_patterns = [
            r'proxy\s*:\s*\{[^}]*target\s*:\s*[\'"`]https?://localhost',
            r'proxy\s*:\s*\{[^}]*secure\s*:\s*false'
        ]
        
        for pattern in proxy_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"vite_insecure_proxy_{hash(pattern)}",
                    title="Insecure Proxy Configuration",
                    description="Proxy configuration may have security implications",
                    severity="medium",
                    confidence="medium",
                    framework="vite",
                    category="configuration",
                    file_path=str(config_file),
                    fix_suggestion="Review proxy configuration for security settings"
                ))
        
        return vulnerabilities
    
    def _analyze_vite_env_files(self, project_path: Path, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze Vite environment files."""
        
        vulnerabilities = []
        
        # Find environment files
        env_patterns = ['.env', '.env.local', '.env.development', '.env.production', '.env.test']
        
        for env_pattern in env_patterns:
            env_file = project_path / env_pattern
            if env_file.exists():
                try:
                    content = env_file.read_text(encoding='utf-8')
                    vulnerabilities.extend(self._analyze_vite_env_file(env_file, content, context))
                except Exception as e:
                    logger.error(f"Error reading env file {env_file}: {e}")
        
        return vulnerabilities
    
    def _analyze_vite_src_directory(self, src_dir: Path, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze Vite src directory."""
        
        vulnerabilities = []
        
        for file_path in src_dir.rglob('*'):
            if file_path.is_file() and file_path.suffix in ['.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte']:
                try:
                    content = file_path.read_text(encoding='utf-8')
                    vulnerabilities.extend(self.analyze_file(file_path, content, context))
                except Exception as e:
                    logger.error(f"Error analyzing Vite src file {file_path}: {e}")
        
        return vulnerabilities
    
    def _analyze_vite_public_directory(self, public_dir: Path, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze Vite public directory for security issues."""
        
        vulnerabilities = []
        
        # Check for sensitive files in public directory
        sensitive_patterns = [
            r'\.env', r'config\.json', r'\.key', r'\.pem',
            r'secrets?\.', r'credentials?\.', r'private',
            r'\.log', r'\.bak', r'\.backup', r'\.git'
        ]
        
        for file_path in public_dir.rglob('*'):
            if file_path.is_file():
                filename = file_path.name.lower()
                
                for pattern in sensitive_patterns:
                    if re.search(pattern, filename):
                        vulnerabilities.append(FrameworkVulnerability(
                            id=f"vite_public_sensitive_{hash(str(file_path))}",
                            title="Sensitive File in Public Directory",
                            description=f"Potentially sensitive file in public directory: {file_path.name}",
                            severity="high",
                            confidence="medium",
                            framework="vite",
                            category="exposure",
                            file_path=str(file_path),
                            affects_client_side=True,
                            fix_suggestion="Remove sensitive files from public directory"
                        ))
                        break
        
        # Check for large files that might impact performance
        for file_path in public_dir.rglob('*'):
            if file_path.is_file():
                try:
                    file_size = file_path.stat().st_size
                    if file_size > 10 * 1024 * 1024:  # 10MB
                        vulnerabilities.append(FrameworkVulnerability(
                            id=f"vite_large_public_file_{hash(str(file_path))}",
                            title="Large File in Public Directory",
                            description=f"Large file ({file_size // 1024 // 1024}MB) in public directory may impact performance",
                            severity="low",
                            confidence="high",
                            framework="vite",
                            category="performance",
                            file_path=str(file_path),
                            fix_suggestion="Consider optimizing or moving large files"
                        ))
                except OSError:
                    pass
        
        return vulnerabilities
    
    def _analyze_vite_build_output(self, project_path: Path, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze Vite build output for security issues."""
        
        vulnerabilities = []
        
        # Check dist directory if present
        dist_dirs = [project_path / 'dist', project_path / 'build']
        
        for dist_dir in dist_dirs:
            if dist_dir.exists():
                # Check for source maps in production build
                for file_path in dist_dir.rglob('*.map'):
                    vulnerabilities.append(FrameworkVulnerability(
                        id=f"vite_build_sourcemap_{hash(str(file_path))}",
                        title="Source Map in Production Build",
                        description="Source map files present in production build",
                        severity="low",
                        confidence="high",
                        framework="vite",
                        category="build",
                        file_path=str(file_path),
                        fix_suggestion="Configure build to exclude source maps in production"
                    ))
                
                # Check for unminified files
                for file_path in dist_dir.rglob('*.js'):
                    if file_path.is_file():
                        try:
                            content = file_path.read_text(encoding='utf-8')
                            # Simple heuristic: if file has lots of whitespace and comments, it might not be minified
                            if len(content) > 1000 and (content.count('\n') > len(content) / 100):
                                vulnerabilities.append(FrameworkVulnerability(
                                    id=f"vite_unminified_build_{hash(str(file_path))}",
                                    title="Unminified File in Production Build",
                                    description="JavaScript file appears to be unminified in production build",
                                    severity="low",
                                    confidence="low",
                                    framework="vite",
                                    category="build",
                                    file_path=str(file_path),
                                    fix_suggestion="Ensure build minification is properly configured"
                                ))
                        except Exception:
                            pass
        
        return vulnerabilities
    
    def _analyze_package_json_vite(self, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze package.json for Vite specific issues."""
        
        vulnerabilities = []
        
        if not context.package_json:
            return vulnerabilities
        
        dependencies = {**context.dependencies, **context.dev_dependencies}
        
        # Check for outdated Vite version
        if 'vite' in dependencies:
            vite_version = dependencies['vite']
            
            # Check for known vulnerable versions (simplified)
            if any(old_version in vite_version for old_version in ['2.', '3.0', '3.1']):
                vulnerabilities.append(FrameworkVulnerability(
                    id="vite_outdated_version",
                    title="Outdated Vite Version",
                    description=f"Using potentially outdated Vite version: {vite_version}",
                    severity="medium",
                    confidence="high",
                    framework="vite",
                    category="dependencies",
                    file_path="package.json",
                    fix_suggestion="Update Vite to the latest stable version"
                ))
        
        # Check for missing security-related plugins
        security_plugins = ['vite-plugin-csp', 'vite-plugin-headers']
        missing_security = [plugin for plugin in security_plugins if plugin not in dependencies]
        
        if len(missing_security) == len(security_plugins):
            vulnerabilities.append(FrameworkVulnerability(
                id="vite_missing_security_plugins",
                title="Missing Security Plugins",
                description="Consider adding security-focused Vite plugins",
                severity="low",
                confidence="low",
                framework="vite",
                category="dependencies",
                file_path="package.json",
                fix_suggestion="Add security plugins like vite-plugin-csp or vite-plugin-headers"
            ))
        
        return vulnerabilities
    
    def _check_vite_security_practices(self, project_path: Path, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Check for Vite security best practices."""
        
        vulnerabilities = []
        
        # Check for TypeScript configuration
        has_typescript = (project_path / 'tsconfig.json').exists()
        
        if not has_typescript and context.package_json:
            dependencies = {**context.dependencies, **context.dev_dependencies}
            if 'typescript' not in dependencies:
                vulnerabilities.append(FrameworkVulnerability(
                    id="vite_no_typescript",
                    title="TypeScript Not Configured",
                    description="TypeScript provides additional type safety for Vite projects",
                    severity="info",
                    confidence="low",
                    framework="vite",
                    category="configuration",
                    file_path=str(project_path),
                    fix_suggestion="Consider using TypeScript for better development experience"
                ))
        
        # Check for testing configuration
        if context.package_json:
            dependencies = {**context.dependencies, **context.dev_dependencies}
            test_libs = ['vitest', '@testing-library/react', '@testing-library/vue', 'cypress']
            
            if not any(lib in dependencies for lib in test_libs):
                vulnerabilities.append(FrameworkVulnerability(
                    id="vite_no_testing",
                    title="No Testing Framework Configured",
                    description="No testing framework found in Vite project",
                    severity="info",
                    confidence="medium",
                    framework="vite",
                    category="configuration",
                    file_path="package.json",
                    fix_suggestion="Consider adding a testing framework like Vitest"
                ))
        
        return vulnerabilities
    
    # Helper methods
    def _has_security_plugins(self, content: str, context: FrameworkContext) -> bool:
        """Check if Vite config has security plugins."""
        security_plugin_patterns = [
            r'vite-plugin-csp',
            r'vite-plugin-headers',
            r'vite-plugin-helmet',
            r'@vitejs/plugin-csp'
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in security_plugin_patterns)
    
    def _extract_code_snippet(self, content: str, match, context_lines: int = 2) -> str:
        """Extract code snippet with context."""
        lines = content.split('\n')
        start_line = content[:match.start()].count('\n')
        
        snippet_start = max(0, start_line - context_lines)
        snippet_end = min(len(lines), start_line + context_lines + 1)
        
        return '\n'.join(lines[snippet_start:snippet_end])
