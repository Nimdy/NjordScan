"""
Configuration Files Security Module

Scans framework configuration files for security issues.
"""

import json
import re
import yaml
from pathlib import Path
from typing import List, Dict, Any

from .base import BaseModule
from ..vulnerability import Vulnerability

class ConfigsModule(BaseModule):
    """Module for scanning configuration files."""
    
    def __init__(self, config, vuln_id_generator):
        super().__init__(config, vuln_id_generator)
        self.config_patterns = {
            'nextjs': [
                'next.config.js', 'next.config.ts', 'next.config.mjs',
                '.env.local', '.env.development', '.env.production', '.env'
            ],
            'react': [
                'package.json', 'webpack.config.js', 'craco.config.js',
                '.env', '.env.local', '.env.development', '.env.production'
            ],
            'vite': [
                'vite.config.js', 'vite.config.ts', 'vite.config.mjs',
                '.env', '.env.local', '.env.development', '.env.production'
            ]
        }
        
        self.secret_patterns = [
            r'[\'"](?:password|secret|key|token|auth)[\'"]?\s*[:=]\s*[\'"][^\'"\s]{8,}[\'"]',
            r'[\'"](?:api_key|apikey|private_key|secret_key)[\'"]?\s*[:=]\s*[\'"][^\'"\s]{8,}[\'"]',
            r'sk_[a-zA-Z0-9]+',  # Stripe secret keys
            r'pk_[a-zA-Z0-9]+',  # Stripe public keys  
            r'AKIA[A-Z0-9]{16}',  # AWS Access Keys
            r'ghp_[a-zA-Z0-9]+',  # GitHub tokens
            r'sk-[a-zA-Z0-9]{48}',  # OpenAI keys
            r'sk-ant-[a-zA-Z0-9\-_]+',  # Anthropic keys
        ]
    
    def should_run(self, mode: str) -> bool:
        """Configs module runs in static and full modes."""
        return mode in ['static', 'full']
    
    async def scan(self, target: str) -> List[Vulnerability]:
        """Scan configuration files for security issues."""
        vulnerabilities = []
        
        if target.startswith(('http://', 'https://')):
            return await self.scan_url(target)
        
        target_path = Path(target)
        if not target_path.exists():
            return vulnerabilities
        
        # Get framework-specific config files
        patterns = self._get_config_patterns()
        
        # Find and scan config files
        for pattern in patterns:
            config_files = list(target_path.rglob(pattern))
            for config_file in config_files:
                file_vulns = await self._scan_config_file(config_file)
                vulnerabilities.extend(file_vulns)
        
        return vulnerabilities
    
    def _get_config_patterns(self) -> List[str]:
        """Get configuration file patterns based on framework."""
        patterns = []
        
        if self.config.framework == 'auto':
            # Scan all patterns if framework is auto-detected
            for framework_patterns in self.config_patterns.values():
                patterns.extend(framework_patterns)
        else:
            patterns = self.config_patterns.get(self.config.framework, [])
        
        # Remove duplicates and return
        return list(set(patterns))
    
    async def _scan_config_file(self, file_path: Path) -> List[Vulnerability]:
        """Scan a specific configuration file."""
        vulnerabilities = []
        
        try:
            content = self.get_file_content(str(file_path))
            if not content:
                return vulnerabilities
            
            file_name = file_path.name
            
            # Scan based on file type
            if file_name.startswith('.env'):
                vulnerabilities.extend(await self._scan_env_file(file_path, content))
            elif file_name == 'package.json':
                vulnerabilities.extend(await self._scan_package_json(file_path, content))
            elif 'next.config' in file_name:
                vulnerabilities.extend(await self._scan_nextjs_config(file_path, content))
            elif 'vite.config' in file_name:
                vulnerabilities.extend(await self._scan_vite_config(file_path, content))
            elif 'webpack.config' in file_name:
                vulnerabilities.extend(await self._scan_webpack_config(file_path, content))
            
            # Scan all files for hardcoded secrets
            secret_vulns = await self._scan_for_secrets(file_path, content)
            vulnerabilities.extend(secret_vulns)
            
        except Exception as e:
            if self.config.verbose:
                print(f"Error scanning {file_path}: {e}")
        
        return vulnerabilities
    
    async def _scan_env_file(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Scan environment files for security issues."""
        vulnerabilities = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"\'')
                
                # Check for public environment variables with sensitive data
                if key.startswith('NEXT_PUBLIC_') and self._is_sensitive_value(value):
                    vulnerabilities.append(self.create_vulnerability(
                        title="Sensitive Data in Public Environment Variable",
                        description=f"Public environment variable '{key}' contains what appears to be sensitive data",
                        severity="high",
                        vuln_type="secrets_exposure",
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=f"{key}={value[:20]}{'...' if len(value) > 20 else ''}",
                        fix="Move sensitive data to server-side environment variables (without NEXT_PUBLIC_ prefix)",
                        metadata={
                            'variable_name': key,
                            'is_public': True
                        }
                    ))
                
                # Check for empty or default values
                if self._is_secret_key(key) and value in ['', 'your_key_here', 'change_me', 'secret']:
                    vulnerabilities.append(self.create_vulnerability(
                        title="Default or Empty Secret Value",
                        description=f"Secret variable '{key}' has a default or empty value",
                        severity="medium",
                        vuln_type="secrets_exposure",
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=f"{key}={value}",
                        fix="Set a strong, unique value for this secret",
                        metadata={
                            'variable_name': key,
                            'value': value
                        }
                    ))
        
        return vulnerabilities
    
    async def _scan_package_json(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Scan package.json for security issues."""
        vulnerabilities = []
        
        try:
            package_data = json.loads(content)
            
            # Check for development dependencies in production
            if 'dependencies' in package_data:
                dev_packages = [
                    'nodemon', 'webpack-dev-server', 'vite', 'dev-server',
                    'hot-reload', 'live-reload', 'browser-sync', '@types/',
                    'eslint', 'prettier', 'jest', 'cypress'
                ]
                
                for dep in package_data['dependencies']:
                    if any(dev_pkg in dep.lower() for dev_pkg in dev_packages):
                        vulnerabilities.append(self.create_vulnerability(
                            title="Development Dependency in Production",
                            description=f"Development package '{dep}' found in production dependencies",
                            severity="medium",
                            vuln_type="insecure_configuration",
                            file_path=str(file_path),
                            fix="Move development packages to devDependencies",
                            metadata={
                                'package_name': dep,
                                'version': package_data['dependencies'][dep]
                            }
                        ))
            
            # Check for insecure scripts
            if 'scripts' in package_data:
                for script_name, script_command in package_data['scripts'].items():
                    if '--disable-web-security' in script_command:
                        vulnerabilities.append(self.create_vulnerability(
                            title="Insecure Script Configuration",
                            description=f"Script '{script_name}' disables web security",
                            severity="high",
                            vuln_type="insecure_configuration",
                            file_path=str(file_path),
                            code_snippet=f'"{script_name}": "{script_command}"',
                            fix="Remove --disable-web-security flag from scripts",
                            metadata={
                                'script_name': script_name,
                                'script_command': script_command
                            }
                        ))
            
            # Check for outdated package structure
            if 'version' in package_data and package_data['version'].startswith('0.'):
                vulnerabilities.append(self.create_vulnerability(
                    title="Pre-release Version in Production",
                    description="Package version indicates pre-release (0.x.x) which may be unstable",
                    severity="low",
                    vuln_type="insecure_configuration",
                    file_path=str(file_path),
                    fix="Use stable version numbers (1.x.x or higher) for production",
                    metadata={
                        'version': package_data['version']
                    }
                ))
            
        except json.JSONDecodeError:
            vulnerabilities.append(self.create_vulnerability(
                title="Invalid JSON in package.json",
                description="package.json contains invalid JSON syntax",
                severity="medium",
                vuln_type="insecure_configuration",
                file_path=str(file_path),
                fix="Fix JSON syntax errors in package.json"
            ))
        
        return vulnerabilities
    
    async def _scan_nextjs_config(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Scan Next.js configuration files."""
        vulnerabilities = []
        
        # Check for insecure image domains
        if re.search(r'images\s*:\s*{[^}]*domains\s*:\s*\[[^\]]*[\'"][*][\'"][^\]]*\]', content):
            vulnerabilities.append(self.create_vulnerability(
                title="Wildcard Image Domain Configuration",
                description="Next.js image configuration allows all domains (*) which may enable SSRF attacks",
                severity="high",
                vuln_type="ssrf",
                file_path=str(file_path),
                fix="Specify explicit allowed domains instead of using wildcards",
                metadata={
                    'config_type': 'images.domains'
                }
            ))
        
        # Check for disabled security features
        if 'poweredByHeader: false' not in content:
            vulnerabilities.append(self.create_vulnerability(
                title="X-Powered-By Header Not Disabled",
                description="Next.js X-Powered-By header disclosure is not disabled",
                severity="low",
                vuln_type="missing_security_headers",
                file_path=str(file_path),
                fix="Add 'poweredByHeader: false' to next.config.js",
                metadata={
                    'header_name': 'X-Powered-By'
                }
            ))
        
        # Check for development mode in production
        if re.search(r'env\s*:\s*[\'"]development[\'"]', content):
            vulnerabilities.append(self.create_vulnerability(
                title="Development Mode Configuration",
                description="Next.js configuration appears to be set for development mode",
                severity="medium",
                vuln_type="debug_mode_enabled",
                file_path=str(file_path),
                fix="Ensure production configurations are used for production deployments"
            ))
        
        # Check for insecure redirects
        redirect_pattern = r'redirects.*destination\s*:\s*[\'"][^\'"]*/.*\$'
        if re.search(redirect_pattern, content, re.DOTALL):
            vulnerabilities.append(self.create_vulnerability(
                title="Potential Open Redirect Configuration",
                description="Next.js redirect configuration may allow open redirects",
                severity="medium",
                vuln_type="idor",
                file_path=str(file_path),
                fix="Validate redirect destinations and avoid user-controlled redirects"
            ))
        
        return vulnerabilities
    
    async def _scan_vite_config(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Scan Vite configuration files."""
        vulnerabilities = []
        
        # Check for insecure server configuration
        if re.search(r'host\s*:\s*[\'"]0\.0\.0\.0[\'"]', content) or re.search(r'host\s*:\s*true', content):
            vulnerabilities.append(self.create_vulnerability(
                title="Insecure Server Host Configuration",
                description="Vite server is configured to bind to all interfaces (0.0.0.0)",
                severity="medium",
                vuln_type="insecure_configuration",
                file_path=str(file_path),
                fix="Use specific host binding for production deployments"
            ))
        
        # Check for exposed file system access
        if re.search(r'fs\.allow.*\.\./.*', content):
            vulnerabilities.append(self.create_vulnerability(
                title="Permissive File System Access",
                description="Vite configuration allows access to parent directories",
                severity="high",
                vuln_type="insecure_configuration",
                file_path=str(file_path),
                fix="Restrict fs.allow to specific necessary directories"
            ))
        
        # Check for development proxy in production
        if 'proxy' in content and 'target' in content:
            vulnerabilities.append(self.create_vulnerability(
                title="Development Proxy Configuration",
                description="Vite proxy configuration found, ensure it's not used in production",
                severity="low",
                vuln_type="debug_mode_enabled",
                file_path=str(file_path),
                fix="Disable proxy configuration in production builds"
            ))
        
        return vulnerabilities
    
    async def _scan_webpack_config(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Scan Webpack configuration files."""
        vulnerabilities = []
        
        # Check for development mode
        if re.search(r"mode\s*:\s*['\"]development['\"]", content):
            vulnerabilities.append(self.create_vulnerability(
                title="Development Mode in Configuration",
                description="Webpack is configured for development mode",
                severity="medium",
                vuln_type="debug_mode_enabled",
                file_path=str(file_path),
                fix="Use production mode for production builds"
            ))
        
        # Check for source maps
        if re.search(r'devtool\s*:.*source-map', content):
            vulnerabilities.append(self.create_vulnerability(
                title="Source Maps Enabled",
                description="Source maps are enabled which may expose source code",
                severity="low",
                vuln_type="debug_mode_enabled",
                file_path=str(file_path),
                fix="Disable source maps in production builds"
            ))
        
        return vulnerabilities
    
    async def _scan_for_secrets(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Scan for hardcoded secrets in any configuration file."""
        vulnerabilities = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for pattern in self.secret_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    # Skip if it's a comment or example
                    if any(indicator in line.lower() for indicator in ['example', 'sample', 'todo', 'fixme', '#', '//']):
                        continue
                    
                    vulnerabilities.append(self.create_vulnerability(
                        title="Potential Hardcoded Secret",
                        description="Potential secret or API key found in configuration file",
                        severity="critical",
                        vuln_type="secrets_exposure",
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=self._mask_secret(line.strip()),
                        fix="Remove hardcoded secrets and use environment variables or secure secret management",
                        metadata={
                            'pattern_matched': pattern,
                            'matched_text': self._mask_secret(match.group())
                        }
                    ))
        
        return vulnerabilities
    
    def _is_sensitive_value(self, value: str) -> bool:
        """Check if a value appears to be sensitive data."""
        if len(value) < 8:
            return False
        
        sensitive_patterns = [
            r'[A-Za-z0-9]{32,}',  # Long alphanumeric strings
            r'sk_[a-zA-Z0-9]+',   # Stripe keys
            r'pk_[a-zA-Z0-9]+',   # Stripe public keys
            r'AKIA[A-Z0-9]{16}',  # AWS Access Keys
            r'ghp_[a-zA-Z0-9]+',  # GitHub tokens
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, value):
                return True
        return False
    
    def _is_secret_key(self, key: str) -> bool:
        """Check if a key name indicates it's a secret."""
        secret_indicators = [
            'secret', 'key', 'token', 'password', 'pass', 'auth',
            'api_key', 'apikey', 'private', 'credential', 'jwt'
        ]
        
        key_lower = key.lower()
        return any(indicator in key_lower for indicator in secret_indicators)
    
    def _mask_secret(self, text: str) -> str:
        """Mask sensitive data in code snippets."""
        # Mask common secret patterns
        text = re.sub(r'sk-[a-zA-Z0-9]{48}', 'sk-***MASKED***', text)
        text = re.sub(r'sk-ant-[a-zA-Z0-9\-_]+', 'sk-ant-***MASKED***', text)
        text = re.sub(r'AKIA[A-Z0-9]{16}', 'AKIA***MASKED***', text)
        text = re.sub(r'ghp_[a-zA-Z0-9]+', 'ghp_***MASKED***', text)
        text = re.sub(r'[\'"][a-zA-Z0-9]{32,}[\'"]', '"***MASKED***"', text)
        
        return text
    
    async def scan_url(self, url: str) -> List[Vulnerability]:
        """Scan a URL for configuration-related security issues."""
        vulnerabilities = []
        
        try:
            import aiohttp
            
            # Create session with timeout
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Test for exposed configuration files
                config_endpoints = [
                    '/.env',
                    '/.env.local',
                    '/.env.development',
                    '/.env.production',
                    '/package.json',
                    '/next.config.js',
                    '/vite.config.js',
                    '/webpack.config.js',
                    '/tsconfig.json',
                    '/jsconfig.json',
                    '/tailwind.config.js',
                    '/postcss.config.js',
                    '/.git/config',
                    '/composer.json',
                    '/requirements.txt',
                    '/Pipfile',
                    '/pyproject.toml'
                ]
                
                for endpoint in config_endpoints:
                    test_url = url.rstrip('/') + endpoint
                    try:
                        async with session.get(test_url) as response:
                            if response.status == 200:
                                content = await response.text()
                                
                                # Check if it's actually a config file (not an error page)
                                if self._is_config_content(content, endpoint):
                                    vulnerabilities.append(self.create_vulnerability(
                                        title=f"Exposed Configuration File: {endpoint}",
                                        description=f"Configuration file {endpoint} is accessible via HTTP",
                                        severity="high",
                                        vuln_type="information_disclosure",
                                        fix=f"Remove or secure access to {endpoint}",
                                        metadata={
                                            'url': test_url,
                                            'endpoint': endpoint,
                                            'status_code': response.status,
                                            'content_length': len(content)
                                        }
                                    ))
                    except Exception as e:
                        if self.config.verbose:
                            print(f"Error testing {test_url}: {e}")
                        continue
                
                # Test for directory listing
                dir_listing_vulns = await self._test_directory_listing(session, url)
                vulnerabilities.extend(dir_listing_vulns)
                
        except Exception as e:
            if self.config.verbose:
                print(f"Error scanning URL {url}: {e}")
        
        return vulnerabilities
    
    def _is_config_content(self, content: str, endpoint: str) -> bool:
        """Check if content appears to be a configuration file."""
        # Skip if content is too short or looks like an error page
        if len(content) < 10:
            return False
        
        # Check for common error page indicators
        error_indicators = ['404', 'not found', 'error', 'page not found', '<html>', '<!doctype']
        if any(indicator in content.lower() for indicator in error_indicators):
            return False
        
        # Check for specific file type indicators
        if endpoint.endswith('.json'):
            try:
                import json
                json.loads(content)
                return True
            except:
                return False
        elif endpoint.endswith(('.js', '.ts')):
            return 'module.exports' in content or 'export' in content or 'import' in content
        elif endpoint.startswith('.env'):
            return '=' in content and '\n' in content
        elif endpoint.endswith('.txt'):
            return '==' in content or '>=' in content  # requirements.txt patterns
        elif endpoint.endswith('.toml'):
            return '[' in content and ']' in content
        elif endpoint.endswith('.yaml') or endpoint.endswith('.yml'):
            return ':' in content and ('version' in content or 'dependencies' in content)
        
        return False
    
    async def _test_directory_listing(self, session, url: str) -> List[Vulnerability]:
        """Test for directory listing vulnerabilities."""
        vulnerabilities = []
        
        # Common directories that might have listing enabled
        test_dirs = [
            '/',
            '/public/',
            '/static/',
            '/assets/',
            '/files/',
            '/uploads/',
            '/config/',
            '/admin/',
            '/.git/',
            '/node_modules/',
            '/vendor/'
        ]
        
        for test_dir in test_dirs:
            test_url = url.rstrip('/') + test_dir
            try:
                async with session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for directory listing indicators
                        if self._is_directory_listing(content):
                            vulnerabilities.append(self.create_vulnerability(
                                title=f"Directory Listing Enabled: {test_dir}",
                                description=f"Directory listing is enabled for {test_dir}",
                                severity="medium",
                                vuln_type="information_disclosure",
                                fix=f"Disable directory listing for {test_dir}",
                                metadata={
                                    'url': test_url,
                                    'directory': test_dir,
                                    'status_code': response.status
                                }
                            ))
            except Exception:
                continue
        
        return vulnerabilities
    
    def _is_directory_listing(self, content: str) -> bool:
        """Check if content appears to be a directory listing."""
        # Common directory listing indicators
        listing_indicators = [
            'Index of',
            'Directory listing',
            'Parent Directory',
            '<a href="../">',
            'Last modified',
            'Size</th>',
            'Name</th>',
            'Apache/',
            'nginx/',
            'Microsoft-IIS/'
        ]
        
        return any(indicator in content for indicator in listing_indicators)