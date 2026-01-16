"""
Static Code Analysis Module

Scans source code for security vulnerabilities using pattern matching and AST analysis.
"""

import re
import ast
import os
from pathlib import Path
from typing import List, Dict, Any, Optional

from .base import BaseModule
from ..vulnerability import Vulnerability

class CodeStaticModule(BaseModule):
    """Module for static code analysis."""
    
    def __init__(self, config, vuln_id_generator):
        super().__init__(config, vuln_id_generator)
        self.file_extensions = {
            'javascript': ['.js', '.jsx', '.ts', '.tsx', '.mjs'],
            'python': ['.py'],
            'html': ['.html', '.htm'],
            'css': ['.css', '.scss', '.sass'],
            'json': ['.json'],
            'yaml': ['.yaml', '.yml']
        }
        
        self.vulnerability_patterns = {
            'xss_reflected': [
                {
                    'pattern': r'dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:.*\}',
                    'severity': 'high',
                    'description': 'Use of dangerouslySetInnerHTML without sanitization - can lead to XSS'
                },
                {
                    'pattern': r'innerHTML\s*=\s*[\'"].*\$\{.*\}.*[\'"]',
                    'severity': 'high',
                    'description': 'Dynamic innerHTML assignment with template literals - XSS risk'
                },
                {
                    'pattern': r'document\.write\s*\(',
                    'severity': 'medium',
                    'description': 'Use of document.write() which can lead to XSS'
                },
                {
                    'pattern': r'eval\s*\(',
                    'severity': 'high',
                    'description': 'Use of eval() function - can execute arbitrary code'
                },
                {
                    'pattern': r'Function\s*\(',
                    'severity': 'high',
                    'description': 'Dynamic function creation - can lead to code injection'
                }
            ],
            'xss_stored': [
                {
                    'pattern': r'db\.\w+\.create\s*\(\s*\{[^}]*content\s*:\s*[^}]*\}',
                    'severity': 'high',
                    'description': 'Database storage without input sanitization'
                },
                {
                    'pattern': r'\.save\s*\(\s*[^)]*content[^)]*\)',
                    'severity': 'high',
                    'description': 'Data persistence without validation'
                }
            ],
            'xss_dom': [
                {
                    'pattern': r'document\.getElementById\s*\([^)]+\)\.innerHTML\s*=',
                    'severity': 'medium',
                    'description': 'Direct DOM manipulation with innerHTML'
                },
                {
                    'pattern': r'document\.location\s*=',
                    'severity': 'medium',
                    'description': 'Direct assignment to document.location'
                }
            ],
            'sql_injection': [
                {
                    'pattern': r'query\s*\(\s*[\'"].*\$\{.*\}.*[\'"]',
                    'severity': 'critical',
                    'description': 'SQL query with string interpolation'
                },
                {
                    'pattern': r'execute\s*\(\s*[\'"].*\+.*[\'"]',
                    'severity': 'critical',
                    'description': 'SQL execution with string concatenation'
                }
            ],
            'command_injection': [
                {
                    'pattern': r'exec\s*\([\'"]?\$\{.*\}[\'"]?\)',
                    'severity': 'critical',
                    'description': 'Command execution with user input'
                },
                {
                    'pattern': r'spawn\s*\([\'"]?\$\{.*\}[\'"]?\)',
                    'severity': 'critical',
                    'description': 'Process spawning with user input'
                },
                {
                    'pattern': r'system\s*\([\'"]?\$\{.*\}[\'"]?\)',
                    'severity': 'critical',
                    'description': 'System command execution with user input'
                }
            ],
            'path_traversal': [
                {
                    'pattern': r'fs\.readFile\s*\([\'"]?\$\{.*\}[\'"]?\)',
                    'severity': 'high',
                    'description': 'File reading with dynamic paths'
                },
                {
                    'pattern': r'fs\.readFileSync\s*\([\'"]?\$\{.*\}[\'"]?\)',
                    'severity': 'high',
                    'description': 'Synchronous file reading with dynamic paths'
                },
                {
                    'pattern': r'fs\.writeFile\s*\([\'"]?\$\{.*\}[\'"]?\)',
                    'severity': 'high',
                    'description': 'File writing with dynamic paths'
                },
                {
                    'pattern': r'path\.join\s*\([^)]*\.\.[^)]*\)',
                    'severity': 'medium',
                    'description': 'Path construction with parent directory traversal'
                },
                {
                    'pattern': r'require\s*\([\'"]?\$\{.*\}[\'"]?\)',
                    'severity': 'high',
                    'description': 'Dynamic require with user input'
                }
            ],
            'ssrf': [
                {
                    'pattern': r'fetch\s*\(\s*[\'"]?\$\{.*\}[\'"]?\s*\)',
                    'severity': 'high',
                    'description': 'HTTP request with user-controlled URL - potential SSRF'
                },
                {
                    'pattern': r'axios\s*\(\s*[\'"]?\$\{.*\}[\'"]?\s*\)',
                    'severity': 'high',
                    'description': 'HTTP request with dynamic URL'
                },
                {
                    'pattern': r'http\.request\s*\(\s*[\'"]?\$\{.*\}[\'"]?\s*\)',
                    'severity': 'high',
                    'description': 'HTTP request with user input'
                }
            ],
            'secrets_exposure': [
                {
                    'pattern': r'api[_-]?key\s*[:=]\s*[\'"]\w+[\'"]',
                    'severity': 'critical',
                    'description': 'Hardcoded API key found'
                },
                {
                    'pattern': r'password\s*[:=]\s*[\'"]\w+[\'"]',
                    'severity': 'critical',
                    'description': 'Hardcoded password found'
                },
                {
                    'pattern': r'secret\s*[:=]\s*[\'"]\w+[\'"]',
                    'severity': 'critical',
                    'description': 'Hardcoded secret found'
                },
                {
                    'pattern': r'token\s*[:=]\s*[\'"]\w+[\'"]',
                    'severity': 'high',
                    'description': 'Hardcoded token found'
                }
            ],
            'weak_random': [
                {
                    'pattern': r'Math\.random\(\)',
                    'severity': 'low',
                    'description': 'Use of cryptographically insecure Math.random() - avoid for security-sensitive operations like tokens or IDs'
                }
            ]
        }
    
    def should_run(self, mode: str) -> bool:
        """Static code module runs in static and full modes."""
        return mode in ['static', 'full']
    
    async def scan(self, target: str) -> List[Vulnerability]:
        """Scan source code for security vulnerabilities."""
        vulnerabilities = []
        
        if target.startswith(('http://', 'https://')):
            return await self.scan_url(target)
        
        target_path = Path(target)
        if not target_path.exists():
            return vulnerabilities
        
        # Get all source files
        source_files = []
        for lang, extensions in self.file_extensions.items():
            for ext in extensions:
                files = list(target_path.rglob(f'*{ext}'))
                source_files.extend([(f, lang) for f in files])
        
        # Scan each file
        for file_path, language in source_files:
            if self._should_skip_file(file_path):
                continue
            
            file_vulns = await self._scan_source_file(file_path, language)
            vulnerabilities.extend(file_vulns)
        
        return vulnerabilities
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped."""
        skip_dirs = {
            'node_modules', '.git', '.next', 'dist', 'build', 
            '__pycache__', '.pytest_cache', 'coverage', '.nyc_output',
            'vendor', 'public', 'static'
        }
        
        # Check if file is in a skip directory
        for part in file_path.parts:
            if part in skip_dirs:
                return True
        
        # Skip minified files
        if '.min.' in file_path.name:
            return True
        
        # Skip source maps
        if file_path.name.endswith('.map'):
            return True
        
        # Skip test files (unless specifically requested)
        if not getattr(self.config, 'include_tests', False):
            test_indicators = ['test', 'spec', '__tests__', '.test.', '.spec.']
            if any(indicator in file_path.name.lower() for indicator in test_indicators):
                return True
        
        # Skip very large files
        try:
            if file_path.stat().st_size > 1024 * 1024:  # 1MB
                return True
        except OSError:
            return True
        
        return False
    
    async def _scan_source_file(self, file_path: Path, language: str) -> List[Vulnerability]:
        """Scan a specific source file."""
        vulnerabilities = []
        
        try:
            content = self.get_file_content(str(file_path))
            if not content:
                return vulnerabilities
            
            # Pattern-based scanning
            pattern_vulns = await self._scan_patterns(file_path, content)
            vulnerabilities.extend(pattern_vulns)
            
            # Framework-specific scanning
            framework_vulns = await self._scan_framework_specific(file_path, content)
            vulnerabilities.extend(framework_vulns)
            
            # Language-specific scanning
            if language == 'python':
                ast_vulns = await self._scan_python_ast(file_path, content)
                vulnerabilities.extend(ast_vulns)
            elif language == 'javascript':
                js_vulns = await self._scan_javascript_specific(file_path, content)
                vulnerabilities.extend(js_vulns)
            
        except Exception as e:
            if self.config.verbose:
                print(f"Error scanning {file_path}: {e}")
        
        return vulnerabilities
    
    async def _scan_patterns(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Scan file content using regex patterns."""
        vulnerabilities = []
        lines = content.split('\n')
        
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern_info in patterns:
                pattern = pattern_info['pattern']
                severity = pattern_info['severity']
                description = pattern_info['description']
                
                for line_num, line in enumerate(lines, 1):
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        # Skip false positives
                        if self._is_false_positive(line, match.group(), vuln_type):
                            continue
                        
                        vulnerabilities.append(self.create_vulnerability(
                            title=f"Potential {vuln_type.replace('_', ' ').title()} Vulnerability",
                            description=description,
                            severity=severity,
                            vuln_type=vuln_type,
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=line.strip(),
                            fix=self._get_fix_for_pattern(vuln_type),
                            metadata={
                                'pattern': pattern,
                                'matched_text': match.group(),
                                'line_content': line.strip()
                            }
                        ))
        
        return vulnerabilities
    
    async def _scan_framework_specific(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Scan for framework-specific vulnerabilities."""
        vulnerabilities = []
        
        if self.config.framework == 'nextjs':
            vulnerabilities.extend(await self._scan_nextjs_patterns(file_path, content))
        elif self.config.framework == 'react':
            vulnerabilities.extend(await self._scan_react_patterns(file_path, content))
        elif self.config.framework == 'vite':
            vulnerabilities.extend(await self._scan_vite_patterns(file_path, content))
        
        return vulnerabilities
    
    async def _scan_nextjs_patterns(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Scan for Next.js specific vulnerabilities."""
        vulnerabilities = []
        lines = content.split('\n')
        
        nextjs_patterns = [
            {
                'pattern': r'process\.env\.NEXT_PUBLIC_[A-Z_]+',
                'title': 'Public Environment Variable Usage',
                'description': 'Usage of NEXT_PUBLIC_ environment variables exposes data to the client',
                'severity': 'info',
                'vuln_type': 'public_env_var'
            },
            {
                'pattern': r'getServerSideProps.*req\..*(?:headers|cookies|query)',
                'title': 'Potential SSRF in getServerSideProps',
                'description': 'User input in getServerSideProps may lead to SSRF vulnerabilities',
                'severity': 'medium',
                'vuln_type': 'ssrf'
            },
            {
                'pattern': r'router\.push\([\'"]?\$\{.*\}[\'"]?\)',
                'title': 'Dynamic Route Navigation',
                'description': 'Dynamic route navigation may be vulnerable to open redirects',
                'severity': 'low',
                'vuln_type': 'open_redirect'
            },
            {
                'pattern': r'Image.*src=\{.*\}',
                'title': 'Dynamic Image Source',
                'description': 'Dynamic image sources should be validated to prevent SSRF',
                'severity': 'medium',
                'vuln_type': 'dynamic_image'
            }
        ]
        
        for pattern_info in nextjs_patterns:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern_info['pattern'], line):
                    vulnerabilities.append(self.create_vulnerability(
                        title=pattern_info['title'],
                        description=pattern_info['description'],
                        severity=pattern_info['severity'],
                        vuln_type=pattern_info['vuln_type'],
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=line.strip(),
                        fix=self._get_nextjs_fix(pattern_info['vuln_type'])
                    ))
        
        return vulnerabilities
    
    async def _scan_react_patterns(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Scan for React specific vulnerabilities."""
        vulnerabilities = []
        lines = content.split('\n')
        
        react_patterns = [
            {
                'pattern': r'React\.createElement\([\'"]script[\'"]',
                'title': 'Dynamic Script Creation',
                'description': 'Dynamic script element creation may lead to XSS',
                'severity': 'high',
                'vuln_type': 'dynamic_script'
            },
            {
                'pattern': r'useEffect\(\s*\(\)\s*=>\s*\{.*fetch\([\'"]?\$\{.*\}[\'"]?\)',
                'title': 'Unsafe API Call in useEffect',
                'description': 'useEffect making API calls with user input may be vulnerable',
                'severity': 'medium',
                'vuln_type': 'unsafe_api_call'
            },
            {
                'pattern': r'onClick=\{.*eval\(',
                'title': 'eval() in Event Handler',
                'description': 'Use of eval() in event handlers is dangerous',
                'severity': 'high',
                'vuln_type': 'eval_handler'
            }
        ]
        
        for pattern_info in react_patterns:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern_info['pattern'], line):
                    vulnerabilities.append(self.create_vulnerability(
                        title=pattern_info['title'],
                        description=pattern_info['description'],
                        severity=pattern_info['severity'],
                        vuln_type=pattern_info['vuln_type'],
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=line.strip(),
                        fix=self._get_react_fix(pattern_info['vuln_type'])
                    ))
        
        return vulnerabilities
    
    async def _scan_vite_patterns(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Scan for Vite specific vulnerabilities."""
        vulnerabilities = []
        lines = content.split('\n')
        
        vite_patterns = [
            {
                'pattern': r'import\.meta\.env\.[A-Z_]+',
                'title': 'Environment Variable Usage',
                'description': 'Usage of import.meta.env variables',
                'severity': 'info',
                'vuln_type': 'env_var_usage'
            },
            {
                'pattern': r'import\.meta\.hot',
                'title': 'Hot Module Replacement in Production',
                'description': 'HMR code may be present in production build',
                'severity': 'low',
                'vuln_type': 'hmr_production'
            }
        ]
        
        for pattern_info in vite_patterns:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern_info['pattern'], line):
                    vulnerabilities.append(self.create_vulnerability(
                        title=pattern_info['title'],
                        description=pattern_info['description'],
                        severity=pattern_info['severity'],
                        vuln_type=pattern_info['vuln_type'],
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=line.strip(),
                        fix=self._get_vite_fix(pattern_info['vuln_type'])
                    ))
        
        return vulnerabilities
    
    async def _scan_python_ast(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Scan Python files using AST analysis."""
        vulnerabilities = []
        
        try:
            tree = ast.parse(content)
            
            class SecurityVisitor(ast.NodeVisitor):
                def __init__(self, module_instance):
                    self.vulnerabilities = []
                    self.module = module_instance
                
                def visit_Call(self, node):
                    # Check for dangerous function calls
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ['eval', 'exec', 'compile']:
                            self.vulnerabilities.append({
                                'title': f'Dangerous Function Call: {node.func.id}',
                                'description': f'Use of {node.func.id} function can lead to code injection',
                                'severity': 'critical',
                                'vuln_type': 'code_injection',
                                'line_number': node.lineno
                            })
                        elif node.func.id == 'input' and len(node.args) == 0:
                            self.vulnerabilities.append({
                                'title': 'Unsafe Input Function',
                                'description': 'Use of input() without prompt may be confusing',
                                'severity': 'low',
                                'vuln_type': 'unsafe_input',
                                'line_number': node.lineno
                            })
                    
                    self.generic_visit(node)
                
                def visit_Import(self, node):
                    # Check for dangerous imports
                    for alias in node.names:
                        if alias.name in ['pickle', 'subprocess', 'os']:
                            self.vulnerabilities.append({
                                'title': f'Potentially Dangerous Import: {alias.name}',
                                'description': f'Import of {alias.name} module requires careful handling',
                                'severity': 'low',
                                'vuln_type': 'dangerous_import',
                                'line_number': node.lineno
                            })
                    
                    self.generic_visit(node)
            
            visitor = SecurityVisitor(self)
            visitor.visit(tree)
            
            for vuln in visitor.vulnerabilities:
                vulnerabilities.append(self.create_vulnerability(
                    title=vuln['title'],
                    description=vuln['description'],
                    severity=vuln['severity'],
                    vuln_type=vuln['vuln_type'],
                    file_path=str(file_path),
                    line_number=vuln['line_number'],
                    fix=self._get_python_fix(vuln['vuln_type'])
                ))
        
        except SyntaxError:
            # File has syntax errors, skip AST analysis
            pass
        
        return vulnerabilities
    
    async def _scan_javascript_specific(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Scan JavaScript files for specific patterns."""
        vulnerabilities = []
        lines = content.split('\n')

        # Check for console.log in production files
        # Skip directories that are expected to have console statements
        excluded_dirs = {'e2e', 'test', 'tests', '__tests__', 'spec', 'scripts', 'cypress', 'playwright'}
        # Skip files that are expected to have console statements
        excluded_files = {'logger', 'logging', 'console', 'debug'}

        file_path_str = str(file_path).lower()
        file_name_stem = file_path.stem.lower()

        # Check if file is in an excluded directory
        is_excluded_dir = any(f'/{excluded}/' in file_path_str or file_path_str.startswith(f'{excluded}/')
                             for excluded in excluded_dirs)
        # Check if file is an excluded file type (logger, etc.)
        is_excluded_file = any(excluded in file_name_stem for excluded in excluded_files)

        if not is_excluded_dir and not is_excluded_file:
            for line_num, line in enumerate(lines, 1):
                if re.search(r'console\.(log|debug|info)', line) and not line.strip().startswith('//'):
                    vulnerabilities.append(self.create_vulnerability(
                        title="Console Statement in Production Code",
                        description="Console statements may leak sensitive information in production builds",
                        severity="low",
                        vuln_type="console_leak",
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=line.strip(),
                        fix="Remove console statements or use a proper logging library that can be disabled in production"
                    ))

        return vulnerabilities
    
    def _is_false_positive(self, line: str, match: str, vuln_type: str) -> bool:
        """Check if a match is likely a false positive."""
        line_lower = line.lower()
        
        # Skip comments
        if any(comment in line_lower for comment in ['//', '/*', '*/', '#', '<!--']):
            return True
        
        # Skip examples and documentation
        if any(keyword in line_lower for keyword in ['example', 'sample', 'todo', 'fixme', 'test']):
            return True
        
        # Skip string literals that are clearly not code
        if vuln_type == 'xss' and 'dangerously' in match.lower():
            # Allow if it's clearly sanitized
            if any(sanitize in line_lower for sanitize in ['sanitize', 'escape', 'clean']):
                return True
        
        return False
    
    def _get_fix_for_pattern(self, vuln_type: str) -> str:
        """Get fix recommendation for vulnerability pattern."""
        fixes = {
            'xss': 'Sanitize user inputs and avoid innerHTML manipulation',
            'sql_injection': 'Use parameterized queries instead of string concatenation',
            'command_injection': 'Avoid dynamic command execution or properly sanitize inputs',
            'path_traversal': 'Validate file paths and implement proper access controls',
            'insecure_random': 'Use cryptographically secure random number generation'
        }
        return fixes.get(vuln_type, 'Review and fix the security issue')
    
    def _get_nextjs_fix(self, vuln_type: str) -> str:
        """Get Next.js specific fix recommendations."""
        fixes = {
            'public_env_var': 'Ensure no sensitive data is exposed through NEXT_PUBLIC_ variables',
            'ssrf': 'Validate and sanitize all user inputs in getServerSideProps',
            'open_redirect': 'Validate route parameters before navigation',
            'dynamic_image': 'Validate image URLs and use Next.js Image domains configuration'
        }
        return fixes.get(vuln_type, 'Review Next.js security best practices')
    
    def _get_react_fix(self, vuln_type: str) -> str:
        """Get React specific fix recommendations."""
        fixes = {
            'dynamic_script': 'Avoid dynamic script creation or properly sanitize content',
            'unsafe_api_call': 'Validate and sanitize inputs before making API calls',
            'eval_handler': 'Remove eval() usage and use safer alternatives'
        }
        return fixes.get(vuln_type, 'Review React security best practices')
    
    def _get_vite_fix(self, vuln_type: str) -> str:
        """Get Vite specific fix recommendations."""
        fixes = {
            'env_var_usage': 'Ensure no sensitive data is exposed through environment variables',
            'hmr_production': 'Ensure HMR code is removed in production builds'
        }
        return fixes.get(vuln_type, 'Review Vite configuration and build process')
    
    def _get_python_fix(self, vuln_type: str) -> str:
        """Get Python specific fix recommendations."""
        fixes = {
            'code_injection': 'Avoid using eval/exec or properly sanitize inputs',
            'unsafe_input': 'Use input() with clear prompts or consider alternatives',
            'dangerous_import': 'Use these modules carefully and validate all inputs'
        }
        return fixes.get(vuln_type, 'Review Python security best practices')
    
    async def scan_url(self, url: str) -> List[Vulnerability]:
        """Scan a URL for static code-related security issues."""
        vulnerabilities = []
        
        try:
            import aiohttp
            
            # Create session with timeout
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Test for exposed source code files
                source_endpoints = [
                    '/app.js',
                    '/index.js',
                    '/main.js',
                    '/server.js',
                    '/app.py',
                    '/main.py',
                    '/server.py',
                    '/index.html',
                    '/app.html',
                    '/main.html',
                    '/style.css',
                    '/app.css',
                    '/main.css',
                    '/app.ts',
                    '/main.ts',
                    '/index.ts',
                    '/app.tsx',
                    '/main.tsx',
                    '/index.tsx',
                    '/app.jsx',
                    '/main.jsx',
                    '/index.jsx'
                ]
                
                for endpoint in source_endpoints:
                    test_url = url.rstrip('/') + endpoint
                    try:
                        async with session.get(test_url) as response:
                            if response.status == 200:
                                content = await response.text()
                                
                                # Check if it's actually source code
                                if self._is_source_code_content(content, endpoint):
                                    vulnerabilities.append(self.create_vulnerability(
                                        title=f"Exposed Source Code File: {endpoint}",
                                        description=f"Source code file {endpoint} is accessible via HTTP",
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
                                    
                                    # Analyze the source code for vulnerabilities
                                    code_vulns = await self._analyze_exposed_source_code(content, endpoint, test_url)
                                    vulnerabilities.extend(code_vulns)
                    except Exception as e:
                        if self.config.verbose:
                            print(f"Error testing {test_url}: {e}")
                        continue
                
                # Test for exposed build artifacts
                build_vulns = await self._test_build_artifacts(session, url)
                vulnerabilities.extend(build_vulns)
                
                # Test for source maps
                sourcemap_vulns = await self._test_source_maps(session, url)
                vulnerabilities.extend(sourcemap_vulns)
                
        except Exception as e:
            if self.config.verbose:
                print(f"Error scanning URL {url}: {e}")
        
        return vulnerabilities
    
    def _is_source_code_content(self, content: str, endpoint: str) -> bool:
        """Check if content appears to be source code."""
        # Skip if content is too short or looks like an error page
        if len(content) < 10:
            return False
        
        # Check for common error page indicators
        error_indicators = ['404', 'not found', 'error', 'page not found', '<html>', '<!doctype']
        if any(indicator in content.lower() for indicator in error_indicators):
            return False
        
        # Check for specific file type indicators
        if endpoint.endswith('.js') or endpoint.endswith('.jsx'):
            return any(keyword in content for keyword in ['function', 'const', 'let', 'var', 'import', 'export', 'require'])
        elif endpoint.endswith('.ts') or endpoint.endswith('.tsx'):
            return any(keyword in content for keyword in ['function', 'const', 'let', 'var', 'import', 'export', 'interface', 'type'])
        elif endpoint.endswith('.py'):
            return any(keyword in content for keyword in ['def ', 'import ', 'from ', 'class ', 'if __name__'])
        elif endpoint.endswith('.html'):
            return '<html' in content or '<!DOCTYPE' in content or '<head>' in content
        elif endpoint.endswith('.css'):
            return '{' in content and '}' in content and ('color:' in content or 'margin:' in content or 'padding:' in content)
        
        return False
    
    async def _analyze_exposed_source_code(self, content: str, endpoint: str, url: str) -> List[Vulnerability]:
        """Analyze exposed source code for security vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Use existing pattern scanning logic
            lines = content.split('\n')
            
            for vuln_type, patterns in self.vulnerability_patterns.items():
                for pattern_info in patterns:
                    pattern = pattern_info['pattern']
                    severity = pattern_info['severity']
                    description = pattern_info['description']
                    
                    for line_num, line in enumerate(lines, 1):
                        matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in matches:
                            # Skip false positives
                            if self._is_false_positive(line, match.group(), vuln_type):
                                continue
                            
                            vulnerabilities.append(self.create_vulnerability(
                                title=f"Exposed Code Vulnerability: {vuln_type.replace('_', ' ').title()}",
                                description=f"{description} - Found in exposed source code",
                                severity=severity,
                                vuln_type=vuln_type,
                                fix=self._get_fix_for_pattern(vuln_type),
                                metadata={
                                    'url': url,
                                    'endpoint': endpoint,
                                    'line_number': line_num,
                                    'pattern': pattern,
                                    'matched_text': match.group(),
                                    'line_content': line.strip()
                                }
                            ))
            
            # Check for hardcoded secrets in exposed code
            secret_vulns = await self._check_hardcoded_secrets(content, endpoint, url)
            vulnerabilities.extend(secret_vulns)
            
        except Exception as e:
            if self.config.verbose:
                print(f"Error analyzing exposed source code {endpoint}: {e}")
        
        return vulnerabilities
    
    async def _check_hardcoded_secrets(self, content: str, endpoint: str, url: str) -> List[Vulnerability]:
        """Check for hardcoded secrets in exposed source code."""
        vulnerabilities = []
        
        # Enhanced secret patterns for exposed code
        secret_patterns = [
            {
                'pattern': r'["\'](?:sk-[a-zA-Z0-9]{48}|sk-ant-[a-zA-Z0-9\-_]{95,})["\']',
                'type': 'ai_api_key',
                'description': 'AI API key (OpenAI/Anthropic) found in source code'
            },
            {
                'pattern': r'["\']AKIA[A-Z0-9]{16}["\']',
                'type': 'aws_key',
                'description': 'AWS access key found in source code'
            },
            {
                'pattern': r'["\']ghp_[a-zA-Z0-9]{36}["\']',
                'type': 'github_token',
                'description': 'GitHub personal access token found in source code'
            },
            {
                'pattern': r'["\'](?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{6,}["\']',
                'type': 'password',
                'description': 'Hardcoded password found in source code'
            },
            {
                'pattern': r'["\'](?:secret|secret_key|private_key)\s*[:=]\s*["\'][^"\']{8,}["\']',
                'type': 'secret',
                'description': 'Hardcoded secret found in source code'
            },
            {
                'pattern': r'["\'](?:api_key|apikey|access_token)\s*[:=]\s*["\'][^"\']{8,}["\']',
                'type': 'api_key',
                'description': 'Hardcoded API key found in source code'
            }
        ]
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern_info in secret_patterns:
                matches = re.finditer(pattern_info['pattern'], line, re.IGNORECASE)
                for match in matches:
                    # Skip if it's clearly a comment or example
                    if any(indicator in line.lower() for indicator in ['//', '/*', '#', 'example', 'sample', 'todo']):
                        continue
                    
                    vulnerabilities.append(self.create_vulnerability(
                        title=f"Hardcoded Secret in Exposed Code: {pattern_info['type']}",
                        description=f"{pattern_info['description']} - Exposed via HTTP",
                        severity="critical",
                        vuln_type="secrets_exposure",
                        fix="Remove hardcoded secrets and use environment variables or secure configuration",
                        metadata={
                            'url': url,
                            'endpoint': endpoint,
                            'line_number': line_num,
                            'secret_type': pattern_info['type'],
                            'matched_text': self._mask_secret(match.group()),
                            'line_content': self._mask_secret(line.strip())
                        }
                    ))
        
        return vulnerabilities
    
    def _mask_secret(self, text: str) -> str:
        """Mask sensitive data in text."""
        # Mask common secret patterns
        text = re.sub(r'sk-[a-zA-Z0-9]{48}', 'sk-***MASKED***', text)
        text = re.sub(r'sk-ant-[a-zA-Z0-9\-_]+', 'sk-ant-***MASKED***', text)
        text = re.sub(r'AKIA[A-Z0-9]{16}', 'AKIA***MASKED***', text)
        text = re.sub(r'ghp_[a-zA-Z0-9]+', 'ghp_***MASKED***', text)
        text = re.sub(r'["\'][a-zA-Z0-9]{32,}["\']', '"***MASKED***"', text)
        
        return text
    
    async def _test_build_artifacts(self, session, url: str) -> List[Vulnerability]:
        """Test for exposed build artifacts."""
        vulnerabilities = []
        
        # Common build artifact endpoints
        build_endpoints = [
            '/dist/',
            '/build/',
            '/out/',
            '/.next/',
            '/public/',
            '/static/',
            '/assets/',
            '/js/',
            '/css/',
            '/images/',
            '/fonts/'
        ]
        
        for endpoint in build_endpoints:
            test_url = url.rstrip('/') + endpoint
            try:
                async with session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check if it's a directory listing
                        if self._is_directory_listing(content):
                            vulnerabilities.append(self.create_vulnerability(
                                title=f"Exposed Build Directory: {endpoint}",
                                description=f"Build directory {endpoint} is accessible via HTTP",
                                severity="medium",
                                vuln_type="information_disclosure",
                                fix=f"Disable directory listing for {endpoint}",
                                metadata={
                                    'url': test_url,
                                    'directory': endpoint,
                                    'status_code': response.status
                                }
                            ))
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_source_maps(self, session, url: str) -> List[Vulnerability]:
        """Test for exposed source maps."""
        vulnerabilities = []
        
        # Common source map endpoints
        sourcemap_endpoints = [
            '/app.js.map',
            '/main.js.map',
            '/index.js.map',
            '/app.css.map',
            '/main.css.map',
            '/index.css.map',
            '/bundle.js.map',
            '/vendor.js.map',
            '/chunk.js.map'
        ]
        
        for endpoint in sourcemap_endpoints:
            test_url = url.rstrip('/') + endpoint
            try:
                async with session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check if it's actually a source map
                        if self._is_source_map_content(content):
                            vulnerabilities.append(self.create_vulnerability(
                                title=f"Exposed Source Map: {endpoint}",
                                description=f"Source map {endpoint} is accessible via HTTP and may expose source code",
                                severity="medium",
                                vuln_type="information_disclosure",
                                fix=f"Remove or secure access to {endpoint}",
                                metadata={
                                    'url': test_url,
                                    'endpoint': endpoint,
                                    'status_code': response.status,
                                    'content_length': len(content)
                                }
                            ))
            except Exception:
                continue
        
        return vulnerabilities
    
    def _is_source_map_content(self, content: str) -> bool:
        """Check if content appears to be a source map."""
        try:
            import json
            data = json.loads(content)
            return 'version' in data and 'sources' in data and 'mappings' in data
        except:
            return False
    
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