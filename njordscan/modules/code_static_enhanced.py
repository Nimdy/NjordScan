"""
Enhanced Static Code Analysis Module

Uses AST parsing and advanced pattern engine for superior vulnerability detection.
"""

import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

from .base import BaseModule
from ..vulnerability import Vulnerability
from ..analysis.ast_analyzer import get_ast_analyzer, SecurityFinding
from ..analysis.pattern_engine import PatternEngine, PatternMatch

logger = logging.getLogger(__name__)

class EnhancedCodeStaticModule(BaseModule):
    """Enhanced static code analysis module with AST parsing and pattern engine."""
    
    def __init__(self, config, vuln_id_generator):
        super().__init__(config, vuln_id_generator)
        
        # Initialize analysis engines
        self.pattern_engine = PatternEngine()
        
        # File extensions to analyze
        self.supported_extensions = {
            '.js', '.jsx', '.ts', '.tsx', '.mjs',  # JavaScript/TypeScript
            '.py',  # Python
            '.json', '.yaml', '.yml',  # Configuration files
            '.html', '.htm',  # HTML files
            '.css', '.scss', '.sass'  # Stylesheets
        }
        
        # Performance tracking
        self.analysis_stats = {
            'files_analyzed': 0,
            'ast_analysis_success': 0,
            'ast_analysis_failed': 0,
            'pattern_matches': 0,
            'vulnerabilities_found': 0
        }
    
    def should_run(self, mode: str) -> bool:
        """Enhanced static analysis runs in static and full modes."""
        return mode in ['static', 'full']
    
    async def scan(self, target: str) -> List[Vulnerability]:
        """Enhanced static code analysis scan."""
        vulnerabilities = []
        
        if target.startswith(('http://', 'https://')):
            return await self.scan_url(target)
        
        target_path = Path(target)
        if not target_path.exists():
            return vulnerabilities
        
        logger.info("Starting enhanced static code analysis")
        
        # Find all source files
        source_files = self._find_source_files(target_path)
        logger.info(f"Found {len(source_files)} files to analyze")
        
        # Analyze files with controlled concurrency
        semaphore = asyncio.Semaphore(min(10, self.config.max_concurrent))
        
        async def analyze_file_with_semaphore(file_path):
            async with semaphore:
                return await self._analyze_source_file(file_path)
        
        # Process files in batches
        tasks = [analyze_file_with_semaphore(file_path) for file_path in source_files]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect results
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"File analysis failed: {result}")
                continue
            
            if isinstance(result, list):
                vulnerabilities.extend(result)
        
        # Log analysis statistics
        logger.info(f"Enhanced static analysis completed: {self.analysis_stats}")
        
        return vulnerabilities
    
    def _find_source_files(self, target_path: Path) -> List[Path]:
        """Find all source files to analyze."""
        source_files = []
        
        for file_path in target_path.rglob('*'):
            if not file_path.is_file():
                continue
            
            # Check file extension
            if file_path.suffix.lower() not in self.supported_extensions:
                continue
            
            # Skip files that should be excluded
            if self._should_skip_file(file_path):
                continue
            
            source_files.append(file_path)
        
        return source_files
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Enhanced file filtering logic."""
        # Standard exclusions
        skip_dirs = {
            'node_modules', '.git', '.next', 'dist', 'build', 
            '__pycache__', '.pytest_cache', 'coverage', '.nyc_output',
            'vendor', '.svn', '.hg', '.vscode', '.idea'
        }
        
        # Check directory exclusions
        for part in file_path.parts:
            if part in skip_dirs:
                return True
        
        # Skip minified files
        if '.min.' in file_path.name:
            return True
        
        # Skip source maps
        if file_path.name.endswith('.map'):
            return True
        
        # Skip backup files
        if file_path.name.endswith(('.bak', '.backup', '.orig')):
            return True
        
        # Skip test files unless explicitly requested
        if not getattr(self.config, 'include_tests', False):
            test_indicators = ['test', 'spec', '__tests__', '.test.', '.spec.', 'cypress/', 'jest/']
            if any(indicator in str(file_path).lower() for indicator in test_indicators):
                return True
        
        # Skip very large files (>5MB)
        try:
            if file_path.stat().st_size > 5 * 1024 * 1024:
                logger.warning(f"Skipping large file: {file_path} ({file_path.stat().st_size / 1024 / 1024:.1f}MB)")
                return True
        except OSError:
            return True
        
        # Skip files based on configuration exclusions
        if self.config.should_exclude_path(file_path):
            return True
        
        return False
    
    async def _analyze_source_file(self, file_path: Path) -> List[Vulnerability]:
        """Analyze a single source file using multiple techniques."""
        vulnerabilities = []
        self.analysis_stats['files_analyzed'] += 1
        
        try:
            content = self.get_file_content(str(file_path))
            if not content:
                return vulnerabilities
            
            # Skip empty files
            if len(content.strip()) == 0:
                return vulnerabilities
            
            logger.debug(f"Analyzing file: {file_path}")
            
            # 1. AST-based analysis for JavaScript/TypeScript files
            if file_path.suffix.lower() in ['.js', '.jsx', '.ts', '.tsx', '.mjs']:
                ast_vulnerabilities = await self._perform_ast_analysis(file_path, content)
                vulnerabilities.extend(ast_vulnerabilities)
            
            # 2. Pattern-based analysis for all files
            pattern_vulnerabilities = await self._perform_pattern_analysis(file_path, content)
            vulnerabilities.extend(pattern_vulnerabilities)
            
            # 3. Framework-specific analysis
            framework_vulnerabilities = await self._perform_framework_analysis(file_path, content)
            vulnerabilities.extend(framework_vulnerabilities)
            
            # 4. Configuration file analysis
            if self._is_config_file(file_path):
                config_vulnerabilities = await self._perform_config_analysis(file_path, content)
                vulnerabilities.extend(config_vulnerabilities)
            
            self.analysis_stats['vulnerabilities_found'] += len(vulnerabilities)
            
        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {e}")
        
        return vulnerabilities
    
    async def _perform_ast_analysis(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Perform AST-based analysis."""
        vulnerabilities = []
        
        try:
            # Get appropriate AST analyzer
            ast_analyzer = get_ast_analyzer(file_path)
            
            # Analyze file
            findings = ast_analyzer.analyze_file(file_path, content)
            
            if findings:
                self.analysis_stats['ast_analysis_success'] += 1
                logger.debug(f"AST analysis found {len(findings)} findings in {file_path}")
            else:
                self.analysis_stats['ast_analysis_failed'] += 1
            
            # Convert findings to vulnerabilities
            for finding in findings:
                vulnerability = self._convert_ast_finding_to_vulnerability(finding, file_path)
                vulnerabilities.append(vulnerability)
            
        except Exception as e:
            self.analysis_stats['ast_analysis_failed'] += 1
            logger.debug(f"AST analysis failed for {file_path}: {e}")
        
        return vulnerabilities
    
    async def _perform_pattern_analysis(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Perform pattern-based analysis."""
        vulnerabilities = []
        
        try:
            # Analyze with pattern engine
            matches = self.pattern_engine.analyze_file(file_path, content)
            
            self.analysis_stats['pattern_matches'] += len(matches)
            
            # Convert matches to vulnerabilities
            for match in matches:
                vulnerability = self._convert_pattern_match_to_vulnerability(match, file_path)
                vulnerabilities.append(vulnerability)
            
        except Exception as e:
            logger.error(f"Pattern analysis failed for {file_path}: {e}")
        
        return vulnerabilities
    
    async def _perform_framework_analysis(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Perform framework-specific analysis."""
        vulnerabilities = []
        
        try:
            if self.config.framework == 'nextjs':
                vulnerabilities.extend(await self._analyze_nextjs_specific(file_path, content))
            elif self.config.framework == 'react':
                vulnerabilities.extend(await self._analyze_react_specific(file_path, content))
            elif self.config.framework == 'vite':
                vulnerabilities.extend(await self._analyze_vite_specific(file_path, content))
            
        except Exception as e:
            logger.error(f"Framework analysis failed for {file_path}: {e}")
        
        return vulnerabilities
    
    async def _perform_config_analysis(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Perform configuration file analysis."""
        vulnerabilities = []
        
        try:
            # Analyze package.json
            if file_path.name == 'package.json':
                vulnerabilities.extend(await self._analyze_package_json(file_path, content))
            
            # Analyze environment files
            elif file_path.name.startswith('.env'):
                vulnerabilities.extend(await self._analyze_env_file(file_path, content))
            
            # Analyze framework configs
            elif 'config' in file_path.name.lower():
                vulnerabilities.extend(await self._analyze_framework_config(file_path, content))
            
        except Exception as e:
            logger.error(f"Config analysis failed for {file_path}: {e}")
        
        return vulnerabilities
    
    def _convert_ast_finding_to_vulnerability(self, finding: SecurityFinding, file_path: Path) -> Vulnerability:
        """Convert AST finding to vulnerability object."""
        return self.create_vulnerability(
            title=f"AST Analysis: {finding.message}",
            description=f"{finding.message}. Detected through AST analysis with {finding.confidence:.1%} confidence.",
            severity=finding.severity,
            confidence="high" if finding.confidence > 0.8 else "medium" if finding.confidence > 0.5 else "low",
            vuln_type=finding.finding_type,
            file_path=str(file_path),
            line_number=finding.line,
            code_snippet=finding.code_snippet,
            fix=self._get_ast_finding_fix(finding.finding_type),
            metadata={
                'analysis_type': 'ast',
                'confidence_score': finding.confidence,
                'function_context': finding.function_context,
                'data_flow': finding.data_flow
            }
        )
    
    def _convert_pattern_match_to_vulnerability(self, match: PatternMatch, file_path: Path) -> Vulnerability:
        """Convert pattern match to vulnerability object."""
        return self.create_vulnerability(
            title=f"Pattern Detection: {match.pattern_name}",
            description=f"{match.pattern_name} detected through advanced pattern matching.",
            severity=match.severity,
            confidence="high" if match.confidence > 0.8 else "medium" if match.confidence > 0.5 else "low",
            vuln_type=match.pattern_id,
            file_path=str(file_path),
            line_number=match.line_number,
            code_snippet=match.matched_text,
            fix=self._get_pattern_fix(match.pattern_id),
            metadata={
                'analysis_type': 'pattern',
                'confidence_score': match.confidence,
                'function_context': match.function_name,
                'cwe_ids': match.metadata.get('cwe_ids', []),
                'owasp_categories': match.metadata.get('owasp_categories', [])
            }
        )
    
    async def _analyze_nextjs_specific(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Enhanced Next.js specific analysis."""
        vulnerabilities = []
        
        # API route security
        if '/api/' in str(file_path):
            vulnerabilities.extend(await self._analyze_nextjs_api_route(file_path, content))
        
        # Page component security
        if '/pages/' in str(file_path) or '/app/' in str(file_path):
            vulnerabilities.extend(await self._analyze_nextjs_page(file_path, content))
        
        # Middleware security
        if 'middleware' in file_path.name:
            vulnerabilities.extend(await self._analyze_nextjs_middleware(file_path, content))
        
        return vulnerabilities
    
    async def _analyze_nextjs_api_route(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Analyze Next.js API routes for security issues."""
        vulnerabilities = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for missing CORS configuration
            if 'res.setHeader' in line and 'Access-Control-Allow-Origin' in line:
                if '*' in line:
                    vulnerabilities.append(self.create_vulnerability(
                        title="Overly Permissive CORS in API Route",
                        description="API route allows all origins with wildcard CORS policy",
                        severity="medium",
                        vuln_type="insecure_cors",
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=line.strip(),
                        fix="Specify explicit allowed origins instead of using wildcards"
                    ))
            
            # Check for missing rate limiting
            if 'export default' in line and 'handler' in content:
                if not any(rate_limit_indicator in content for rate_limit_indicator in 
                          ['rate-limit', 'rateLimit', 'slowDown', 'express-rate-limit']):
                    vulnerabilities.append(self.create_vulnerability(
                        title="Missing Rate Limiting in API Route",
                        description="API route lacks rate limiting protection",
                        severity="medium",
                        vuln_type="insecure_configuration",
                        file_path=str(file_path),
                        line_number=line_num,
                        fix="Implement rate limiting middleware to prevent abuse"
                    ))
        
        return vulnerabilities
    
    async def _analyze_nextjs_page(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Analyze Next.js pages for security issues."""
        vulnerabilities = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for unsafe getServerSideProps
            if 'getServerSideProps' in line:
                # Look for potential SSRF in the function
                gss_start = line_num
                gss_content = self._extract_function_content(lines, gss_start, 'getServerSideProps')
                
                if 'fetch(' in gss_content and 'req.' in gss_content:
                    vulnerabilities.append(self.create_vulnerability(
                        title="Potential SSRF in getServerSideProps",
                        description="getServerSideProps makes external requests with user-controlled input",
                        severity="high",
                        vuln_type="ssrf",
                        file_path=str(file_path),
                        line_number=line_num,
                        fix="Validate and sanitize all user inputs before making external requests"
                    ))
        
        return vulnerabilities
    
    async def _analyze_nextjs_middleware(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Analyze Next.js middleware for security issues."""
        vulnerabilities = []
        lines = content.split('\n')
        
        # Check for overly broad matcher
        for line_num, line in enumerate(lines, 1):
            if 'matcher:' in line and ('*' in line or '/((?!api|_next/static|favicon.ico).*)' in line):
                vulnerabilities.append(self.create_vulnerability(
                    title="Overly Broad Middleware Matcher",
                    description="Middleware matcher pattern may impact performance and security",
                    severity="low",
                    vuln_type="insecure_configuration",
                    file_path=str(file_path),
                    line_number=line_num,
                    code_snippet=line.strip(),
                    fix="Use more specific matcher patterns to reduce performance impact"
                ))
        
        return vulnerabilities
    
    async def _analyze_react_specific(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Enhanced React specific analysis."""
        vulnerabilities = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for unsafe React patterns
            if 'useEffect' in line and 'fetch' in content:
                # Check for useEffect with external dependencies
                effect_content = self._extract_hook_content(lines, line_num, 'useEffect')
                if 'fetch(' in effect_content and ('props.' in effect_content or 'router.' in effect_content):
                    vulnerabilities.append(self.create_vulnerability(
                        title="Unsafe External Request in useEffect",
                        description="useEffect makes external requests with potentially unsafe dependencies",
                        severity="medium",
                        vuln_type="ssrf",
                        file_path=str(file_path),
                        line_number=line_num,
                        fix="Validate and sanitize external dependencies before using in fetch requests"
                    ))
        
        return vulnerabilities
    
    async def _analyze_vite_specific(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Enhanced Vite specific analysis."""
        vulnerabilities = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for exposed Vite dev features in production
            if 'import.meta.hot' in line and 'production' not in str(file_path):
                vulnerabilities.append(self.create_vulnerability(
                    title="Vite HMR Code in Production Build",
                    description="Vite Hot Module Replacement code may be included in production",
                    severity="low",
                    vuln_type="debug_mode_enabled",
                    file_path=str(file_path),
                    line_number=line_num,
                    code_snippet=line.strip(),
                    fix="Ensure HMR code is properly tree-shaken in production builds"
                ))
        
        return vulnerabilities
    
    async def _analyze_package_json(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Enhanced package.json analysis."""
        vulnerabilities = []
        
        try:
            import json
            package_data = json.loads(content)
            
            # Check for development dependencies in production
            if 'dependencies' in package_data:
                dev_packages = {
                    'nodemon', 'webpack-dev-server', 'vite', '@vite/client',
                    'eslint', 'prettier', 'jest', 'cypress', '@types/',
                    'typescript', '@typescript-eslint/', 'ts-node'
                }
                
                for dep_name in package_data['dependencies']:
                    if any(dev_pkg in dep_name for dev_pkg in dev_packages):
                        vulnerabilities.append(self.create_vulnerability(
                            title="Development Dependency in Production",
                            description=f"Development package '{dep_name}' found in production dependencies",
                            severity="medium",
                            vuln_type="insecure_configuration",
                            file_path=str(file_path),
                            fix=f"Move {dep_name} to devDependencies section"
                        ))
            
            # Check for known vulnerable packages
            vulnerable_packages = {
                'event-stream': 'Known malicious package',
                'eslint-scope': 'Compromised package (historical)',
                'flatmap-stream': 'Malicious dependency'
            }
            
            all_deps = {
                **package_data.get('dependencies', {}),
                **package_data.get('devDependencies', {})
            }
            
            for vuln_package, reason in vulnerable_packages.items():
                if vuln_package in all_deps:
                    vulnerabilities.append(self.create_vulnerability(
                        title=f"Known Vulnerable Package: {vuln_package}",
                        description=f"Package {vuln_package} is known to be vulnerable: {reason}",
                        severity="high",
                        vuln_type="vulnerable_dependency",
                        file_path=str(file_path),
                        fix=f"Remove {vuln_package} and find a secure alternative"
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
    
    async def _analyze_env_file(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Enhanced environment file analysis."""
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
                
                # Check for exposed secrets in public env vars
                if key.startswith('NEXT_PUBLIC_') or key.startswith('VITE_'):
                    if self._looks_like_secret(value):
                        vulnerabilities.append(self.create_vulnerability(
                            title="Secret in Public Environment Variable",
                            description=f"Public environment variable '{key}' contains what appears to be a secret",
                            severity="critical",
                            vuln_type="secrets_exposure",
                            file_path=str(file_path),
                            line_number=line_num,
                            code_snippet=f"{key}=***REDACTED***",
                            fix="Move secrets to server-side environment variables"
                        ))
                
                # Check for weak or default values
                if self._is_security_related_key(key):
                    if value in ['', 'password', '123456', 'secret', 'change_me', 'your_key_here']:
                        vulnerabilities.append(self.create_vulnerability(
                            title="Weak or Default Secret Value",
                            description=f"Security-related variable '{key}' has a weak or default value",
                            severity="high",
                            vuln_type="secrets_exposure",
                            file_path=str(file_path),
                            line_number=line_num,
                            fix="Set a strong, unique value for this security variable"
                        ))
        
        return vulnerabilities
    
    async def _analyze_framework_config(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Enhanced framework configuration analysis."""
        vulnerabilities = []
        
        # Next.js config analysis
        if 'next.config' in file_path.name:
            vulnerabilities.extend(await self._analyze_nextjs_config_advanced(file_path, content))
        
        # Vite config analysis
        elif 'vite.config' in file_path.name:
            vulnerabilities.extend(await self._analyze_vite_config_advanced(file_path, content))
        
        return vulnerabilities
    
    async def _analyze_nextjs_config_advanced(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Advanced Next.js configuration analysis."""
        vulnerabilities = []
        
        # Check for insecure configurations
        insecure_configs = {
            'experimental': 'Experimental features should not be used in production',
            'trailingSlash: true': 'Trailing slashes can cause SEO and caching issues',
            'poweredByHeader: true': 'X-Powered-By header exposes technology stack'
        }
        
        for config, issue in insecure_configs.items():
            if config in content:
                vulnerabilities.append(self.create_vulnerability(
                    title=f"Insecure Next.js Configuration: {config}",
                    description=issue,
                    severity="medium",
                    vuln_type="insecure_configuration",
                    file_path=str(file_path),
                    fix=f"Review and secure the {config} configuration"
                ))
        
        return vulnerabilities
    
    async def _analyze_vite_config_advanced(self, file_path: Path, content: str) -> List[Vulnerability]:
        """Advanced Vite configuration analysis."""
        vulnerabilities = []
        
        # Check for insecure server configurations
        if 'server:' in content and 'host:' in content:
            if '0.0.0.0' in content or 'host: true' in content:
                vulnerabilities.append(self.create_vulnerability(
                    title="Insecure Vite Server Host Configuration",
                    description="Vite server is configured to bind to all interfaces",
                    severity="medium",
                    vuln_type="insecure_configuration",
                    file_path=str(file_path),
                    fix="Use specific host binding for production deployments"
                ))
        
        return vulnerabilities
    
    def _is_config_file(self, file_path: Path) -> bool:
        """Check if file is a configuration file."""
        config_files = {
            'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
            'next.config.js', 'next.config.ts', 'next.config.mjs',
            'vite.config.js', 'vite.config.ts', 'vite.config.mjs',
            'webpack.config.js', 'webpack.config.ts',
            'tsconfig.json', 'jsconfig.json',
            'tailwind.config.js', 'postcss.config.js'
        }
        
        return (file_path.name in config_files or 
                file_path.name.startswith('.env') or
                'config' in file_path.name.lower())
    
    def _extract_function_content(self, lines: List[str], start_line: int, function_name: str) -> str:
        """Extract content of a function."""
        content_lines = []
        brace_count = 0
        in_function = False
        
        for i in range(start_line - 1, min(len(lines), start_line + 50)):
            line = lines[i]
            
            if function_name in line:
                in_function = True
            
            if in_function:
                content_lines.append(line)
                brace_count += line.count('{') - line.count('}')
                
                if brace_count <= 0 and '{' in ''.join(content_lines):
                    break
        
        return '\n'.join(content_lines)
    
    def _extract_hook_content(self, lines: List[str], start_line: int, hook_name: str) -> str:
        """Extract content of a React hook."""
        content_lines = []
        paren_count = 0
        in_hook = False
        
        for i in range(start_line - 1, min(len(lines), start_line + 20)):
            line = lines[i]
            
            if hook_name in line:
                in_hook = True
            
            if in_hook:
                content_lines.append(line)
                paren_count += line.count('(') - line.count(')')
                
                if paren_count <= 0 and '(' in ''.join(content_lines):
                    break
        
        return '\n'.join(content_lines)
    
    def _looks_like_secret(self, value: str) -> bool:
        """Check if value looks like a secret."""
        if len(value) < 8:
            return False
        
        # Check for common secret patterns
        secret_patterns = [
            r'^sk-[a-zA-Z0-9]{48}$',  # OpenAI keys
            r'^sk-ant-[a-zA-Z0-9\-_]{95,}$',  # Anthropic keys
            r'^AKIA[A-Z0-9]{16}$',  # AWS keys
            r'^ghp_[a-zA-Z0-9]{36}$',  # GitHub tokens
            r'^[a-zA-Z0-9]{32,}$',  # Long alphanumeric strings
        ]
        
        import re
        for pattern in secret_patterns:
            if re.match(pattern, value):
                return True
        
        return False
    
    def _is_security_related_key(self, key: str) -> bool:
        """Check if key is security-related."""
        security_keywords = [
            'secret', 'key', 'token', 'password', 'pass', 'auth',
            'api_key', 'apikey', 'private', 'credential', 'jwt',
            'session', 'salt', 'hash'
        ]
        
        key_lower = key.lower()
        return any(keyword in key_lower for keyword in security_keywords)
    
    def _get_ast_finding_fix(self, finding_type: str) -> str:
        """Get fix recommendation for AST finding."""
        fixes = {
            'xss_innerHTML': 'Use textContent instead of innerHTML, or properly sanitize input',
            'xss_jsx_dangerous': 'Avoid dangerouslySetInnerHTML or use a sanitization library',
            'xss_document_write': 'Use modern DOM manipulation methods instead of document.write',
            'sql_injection': 'Use parameterized queries or prepared statements',
            'command_injection': 'Avoid dynamic command execution or properly validate inputs',
            'path_traversal': 'Validate and sanitize file paths, use path.resolve()',
            'weak_crypto': 'Use crypto.getRandomValues() or crypto.randomBytes() for secure random generation',
            'hardcoded_secret': 'Move secrets to environment variables or secure configuration',
            'code_injection': 'Avoid eval() and Function constructor, or properly sanitize inputs'
        }
        
        return fixes.get(finding_type, 'Review and address the security issue identified by AST analysis')
    
    def _get_pattern_fix(self, pattern_id: str) -> str:
        """Get fix recommendation for pattern match."""
        fixes = {
            'xss_innerHTML': 'Use safe DOM manipulation methods and sanitize user input',
            'xss_dangerously_set_inner_html': 'Use React\'s built-in XSS protection or sanitize with DOMPurify',
            'sql_injection_string_concat': 'Use parameterized queries instead of string concatenation',
            'command_injection_exec': 'Avoid dynamic command execution or use input validation',
            'path_traversal_fs': 'Validate file paths and use path.resolve() to prevent traversal',
            'hardcoded_api_key': 'Move API keys to environment variables',
            'weak_random': 'Use cryptographically secure random number generation',
            'nextjs_ssrf_image': 'Validate image URLs and configure allowed domains',
            'react_ref_xss': 'Sanitize content before setting innerHTML via refs'
        }
        
        return fixes.get(pattern_id, 'Review and address the security pattern detected')
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get analysis statistics."""
        return {
            **self.analysis_stats,
            'pattern_engine_stats': self.pattern_engine.get_pattern_statistics()
        }
    
    async def scan_url(self, url: str) -> List[Vulnerability]:
        """Enhanced URL scanning for static code-related security issues."""
        vulnerabilities = []
        
        try:
            import aiohttp
            
            # Create session with timeout
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                logger.info(f"Starting enhanced URL scan for: {url}")
                
                # Test for exposed source code files with enhanced detection
                source_vulns = await self._test_exposed_source_files(session, url)
                vulnerabilities.extend(source_vulns)
                
                # Test for exposed build artifacts and development files
                build_vulns = await self._test_exposed_build_artifacts(session, url)
                vulnerabilities.extend(build_vulns)
                
                # Test for exposed configuration files
                config_vulns = await self._test_exposed_config_files(session, url)
                vulnerabilities.extend(config_vulns)
                
                # Test for exposed development tools and debug endpoints
                dev_vulns = await self._test_development_endpoints(session, url)
                vulnerabilities.extend(dev_vulns)
                
                # Test for source maps and debugging information
                debug_vulns = await self._test_debug_information(session, url)
                vulnerabilities.extend(debug_vulns)
                
                logger.info(f"Enhanced URL scan completed for {url}: {len(vulnerabilities)} vulnerabilities found")
                
        except Exception as e:
            logger.error(f"Error in enhanced URL scan for {url}: {e}")
            if self.config.verbose:
                print(f"Error scanning URL {url}: {e}")
        
        return vulnerabilities
    
    async def _test_exposed_source_files(self, session, url: str) -> List[Vulnerability]:
        """Test for exposed source code files with enhanced detection."""
        vulnerabilities = []
        
        # Comprehensive list of source file endpoints
        source_endpoints = [
            # JavaScript/TypeScript files
            '/app.js', '/main.js', '/index.js', '/server.js', '/client.js',
            '/app.ts', '/main.ts', '/index.ts', '/server.ts', '/client.ts',
            '/app.jsx', '/main.jsx', '/index.jsx', '/App.jsx', '/Main.jsx',
            '/app.tsx', '/main.tsx', '/index.tsx', '/App.tsx', '/Main.tsx',
            # Python files
            '/app.py', '/main.py', '/server.py', '/client.py', '/index.py',
            '/manage.py', '/wsgi.py', '/asgi.py', '/settings.py', '/config.py',
            # HTML files
            '/index.html', '/app.html', '/main.html', '/home.html', '/login.html',
            # CSS files
            '/style.css', '/app.css', '/main.css', '/index.css', '/global.css',
            # Configuration files
            '/webpack.config.js', '/rollup.config.js', '/vite.config.js',
            '/next.config.js', '/nuxt.config.js', '/vue.config.js',
            # API and route files
            '/api.js', '/routes.js', '/controllers.js', '/middleware.js',
            '/api.ts', '/routes.ts', '/controllers.ts', '/middleware.ts'
        ]
        
        for endpoint in source_endpoints:
            test_url = url.rstrip('/') + endpoint
            try:
                async with session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Enhanced content validation
                        if self._is_valid_source_code(content, endpoint):
                            vulnerabilities.append(self.create_vulnerability(
                                title=f"Exposed Source Code: {endpoint}",
                                description=f"Source code file {endpoint} is accessible via HTTP",
                                severity="high",
                                vuln_type="information_disclosure",
                                fix=f"Remove or secure access to {endpoint}",
                                metadata={
                                    'url': test_url,
                                    'endpoint': endpoint,
                                    'status_code': response.status,
                                    'content_length': len(content),
                                    'content_type': response.headers.get('content-type', 'unknown')
                                }
                            ))
                            
                            # Enhanced analysis of exposed source code
                            enhanced_vulns = await self._analyze_exposed_source_enhanced(content, endpoint, test_url)
                            vulnerabilities.extend(enhanced_vulns)
            except Exception as e:
                if self.config.verbose:
                    print(f"Error testing {test_url}: {e}")
                continue
        
        return vulnerabilities
    
    async def _test_exposed_build_artifacts(self, session, url: str) -> List[Vulnerability]:
        """Test for exposed build artifacts and development files."""
        vulnerabilities = []
        
        # Build artifact endpoints
        build_endpoints = [
            '/dist/', '/build/', '/out/', '/.next/', '/.nuxt/', '/.vuepress/',
            '/public/', '/static/', '/assets/', '/js/', '/css/', '/images/',
            '/fonts/', '/media/', '/uploads/', '/files/', '/temp/', '/tmp/',
            '/cache/', '/logs/', '/backup/', '/backups/'
        ]
        
        for endpoint in build_endpoints:
            test_url = url.rstrip('/') + endpoint
            try:
                async with session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for directory listing
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
                        
                        # Check for specific build artifacts
                        artifact_vulns = await self._check_build_artifacts(session, url, endpoint)
                        vulnerabilities.extend(artifact_vulns)
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_exposed_config_files(self, session, url: str) -> List[Vulnerability]:
        """Test for exposed configuration files."""
        vulnerabilities = []
        
        config_endpoints = [
            '/.env', '/.env.local', '/.env.development', '/.env.production',
            '/package.json', '/package-lock.json', '/yarn.lock', '/pnpm-lock.yaml',
            '/composer.json', '/composer.lock', '/requirements.txt', '/Pipfile',
            '/pyproject.toml', '/go.mod', '/go.sum', '/pom.xml', '/build.gradle',
            '/tsconfig.json', '/jsconfig.json', '/tailwind.config.js',
            '/postcss.config.js', '/babel.config.js', '/eslint.config.js'
        ]
        
        for endpoint in config_endpoints:
            test_url = url.rstrip('/') + endpoint
            try:
                async with session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        if self._is_valid_config_file(content, endpoint):
                            vulnerabilities.append(self.create_vulnerability(
                                title=f"Exposed Configuration: {endpoint}",
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
                            
                            # Analyze config file for secrets
                            secret_vulns = await self._analyze_config_secrets(content, endpoint, test_url)
                            vulnerabilities.extend(secret_vulns)
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_development_endpoints(self, session, url: str) -> List[Vulnerability]:
        """Test for exposed development tools and debug endpoints."""
        vulnerabilities = []
        
        dev_endpoints = [
            '/debug', '/dev', '/development', '/test', '/testing',
            '/admin', '/administrator', '/manage', '/management',
            '/phpmyadmin', '/adminer', '/phpinfo.php', '/info.php',
            '/.git/', '/.svn/', '/.hg/', '/.bzr/',
            '/node_modules/', '/vendor/', '/bower_components/',
            '/wp-admin/', '/wp-content/', '/wp-includes/',
            '/.well-known/', '/.htaccess', '/.htpasswd',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml'
        ]
        
        for endpoint in dev_endpoints:
            test_url = url.rstrip('/') + endpoint
            try:
                async with session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for development/debug indicators
                        if self._is_development_endpoint(content, endpoint):
                            severity = "high" if any(dev in endpoint for dev in ['debug', 'admin', '.git', 'phpinfo']) else "medium"
                            
                            vulnerabilities.append(self.create_vulnerability(
                                title=f"Exposed Development Endpoint: {endpoint}",
                                description=f"Development/debug endpoint {endpoint} is accessible via HTTP",
                                severity=severity,
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
    
    async def _test_debug_information(self, session, url: str) -> List[Vulnerability]:
        """Test for exposed debugging information and source maps."""
        vulnerabilities = []
        
        # Source map endpoints
        sourcemap_endpoints = [
            '/app.js.map', '/main.js.map', '/index.js.map', '/bundle.js.map',
            '/vendor.js.map', '/chunk.js.map', '/app.css.map', '/main.css.map',
            '/index.css.map', '/style.css.map'
        ]
        
        for endpoint in sourcemap_endpoints:
            test_url = url.rstrip('/') + endpoint
            try:
                async with session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        if self._is_valid_source_map(content):
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
    
    async def _analyze_exposed_source_enhanced(self, content: str, endpoint: str, url: str) -> List[Vulnerability]:
        """Enhanced analysis of exposed source code."""
        vulnerabilities = []
        
        try:
            # Use pattern engine for advanced analysis
            matches = self.pattern_engine.analyze_file(Path(endpoint), content)
            
            for match in matches:
                vulnerability = self._convert_pattern_match_to_vulnerability(match, Path(endpoint))
                # Update metadata with URL information
                vulnerability.metadata.update({
                    'url': url,
                    'endpoint': endpoint,
                    'exposed_via_http': True
                })
                vulnerabilities.append(vulnerability)
            
            # Check for hardcoded secrets with enhanced patterns
            secret_vulns = await self._check_enhanced_secrets(content, endpoint, url)
            vulnerabilities.extend(secret_vulns)
            
            # Check for framework-specific vulnerabilities
            framework_vulns = await self._check_framework_vulnerabilities(content, endpoint, url)
            vulnerabilities.extend(framework_vulns)
            
        except Exception as e:
            logger.error(f"Error in enhanced source analysis for {endpoint}: {e}")
        
        return vulnerabilities
    
    async def _check_build_artifacts(self, session, url: str, base_endpoint: str) -> List[Vulnerability]:
        """Check for specific build artifacts."""
        vulnerabilities = []
        
        # Common build artifact files
        artifact_files = [
            'bundle.js', 'app.js', 'main.js', 'vendor.js', 'chunk.js',
            'bundle.css', 'app.css', 'main.css', 'style.css',
            'manifest.json', 'sw.js', 'service-worker.js'
        ]
        
        for artifact in artifact_files:
            test_url = url.rstrip('/') + base_endpoint + artifact
            try:
                async with session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check if it's actually a build artifact
                        if self._is_build_artifact(content, artifact):
                            vulnerabilities.append(self.create_vulnerability(
                                title=f"Exposed Build Artifact: {artifact}",
                                description=f"Build artifact {artifact} is accessible via HTTP",
                                severity="low",
                                vuln_type="information_disclosure",
                                fix=f"Ensure build artifacts are properly served and not exposed unnecessarily",
                                metadata={
                                    'url': test_url,
                                    'artifact': artifact,
                                    'base_endpoint': base_endpoint,
                                    'status_code': response.status
                                }
                            ))
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _analyze_config_secrets(self, content: str, endpoint: str, url: str) -> List[Vulnerability]:
        """Analyze configuration files for exposed secrets."""
        vulnerabilities = []
        
        # Enhanced secret patterns for config files
        secret_patterns = [
            {
                'pattern': r'["\'](?:sk-[a-zA-Z0-9]{48}|sk-ant-[a-zA-Z0-9\-_]{95,})["\']',
                'type': 'ai_api_key',
                'description': 'AI API key found in configuration file'
            },
            {
                'pattern': r'["\']AKIA[A-Z0-9]{16}["\']',
                'type': 'aws_key',
                'description': 'AWS access key found in configuration file'
            },
            {
                'pattern': r'["\']ghp_[a-zA-Z0-9]{36}["\']',
                'type': 'github_token',
                'description': 'GitHub token found in configuration file'
            },
            {
                'pattern': r'["\'](?:password|passwd|pwd|secret|key|token)\s*[:=]\s*["\'][^"\']{6,}["\']',
                'type': 'generic_secret',
                'description': 'Generic secret found in configuration file'
            }
        ]
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern_info in secret_patterns:
                import re
                matches = re.finditer(pattern_info['pattern'], line, re.IGNORECASE)
                for match in matches:
                    # Skip if it's clearly a comment or example
                    if any(indicator in line.lower() for indicator in ['//', '/*', '#', 'example', 'sample', 'todo']):
                        continue
                    
                    vulnerabilities.append(self.create_vulnerability(
                        title=f"Secret in Exposed Config: {pattern_info['type']}",
                        description=f"{pattern_info['description']} - Exposed via HTTP",
                        severity="critical",
                        vuln_type="secrets_exposure",
                        fix="Remove secrets from configuration files and use environment variables",
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
    
    async def _check_enhanced_secrets(self, content: str, endpoint: str, url: str) -> List[Vulnerability]:
        """Enhanced secret detection for exposed source code."""
        vulnerabilities = []
        
        # More comprehensive secret patterns
        secret_patterns = [
            {
                'pattern': r'["\'](?:sk-[a-zA-Z0-9]{48}|sk-ant-[a-zA-Z0-9\-_]{95,})["\']',
                'type': 'ai_api_key',
                'description': 'AI API key found in exposed source code'
            },
            {
                'pattern': r'["\']AKIA[A-Z0-9]{16}["\']',
                'type': 'aws_key',
                'description': 'AWS access key found in exposed source code'
            },
            {
                'pattern': r'["\']ghp_[a-zA-Z0-9]{36}["\']',
                'type': 'github_token',
                'description': 'GitHub token found in exposed source code'
            },
            {
                'pattern': r'["\'](?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{6,}["\']',
                'type': 'password',
                'description': 'Password found in exposed source code'
            },
            {
                'pattern': r'["\'](?:secret|secret_key|private_key|api_key|access_token)\s*[:=]\s*["\'][^"\']{8,}["\']',
                'type': 'generic_secret',
                'description': 'Generic secret found in exposed source code'
            }
        ]
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern_info in secret_patterns:
                import re
                matches = re.finditer(pattern_info['pattern'], line, re.IGNORECASE)
                for match in matches:
                    # Skip if it's clearly a comment or example
                    if any(indicator in line.lower() for indicator in ['//', '/*', '#', 'example', 'sample', 'todo']):
                        continue
                    
                    vulnerabilities.append(self.create_vulnerability(
                        title=f"Secret in Exposed Code: {pattern_info['type']}",
                        description=f"{pattern_info['description']} - Critical security risk",
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
    
    async def _check_framework_vulnerabilities(self, content: str, endpoint: str, url: str) -> List[Vulnerability]:
        """Check for framework-specific vulnerabilities in exposed code."""
        vulnerabilities = []
        
        # Framework-specific vulnerability patterns
        framework_patterns = {
            'nextjs': [
                {
                    'pattern': r'process\.env\.NEXT_PUBLIC_[A-Z_]+',
                    'description': 'Public environment variable usage in exposed code',
                    'severity': 'medium'
                }
            ],
            'react': [
                {
                    'pattern': r'dangerouslySetInnerHTML',
                    'description': 'Dangerous HTML injection in exposed React code',
                    'severity': 'high'
                }
            ],
            'express': [
                {
                    'pattern': r'app\.use\(express\.static\([^)]*\)',
                    'description': 'Static file serving configuration in exposed code',
                    'severity': 'low'
                }
            ]
        }
        
        for framework, patterns in framework_patterns.items():
            for pattern_info in patterns:
                import re
                if re.search(pattern_info['pattern'], content, re.IGNORECASE):
                    vulnerabilities.append(self.create_vulnerability(
                        title=f"Framework Vulnerability in Exposed Code: {framework}",
                        description=f"{pattern_info['description']} - Found in exposed {framework} code",
                        severity=pattern_info['severity'],
                        vuln_type="framework_vulnerability",
                        fix=f"Review and secure {framework} configuration",
                        metadata={
                            'url': url,
                            'endpoint': endpoint,
                            'framework': framework,
                            'pattern': pattern_info['pattern']
                        }
                    ))
        
        return vulnerabilities
    
    def _is_valid_source_code(self, content: str, endpoint: str) -> bool:
        """Enhanced validation for source code content."""
        if len(content) < 10:
            return False
        
        # Check for error page indicators
        error_indicators = ['404', 'not found', 'error', 'page not found', '<html>', '<!doctype']
        if any(indicator in content.lower() for indicator in error_indicators):
            return False
        
        # Language-specific validation
        if endpoint.endswith(('.js', '.jsx')):
            return any(keyword in content for keyword in ['function', 'const', 'let', 'var', 'import', 'export', 'require'])
        elif endpoint.endswith(('.ts', '.tsx')):
            return any(keyword in content for keyword in ['function', 'const', 'let', 'var', 'import', 'export', 'interface', 'type'])
        elif endpoint.endswith('.py'):
            return any(keyword in content for keyword in ['def ', 'import ', 'from ', 'class ', 'if __name__'])
        elif endpoint.endswith('.html'):
            return '<html' in content or '<!DOCTYPE' in content or '<head>' in content
        elif endpoint.endswith('.css'):
            return '{' in content and '}' in content and ('color:' in content or 'margin:' in content or 'padding:' in content)
        
        return False
    
    def _is_valid_config_file(self, content: str, endpoint: str) -> bool:
        """Enhanced validation for configuration files."""
        if len(content) < 10:
            return False
        
        # Check for error page indicators
        error_indicators = ['404', 'not found', 'error', 'page not found', '<html>', '<!doctype']
        if any(indicator in content.lower() for indicator in error_indicators):
            return False
        
        # File type specific validation
        if endpoint.endswith('.json'):
            try:
                import json
                data = json.loads(content)
                return isinstance(data, dict) and len(data) > 0
            except:
                return False
        elif endpoint.startswith('.env'):
            return '=' in content and '\n' in content
        elif endpoint.endswith('.txt'):
            return '==' in content or '>=' in content or '~=' in content
        elif endpoint.endswith('.toml'):
            return '[' in content and ']' in content
        elif endpoint.endswith(('.yaml', '.yml')):
            return ':' in content and ('version' in content or 'dependencies' in content)
        
        return False
    
    def _is_directory_listing(self, content: str) -> bool:
        """Check if content appears to be a directory listing."""
        listing_indicators = [
            'Index of', 'Directory listing', 'Parent Directory', '<a href="../">',
            'Last modified', 'Size</th>', 'Name</th>', 'Apache/', 'nginx/', 'Microsoft-IIS/'
        ]
        return any(indicator in content for indicator in listing_indicators)
    
    def _is_development_endpoint(self, content: str, endpoint: str) -> bool:
        """Check if endpoint appears to be a development/debug endpoint."""
        # Check for specific development indicators
        dev_indicators = [
            'phpinfo', 'debug', 'development', 'admin', 'manage',
            'git', 'svn', 'node_modules', 'vendor', 'bower_components'
        ]
        
        # Check endpoint name
        if any(dev in endpoint.lower() for dev in dev_indicators):
            return True
        
        # Check content for development indicators
        content_indicators = [
            'phpinfo', 'debug', 'development', 'admin', 'manage',
            'git', 'svn', 'node_modules', 'vendor', 'bower_components',
            'Index of', 'Directory listing'
        ]
        
        return any(indicator in content.lower() for indicator in content_indicators)
    
    def _is_valid_source_map(self, content: str) -> bool:
        """Check if content is a valid source map."""
        try:
            import json
            data = json.loads(content)
            return 'version' in data and 'sources' in data and 'mappings' in data
        except:
            return False
    
    def _is_build_artifact(self, content: str, filename: str) -> bool:
        """Check if content appears to be a build artifact."""
        if filename.endswith('.js'):
            return any(keyword in content for keyword in ['webpack', 'bundle', 'chunk', 'module.exports'])
        elif filename.endswith('.css'):
            return '{' in content and '}' in content and len(content) > 100
        elif filename.endswith('.json'):
            try:
                import json
                data = json.loads(content)
                return isinstance(data, dict) and ('name' in data or 'version' in data)
            except:
                return False
        
        return False
    
    def _mask_secret(self, text: str) -> str:
        """Mask sensitive data in text."""
        import re
        # Mask common secret patterns
        text = re.sub(r'sk-[a-zA-Z0-9]{48}', 'sk-***MASKED***', text)
        text = re.sub(r'sk-ant-[a-zA-Z0-9\-_]+', 'sk-ant-***MASKED***', text)
        text = re.sub(r'AKIA[A-Z0-9]{16}', 'AKIA***MASKED***', text)
        text = re.sub(r'ghp_[a-zA-Z0-9]+', 'ghp_***MASKED***', text)
        text = re.sub(r'["\'][a-zA-Z0-9]{32,}["\']', '"***MASKED***"', text)
        return text
