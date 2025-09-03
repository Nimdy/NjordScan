"""
Advanced Next.js Security Analyzer

Provides deep security analysis specifically for Next.js applications.
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import logging

from .base_framework_analyzer import BaseFrameworkAnalyzer, FrameworkVulnerability, FrameworkContext

logger = logging.getLogger(__name__)

class NextJSAnalyzer(BaseFrameworkAnalyzer):
    """Advanced security analyzer for Next.js applications."""
    
    def __init__(self):
        super().__init__("nextjs")
        
        # Next.js specific file patterns
        self.file_patterns = {
            'config': [r'next\.config\.(js|ts|mjs)$'],
            'pages': [r'pages/.*\.(js|jsx|ts|tsx)$', r'src/pages/.*\.(js|jsx|ts|tsx)$'],
            'app_router': [r'app/.*\.(js|jsx|ts|tsx)$', r'src/app/.*\.(js|jsx|ts|tsx)$'],
            'api': [r'pages/api/.*\.(js|ts)$', r'src/pages/api/.*\.(js|ts)$', r'app/api/.*\.(js|ts)$'],
            'middleware': [r'middleware\.(js|ts)$', r'src/middleware\.(js|ts)$'],
            'components': [r'components/.*\.(js|jsx|ts|tsx)$'],
            'build': [r'\.next/.*$']
        }
        
        # Next.js specific security patterns
        self.nextjs_patterns = {
            'ssr_xss': [
                r'getServerSideProps.*dangerouslySetInnerHTML',
                r'getStaticProps.*dangerouslySetInnerHTML',
                r'getServerSideProps.*innerHTML\s*=',
            ],
            'api_route_issues': [
                r'export\s+default\s+(?:async\s+)?function.*handler.*\{[^}]*req\.body[^}]*\}',
                r'res\.status\(\d+\)\.json\([^)]*req\.(query|body)',
                r'req\.(query|body)\.[a-zA-Z_$][a-zA-Z0-9_$]*(?!\s*[=!<>])',
            ],
            'middleware_issues': [
                r'NextRequest.*url.*redirect',
                r'NextResponse\.redirect\([^)]*req\.',
                r'request\.nextUrl\.pathname',
            ],
            'image_ssrf': [
                r'<Image[^>]+src\s*=\s*\{[^}]*req\.(query|body)',
                r'next/image.*src.*\$\{[^}]*\}',
            ],
            'hydration_issues': [
                r'useEffect\(\s*\(\)\s*=>\s*\{[^}]*innerHTML',
                r'useLayoutEffect.*dangerouslySetInnerHTML',
            ],
            'build_config_issues': [
                r'experimental\s*:\s*\{[^}]*serverActions\s*:\s*true',
                r'images\s*:\s*\{[^}]*domains\s*:\s*\[.*\*.*\]',
            ]
        }
        
        # Next.js specific security features to check
        self.nextjs_security_features = {
            'csp_headers': ['Content-Security-Policy', 'contentSecurityPolicy'],
            'security_headers': ['X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security'],
            'csrf_protection': ['csrf', 'xsrf', 'next-csrf'],
            'rate_limiting': ['rate-limit', 'rateLimit', 'slowDown'],
            'input_validation': ['joi', 'yup', 'zod', 'express-validator'],
            'authentication': ['next-auth', 'auth0', 'passport', 'clerk']
        }
    
    def analyze_project(self, project_path: Path) -> List[FrameworkVulnerability]:
        """Analyze Next.js project for security vulnerabilities."""
        
        vulnerabilities = []
        context = self.create_framework_context(project_path)
        
        # Analyze Next.js configuration
        vulnerabilities.extend(self._analyze_nextjs_config(context))
        
        # Analyze pages and app router
        vulnerabilities.extend(self._analyze_pages_directory(project_path, context))
        vulnerabilities.extend(self._analyze_app_directory(project_path, context))
        
        # Analyze API routes
        vulnerabilities.extend(self._analyze_api_routes(project_path, context))
        
        # Analyze middleware
        vulnerabilities.extend(self._analyze_middleware(project_path, context))
        
        # Analyze package.json for Next.js specific issues
        vulnerabilities.extend(self._analyze_package_json_nextjs(context))
        
        # Check for Next.js security best practices
        vulnerabilities.extend(self._check_nextjs_security_practices(project_path, context))
        
        return vulnerabilities
    
    def detect_framework_features(self, context: FrameworkContext) -> Set[str]:
        """Detect Next.js specific features."""
        features = set()
        
        if context.package_json:
            dependencies = {**context.dependencies, **context.dev_dependencies}
            
            # Check for Next.js version and features
            if 'next' in dependencies:
                features.add('nextjs')
                
                # Version-specific features
                next_version = dependencies['next']
                if '13' in next_version or '14' in next_version:
                    features.add('app_router_available')
                
            # Check for Next.js plugins and extensions
            nextjs_plugins = [
                'next-pwa', 'next-seo', 'next-auth', 'next-i18next',
                '@next/bundle-analyzer', 'next-compose-plugins'
            ]
            
            for plugin in nextjs_plugins:
                if plugin in dependencies:
                    features.add(plugin.replace('-', '_').replace('@next/', 'next_'))
        
        # Check for directory structure
        if context.project_root:
            if (context.project_root / 'pages').exists():
                features.add('pages_router')
            
            if (context.project_root / 'app').exists():
                features.add('app_router')
            
            if (context.project_root / 'middleware.js').exists() or \
               (context.project_root / 'middleware.ts').exists():
                features.add('middleware')
            
            if (context.project_root / 'public').exists():
                features.add('static_assets')
        
        return features
    
    def _analyze_framework_specific(self, file_path: Path, content: str, 
                                  context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze Next.js specific security patterns."""
        
        vulnerabilities = []
        
        # Determine file type for context-aware analysis
        file_type = self._determine_file_type(file_path, context)
        
        # Analyze based on file type
        if file_type == 'api_route':
            vulnerabilities.extend(self._analyze_api_route_file(file_path, content, context))
        elif file_type == 'page':
            vulnerabilities.extend(self._analyze_page_file(file_path, content, context))
        elif file_type == 'middleware':
            vulnerabilities.extend(self._analyze_middleware_file(file_path, content, context))
        elif file_type == 'component':
            vulnerabilities.extend(self._analyze_component_file(file_path, content, context))
        
        # General Next.js pattern analysis
        vulnerabilities.extend(self._analyze_nextjs_patterns(file_path, content, context))
        
        return vulnerabilities
    
    def _determine_file_type(self, file_path: Path, context: FrameworkContext) -> str:
        """Determine the type of Next.js file."""
        
        path_str = str(file_path).lower()
        
        if '/api/' in path_str and file_path.suffix in ['.js', '.ts']:
            return 'api_route'
        elif '/pages/' in path_str and file_path.suffix in ['.js', '.jsx', '.ts', '.tsx']:
            return 'page'
        elif '/app/' in path_str and file_path.suffix in ['.js', '.jsx', '.ts', '.tsx']:
            return 'app_route_page'
        elif 'middleware' in file_path.name:
            return 'middleware'
        elif '/components/' in path_str:
            return 'component'
        elif 'next.config' in file_path.name:
            return 'config'
        else:
            return 'unknown'
    
    def _analyze_api_route_file(self, file_path: Path, content: str, 
                               context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze Next.js API route for security issues."""
        
        vulnerabilities = []
        
        # Check for missing input validation
        if self._has_user_input(content) and not self._has_input_validation(content):
            vulnerabilities.append(FrameworkVulnerability(
                id=f"api_no_validation_{hash(str(file_path))}",
                title="Missing Input Validation in API Route",
                description="API route processes user input without validation",
                severity="high",
                confidence="medium",
                framework="nextjs",
                category="api",
                file_path=str(file_path),
                component_type="api_route",
                affects_server_side=True,
                requires_user_input=True,
                fix_suggestion="Implement input validation using libraries like Joi, Yup, or Zod"
            ))
        
        # Check for missing CORS configuration
        if not self._has_cors_config(content) and self._is_public_api(file_path):
            vulnerabilities.append(FrameworkVulnerability(
                id=f"api_no_cors_{hash(str(file_path))}",
                title="Missing CORS Configuration",
                description="Public API route lacks CORS configuration",
                severity="medium",
                confidence="low",
                framework="nextjs",
                category="api",
                file_path=str(file_path),
                component_type="api_route",
                affects_server_side=True,
                fix_suggestion="Configure CORS headers appropriately for your use case"
            ))
        
        # Check for missing rate limiting
        if not self._has_rate_limiting(content) and self._is_public_api(file_path):
            vulnerabilities.append(FrameworkVulnerability(
                id=f"api_no_rate_limit_{hash(str(file_path))}",
                title="Missing Rate Limiting",
                description="API route lacks rate limiting protection",
                severity="medium",
                confidence="medium",
                framework="nextjs",
                category="api",
                file_path=str(file_path),
                component_type="api_route",
                affects_server_side=True,
                fix_suggestion="Implement rate limiting middleware"
            ))
        
        # Check for SQL injection in database queries
        sql_patterns = [
            r'(query|execute|exec)\s*\(\s*[\'"`][^\'"`]*\$\{[^}]+\}[^\'"`]*[\'"`]',
            r'(SELECT|INSERT|UPDATE|DELETE)[^;]*\$\{[^}]+\}',
        ]
        
        for pattern in sql_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"api_sql_injection_{hash(str(match.group()))}",
                    title="Potential SQL Injection in API Route",
                    description="API route constructs SQL query with user input",
                    severity="critical",
                    confidence="high",
                    framework="nextjs",
                    category="api",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    component_type="api_route",
                    affects_server_side=True,
                    requires_user_input=True,
                    attack_vector="sql_injection",
                    fix_suggestion="Use parameterized queries or ORM methods"
                ))
        
        # Check for command injection
        cmd_patterns = [
            r'child_process\.(exec|spawn)\s*\([^)]*req\.(body|query)',
            r'(exec|spawn)Sync\s*\([^)]*req\.(body|query)',
        ]
        
        for pattern in cmd_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"api_cmd_injection_{hash(str(match.group()))}",
                    title="Potential Command Injection in API Route",
                    description="API route executes system commands with user input",
                    severity="critical",
                    confidence="high",
                    framework="nextjs",
                    category="api",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    component_type="api_route",
                    affects_server_side=True,
                    requires_user_input=True,
                    attack_vector="command_injection",
                    fix_suggestion="Avoid executing system commands with user input"
                ))
        
        return vulnerabilities
    
    def _analyze_page_file(self, file_path: Path, content: str, 
                          context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze Next.js page file for security issues."""
        
        vulnerabilities = []
        
        # Check for XSS in getServerSideProps
        gsp_xss_patterns = [
            r'getServerSideProps[^}]*dangerouslySetInnerHTML[^}]*\$\{[^}]*\}',
            r'getServerSideProps[^}]*innerHTML\s*=[^}]*\$\{[^}]*\}',
        ]
        
        for pattern in gsp_xss_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"page_ssr_xss_{hash(str(match.group()))}",
                    title="Potential XSS in Server-Side Rendering",
                    description="Server-side rendered content may contain unescaped user input",
                    severity="high",
                    confidence="medium",
                    framework="nextjs",
                    category="ssr",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=self._extract_code_snippet(content, match),
                    component_type="page",
                    affects_server_side=True,
                    affects_client_side=True,
                    requires_user_input=True,
                    attack_vector="xss",
                    fix_suggestion="Sanitize user input before rendering or use safe rendering methods"
                ))
        
        # Check for SSRF in getServerSideProps
        ssrf_patterns = [
            r'getServerSideProps[^}]*fetch\s*\([^)]*req\.(query|body)',
            r'getServerSideProps[^}]*axios\.[a-z]+\([^)]*req\.(query|body)',
        ]
        
        for pattern in ssrf_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"page_ssrf_{hash(str(match.group()))}",
                    title="Potential SSRF in Server-Side Props",
                    description="Server-side code makes external requests with user input",
                    severity="high",
                    confidence="medium",
                    framework="nextjs",
                    category="ssr",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=self._extract_code_snippet(content, match),
                    component_type="page",
                    affects_server_side=True,
                    requires_user_input=True,
                    attack_vector="ssrf",
                    fix_suggestion="Validate and whitelist URLs before making external requests"
                ))
        
        # Check for hydration XSS
        hydration_patterns = [
            r'useEffect\s*\([^}]*innerHTML\s*=[^}]*\$\{[^}]*\}',
            r'useLayoutEffect\s*\([^}]*dangerouslySetInnerHTML',
        ]
        
        for pattern in hydration_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"page_hydration_xss_{hash(str(match.group()))}",
                    title="Potential XSS in Client-Side Hydration",
                    description="Client-side code manipulates DOM with potentially unsafe content",
                    severity="medium",
                    confidence="medium",
                    framework="nextjs",
                    category="hydration",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=self._extract_code_snippet(content, match),
                    component_type="page",
                    affects_client_side=True,
                    attack_vector="xss",
                    fix_suggestion="Use safe DOM manipulation methods and sanitize content"
                ))
        
        return vulnerabilities
    
    def _analyze_middleware_file(self, file_path: Path, content: str, 
                               context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze Next.js middleware for security issues."""
        
        vulnerabilities = []
        
        # Check for open redirect in middleware
        redirect_patterns = [
            r'NextResponse\.redirect\s*\([^)]*req\.(nextUrl|url)',
            r'redirect\s*\([^)]*request\.nextUrl\.searchParams',
        ]
        
        for pattern in redirect_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"middleware_open_redirect_{hash(str(match.group()))}",
                    title="Potential Open Redirect in Middleware",
                    description="Middleware redirects based on user-controlled input",
                    severity="medium",
                    confidence="medium",
                    framework="nextjs",
                    category="middleware",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    component_type="middleware",
                    affects_server_side=True,
                    requires_user_input=True,
                    attack_vector="open_redirect",
                    fix_suggestion="Validate redirect URLs against a whitelist"
                ))
        
        # Check for overly broad matcher
        matcher_patterns = [
            r'matcher\s*:\s*[\'"`]/\(\?\!api\|_next\/static\|favicon\.ico\)\.\*[\'"`]',
            r'matcher\s*:\s*[\'"`]/\.\*[\'"`]',
        ]
        
        for pattern in matcher_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"middleware_broad_matcher_{hash(str(match.group()))}",
                    title="Overly Broad Middleware Matcher",
                    description="Middleware matcher pattern may impact performance",
                    severity="low",
                    confidence="high",
                    framework="nextjs",
                    category="middleware",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    component_type="middleware",
                    fix_suggestion="Use more specific matcher patterns"
                ))
        
        return vulnerabilities
    
    def _analyze_component_file(self, file_path: Path, content: str, 
                               context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze Next.js component file for security issues."""
        
        vulnerabilities = []
        
        # Check for Next.js Image component SSRF
        image_ssrf_patterns = [
            r'<Image[^>]+src\s*=\s*\{[^}]*\$\{[^}]*\}[^}]*\}',
            r'next/image.*src.*req\.(query|body)',
        ]
        
        for pattern in image_ssrf_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"component_image_ssrf_{hash(str(match.group()))}",
                    title="Potential SSRF via Next.js Image Component",
                    description="Image component uses user-controlled URL",
                    severity="medium",
                    confidence="medium",
                    framework="nextjs",
                    category="component",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    component_type="component",
                    affects_server_side=True,
                    requires_user_input=True,
                    attack_vector="ssrf",
                    fix_suggestion="Validate image URLs and configure allowed domains in next.config.js"
                ))
        
        return vulnerabilities
    
    def _analyze_nextjs_patterns(self, file_path: Path, content: str, 
                                context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze general Next.js security patterns."""
        
        vulnerabilities = []
        
        # Check all Next.js specific patterns
        for category, patterns in self.nextjs_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    line_number = content[:match.start()].count('\n') + 1
                    
                    vulnerability = self._create_pattern_vulnerability(
                        category, pattern, match, file_path, line_number, content
                    )
                    
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _create_pattern_vulnerability(self, category: str, pattern: str, match, 
                                    file_path: Path, line_number: int, content: str) -> Optional[FrameworkVulnerability]:
        """Create vulnerability from pattern match."""
        
        pattern_configs = {
            'ssr_xss': {
                'title': 'XSS in Server-Side Rendering',
                'description': 'Potential XSS vulnerability in server-side rendering',
                'severity': 'high',
                'category': 'ssr'
            },
            'api_route_issues': {
                'title': 'API Route Security Issue',
                'description': 'Potential security issue in API route',
                'severity': 'medium',
                'category': 'api'
            },
            'middleware_issues': {
                'title': 'Middleware Security Issue',
                'description': 'Potential security issue in middleware',
                'severity': 'medium',
                'category': 'middleware'
            },
            'image_ssrf': {
                'title': 'Image Component SSRF',
                'description': 'Potential SSRF via Image component',
                'severity': 'medium',
                'category': 'component'
            },
            'hydration_issues': {
                'title': 'Hydration Security Issue',
                'description': 'Potential security issue in client-side hydration',
                'severity': 'medium',
                'category': 'hydration'
            },
            'build_config_issues': {
                'title': 'Build Configuration Issue',
                'description': 'Potentially insecure build configuration',
                'severity': 'low',
                'category': 'configuration'
            }
        }
        
        config = pattern_configs.get(category)
        if not config:
            return None
        
        return FrameworkVulnerability(
            id=f"nextjs_{category}_{hash(str(match.group()))}",
            title=config['title'],
            description=config['description'],
            severity=config['severity'],
            confidence="medium",
            framework="nextjs",
            category=config['category'],
            file_path=str(file_path),
            line_number=line_number,
            code_snippet=self._extract_code_snippet(content, match),
            fix_suggestion=self._get_fix_suggestion(category)
        )
    
    def _get_fix_suggestion(self, category: str) -> str:
        """Get fix suggestion for vulnerability category."""
        
        suggestions = {
            'ssr_xss': 'Sanitize user input before rendering and use safe rendering methods',
            'api_route_issues': 'Implement proper input validation and error handling',
            'middleware_issues': 'Validate user input and use secure redirect practices',
            'image_ssrf': 'Configure allowed image domains and validate URLs',
            'hydration_issues': 'Use safe DOM manipulation and sanitize content',
            'build_config_issues': 'Review and secure build configuration'
        }
        
        return suggestions.get(category, 'Review and address the security issue')
    
    def _analyze_nextjs_config(self, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze Next.js configuration for security issues."""
        
        vulnerabilities = []
        
        # Find Next.js config file
        config_files = [
            context.project_root / 'next.config.js',
            context.project_root / 'next.config.ts',
            context.project_root / 'next.config.mjs'
        ]
        
        for config_file in config_files:
            if config_file.exists():
                try:
                    content = config_file.read_text(encoding='utf-8')
                    vulnerabilities.extend(self._analyze_nextjs_config_content(config_file, content))
                except Exception as e:
                    logger.error(f"Error reading Next.js config {config_file}: {e}")
        
        return vulnerabilities
    
    def _analyze_nextjs_config_content(self, config_file: Path, content: str) -> List[FrameworkVulnerability]:
        """Analyze Next.js configuration content."""
        
        vulnerabilities = []
        
        # Check for insecure image domains
        if re.search(r'images\s*:\s*\{[^}]*domains\s*:\s*\[.*\*.*\]', content, re.IGNORECASE | re.DOTALL):
            vulnerabilities.append(FrameworkVulnerability(
                id="nextjs_config_wildcard_images",
                title="Wildcard Image Domains",
                description="Next.js configuration allows images from any domain",
                severity="medium",
                confidence="high",
                framework="nextjs",
                category="configuration",
                file_path=str(config_file),
                fix_suggestion="Specify explicit allowed image domains instead of wildcards"
            ))
        
        # Check for experimental features in production
        experimental_patterns = [
            r'experimental\s*:\s*\{[^}]*serverActions\s*:\s*true',
            r'experimental\s*:\s*\{[^}]*appDir\s*:\s*true',
        ]
        
        for pattern in experimental_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"nextjs_config_experimental_{hash(pattern)}",
                    title="Experimental Features Enabled",
                    description="Experimental Next.js features should not be used in production",
                    severity="low",
                    confidence="medium",
                    framework="nextjs",
                    category="configuration",
                    file_path=str(config_file),
                    fix_suggestion="Disable experimental features in production builds"
                ))
        
        # Check for missing security headers
        if not re.search(r'headers\s*:\s*async\s*\(\)', content, re.IGNORECASE):
            vulnerabilities.append(FrameworkVulnerability(
                id="nextjs_config_no_security_headers",
                title="Missing Security Headers Configuration",
                description="Next.js configuration lacks security headers setup",
                severity="medium",
                confidence="low",
                framework="nextjs",
                category="configuration",
                file_path=str(config_file),
                fix_suggestion="Configure security headers in Next.js config"
            ))
        
        return vulnerabilities
    
    def _analyze_pages_directory(self, project_path: Path, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze pages directory structure."""
        
        vulnerabilities = []
        pages_dirs = [project_path / 'pages', project_path / 'src' / 'pages']
        
        for pages_dir in pages_dirs:
            if pages_dir.exists():
                for file_path in pages_dir.rglob('*'):
                    if file_path.is_file() and file_path.suffix in ['.js', '.jsx', '.ts', '.tsx']:
                        try:
                            content = file_path.read_text(encoding='utf-8')
                            vulnerabilities.extend(self.analyze_file(file_path, content, context))
                        except Exception as e:
                            logger.error(f"Error analyzing page file {file_path}: {e}")
        
        return vulnerabilities
    
    def _analyze_app_directory(self, project_path: Path, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze app directory structure (App Router)."""
        
        vulnerabilities = []
        app_dirs = [project_path / 'app', project_path / 'src' / 'app']
        
        for app_dir in app_dirs:
            if app_dir.exists():
                for file_path in app_dir.rglob('*'):
                    if file_path.is_file() and file_path.suffix in ['.js', '.jsx', '.ts', '.tsx']:
                        try:
                            content = file_path.read_text(encoding='utf-8')
                            vulnerabilities.extend(self.analyze_file(file_path, content, context))
                        except Exception as e:
                            logger.error(f"Error analyzing app file {file_path}: {e}")
        
        return vulnerabilities
    
    def _analyze_api_routes(self, project_path: Path, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze API routes specifically."""
        
        vulnerabilities = []
        api_dirs = [
            project_path / 'pages' / 'api',
            project_path / 'src' / 'pages' / 'api',
            project_path / 'app' / 'api',
            project_path / 'src' / 'app' / 'api'
        ]
        
        for api_dir in api_dirs:
            if api_dir.exists():
                for file_path in api_dir.rglob('*'):
                    if file_path.is_file() and file_path.suffix in ['.js', '.ts']:
                        try:
                            content = file_path.read_text(encoding='utf-8')
                            vulnerabilities.extend(self._analyze_api_route_file(file_path, content, context))
                        except Exception as e:
                            logger.error(f"Error analyzing API route {file_path}: {e}")
        
        return vulnerabilities
    
    def _analyze_middleware(self, project_path: Path, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze middleware files."""
        
        vulnerabilities = []
        middleware_files = [
            project_path / 'middleware.js',
            project_path / 'middleware.ts',
            project_path / 'src' / 'middleware.js',
            project_path / 'src' / 'middleware.ts'
        ]
        
        for middleware_file in middleware_files:
            if middleware_file.exists():
                try:
                    content = middleware_file.read_text(encoding='utf-8')
                    vulnerabilities.extend(self._analyze_middleware_file(middleware_file, content, context))
                except Exception as e:
                    logger.error(f"Error analyzing middleware {middleware_file}: {e}")
        
        return vulnerabilities
    
    def _analyze_package_json_nextjs(self, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze package.json for Next.js specific issues."""
        
        vulnerabilities = []
        
        if not context.package_json:
            return vulnerabilities
        
        # Check for outdated Next.js version
        dependencies = {**context.dependencies, **context.dev_dependencies}
        
        if 'next' in dependencies:
            next_version = dependencies['next']
            
            # Check for known vulnerable versions (simplified check)
            if any(old_version in next_version for old_version in ['12.0', '12.1', '13.0']):
                vulnerabilities.append(FrameworkVulnerability(
                    id="nextjs_outdated_version",
                    title="Outdated Next.js Version",
                    description=f"Using potentially vulnerable Next.js version: {next_version}",
                    severity="medium",
                    confidence="high",
                    framework="nextjs",
                    category="dependencies",
                    file_path="package.json",
                    fix_suggestion="Update Next.js to the latest stable version"
                ))
        
        # Check for missing security-related dependencies
        security_deps = ['helmet', 'cors', 'express-rate-limit', 'next-csrf']
        missing_security = [dep for dep in security_deps if dep not in dependencies]
        
        if len(missing_security) > 2:  # If missing more than 2 security deps
            vulnerabilities.append(FrameworkVulnerability(
                id="nextjs_missing_security_deps",
                title="Missing Security Dependencies",
                description=f"Consider adding security-related dependencies: {', '.join(missing_security)}",
                severity="low",
                confidence="low",
                framework="nextjs",
                category="dependencies",
                file_path="package.json",
                fix_suggestion="Add relevant security middleware and libraries"
            ))
        
        return vulnerabilities
    
    def _check_nextjs_security_practices(self, project_path: Path, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Check for Next.js security best practices."""
        
        vulnerabilities = []
        
        # Check for environment variables file
        env_files = [
            project_path / '.env.local',
            project_path / '.env',
            project_path / '.env.production'
        ]
        
        has_env_file = any(env_file.exists() for env_file in env_files)
        
        if not has_env_file:
            vulnerabilities.append(FrameworkVulnerability(
                id="nextjs_no_env_file",
                title="Missing Environment Variables File",
                description="No environment variables file found for configuration",
                severity="low",
                confidence="medium",
                framework="nextjs",
                category="configuration",
                file_path=str(project_path),
                fix_suggestion="Create .env.local file for environment-specific configuration"
            ))
        
        # Check for TypeScript usage (security through type safety)
        has_typescript = any(
            (project_path / ts_file).exists() 
            for ts_file in ['tsconfig.json', 'next-env.d.ts']
        )
        
        if not has_typescript:
            vulnerabilities.append(FrameworkVulnerability(
                id="nextjs_no_typescript",
                title="TypeScript Not Configured",
                description="TypeScript provides additional type safety and security",
                severity="info",
                confidence="low",
                framework="nextjs",
                category="configuration",
                file_path=str(project_path),
                fix_suggestion="Consider migrating to TypeScript for better type safety"
            ))
        
        return vulnerabilities
    
    # Helper methods
    def _has_user_input(self, content: str) -> bool:
        """Check if content processes user input."""
        input_patterns = [
            r'req\.(body|query|params)',
            r'request\.(body|query|params)',
            r'searchParams\.',
            r'formData\.'
        ]
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in input_patterns)
    
    def _has_input_validation(self, content: str) -> bool:
        """Check if content has input validation."""
        validation_patterns = [
            r'(joi|yup|zod)\.',
            r'validate\s*\(',
            r'schema\.',
            r'express-validator'
        ]
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in validation_patterns)
    
    def _has_cors_config(self, content: str) -> bool:
        """Check if content has CORS configuration."""
        cors_patterns = [
            r'cors\s*\(',
            r'Access-Control-Allow-Origin',
            r'res\.setHeader.*cors',
            r'next-cors'
        ]
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in cors_patterns)
    
    def _has_rate_limiting(self, content: str) -> bool:
        """Check if content has rate limiting."""
        rate_limit_patterns = [
            r'rate-?limit',
            r'slowDown',
            r'express-rate-limit',
            r'rateLimit\s*\('
        ]
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in rate_limit_patterns)
    
    def _is_public_api(self, file_path: Path) -> bool:
        """Check if API route is likely public."""
        # Simplified heuristic - in practice, this would be more sophisticated
        path_str = str(file_path).lower()
        return not any(private_indicator in path_str 
                      for private_indicator in ['admin', 'internal', 'private'])
    
    def _extract_code_snippet(self, content: str, match, context_lines: int = 2) -> str:
        """Extract code snippet with context."""
        lines = content.split('\n')
        start_line = content[:match.start()].count('\n')
        
        snippet_start = max(0, start_line - context_lines)
        snippet_end = min(len(lines), start_line + context_lines + 1)
        
        return '\n'.join(lines[snippet_start:snippet_end])
