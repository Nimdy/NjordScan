"""
Advanced React Security Analyzer

Provides deep security analysis specifically for React applications.
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import logging

from .base_framework_analyzer import BaseFrameworkAnalyzer, FrameworkVulnerability, FrameworkContext

logger = logging.getLogger(__name__)

class ReactAnalyzer(BaseFrameworkAnalyzer):
    """Advanced security analyzer for React applications."""
    
    def __init__(self):
        super().__init__("react")
        
        # React specific file patterns
        self.file_patterns = {
            'config': [r'webpack\.config\.(js|ts)$', r'craco\.config\.(js|ts)$'],
            'components': [r'src/components/.*\.(js|jsx|ts|tsx)$'],
            'pages': [r'src/pages/.*\.(js|jsx|ts|tsx)$'],
            'hooks': [r'src/hooks/.*\.(js|jsx|ts|tsx)$'],
            'context': [r'src/context/.*\.(js|jsx|ts|tsx)$'],
            'utils': [r'src/utils/.*\.(js|jsx|ts|tsx)$'],
            'services': [r'src/services/.*\.(js|jsx|ts|tsx)$']
        }
        
        # React specific security patterns
        self.react_patterns = {
            'dangerous_html': [
                r'dangerouslySetInnerHTML\s*=\s*\{\s*__html\s*:\s*([^}]+)\}',
                r'dangerouslySetInnerHTML.*\$\{[^}]*\}',
                r'dangerouslySetInnerHTML.*props\.[a-zA-Z_$]',
                r'dangerouslySetInnerHTML.*state\.[a-zA-Z_$]'
            ],
            'ref_dom_manipulation': [
                r'useRef\(\)\.current\.(innerHTML|outerHTML)',
                r'ref\.current\.(innerHTML|outerHTML)\s*=',
                r'createRef\(\)\.current\.(innerHTML|outerHTML)',
                r'\w+Ref\.current\.innerHTML'
            ],
            'unsafe_lifecycle': [
                r'componentWillMount\s*\(',
                r'componentWillReceiveProps\s*\(',
                r'componentWillUpdate\s*\(',
                r'UNSAFE_componentWillMount',
                r'UNSAFE_componentWillReceiveProps',
                r'UNSAFE_componentWillUpdate'
            ],
            'state_mutation': [
                r'this\.state\.[a-zA-Z_$][a-zA-Z0-9_$]*\s*=',
                r'state\.[a-zA-Z_$][a-zA-Z0-9_$]*\s*=(?!\s*=)',
                r'this\.state\[[\'"][^\'"]+[\'"]\]\s*='
            ],
            'external_script_injection': [
                r'<script[^>]+src\s*=\s*\{[^}]*\$\{[^}]*\}[^}]*\}',
                r'createElement\s*\(\s*[\'"]script[\'"].*src.*\$\{',
                r'document\.createElement\s*\(\s*[\'"]script[\'"].*src'
            ],
            'insecure_random_keys': [
                r'key\s*=\s*\{Math\.random\(\)',
                r'key\s*=\s*\{Date\.now\(\)',
                r'key\s*=\s*\{new Date\(\)\.getTime\(\)'
            ],
            'prop_injection': [
                r'\.\.\.[a-zA-Z_$][a-zA-Z0-9_$]*Props',
                r'spread.*props.*dangerouslySetInnerHTML',
                r'\{\.\.\.props\}.*<[a-zA-Z]+'
            ],
            'context_injection': [
                r'createContext\s*\([^)]*\$\{[^}]*\}',
                r'Provider.*value\s*=\s*\{[^}]*\$\{[^}]*user',
                r'useContext.*\$\{[^}]*\}'
            ],
            'event_handler_injection': [
                r'onClick\s*=\s*\{[^}]*eval\s*\(',
                r'onLoad\s*=\s*\{[^}]*\$\{[^}]*\}',
                r'on[A-Z][a-zA-Z]*\s*=\s*\{[^}]*Function\s*\('
            ]
        }
        
        # React security best practices
        self.react_security_features = {
            'csp_integration': ['react-helmet', 'react-helmet-async'],
            'sanitization': ['dompurify', 'sanitize-html', 'xss'],
            'validation': ['prop-types', 'joi', 'yup', 'zod'],
            'security_headers': ['helmet', 'express-helmet'],
            'authentication': ['react-router-dom', 'auth0-react', '@auth0/nextjs-auth0'],
            'state_management': ['redux', 'zustand', 'recoil', 'context-api']
        }
        
        # React hooks security patterns
        self.hooks_patterns = {
            'unsafe_effect_dependencies': [
                r'useEffect\s*\([^,]*,\s*\[\].*fetch',
                r'useEffect\s*\([^,]*,\s*\[\].*axios',
                r'useLayoutEffect.*innerHTML'
            ],
            'memory_leaks': [
                r'useEffect\s*\([^}]*setInterval[^}]*\}(?!\s*,\s*\[[^\]]*\])',
                r'useEffect\s*\([^}]*setTimeout[^}]*\}(?!\s*,\s*\[[^\]]*\])',
                r'useEffect\s*\([^}]*addEventListener[^}]*\}.*(?!removeEventListener)'
            ],
            'state_race_conditions': [
                r'useState.*async.*setState',
                r'useEffect.*setState.*async',
                r'useCallback.*setState.*Promise'
            ]
        }
    
    def analyze_project(self, project_path: Path) -> List[FrameworkVulnerability]:
        """Analyze React project for security vulnerabilities."""
        
        vulnerabilities = []
        context = self.create_framework_context(project_path)
        
        # Analyze React configuration
        vulnerabilities.extend(self._analyze_react_config(context))
        
        # Analyze source directory
        src_dir = project_path / 'src'
        if src_dir.exists():
            vulnerabilities.extend(self._analyze_src_directory(src_dir, context))
        
        # Analyze public directory for security issues
        public_dir = project_path / 'public'
        if public_dir.exists():
            vulnerabilities.extend(self._analyze_public_directory(public_dir, context))
        
        # Analyze package.json for React specific issues
        vulnerabilities.extend(self._analyze_package_json_react(context))
        
        # Check React security best practices
        vulnerabilities.extend(self._check_react_security_practices(project_path, context))
        
        # Analyze build configuration
        vulnerabilities.extend(self._analyze_build_config(project_path, context))
        
        return vulnerabilities
    
    def detect_framework_features(self, context: FrameworkContext) -> Set[str]:
        """Detect React specific features."""
        features = set()
        
        if context.package_json:
            dependencies = {**context.dependencies, **context.dev_dependencies}
            
            # Check for React and related libraries
            if 'react' in dependencies:
                features.add('react')
                
                # Version-specific features
                react_version = dependencies['react']
                if any(v in react_version for v in ['18', '17', '16']):
                    features.add(f'react_{react_version.split(".")[0]}')
            
            # Check for React ecosystem libraries
            react_libs = {
                'react-dom': 'react_dom',
                'react-router-dom': 'react_router',
                'react-redux': 'redux_integration',
                'react-helmet': 'helmet_integration',
                'react-query': 'react_query',
                '@tanstack/react-query': 'tanstack_query',
                'swr': 'swr',
                'recoil': 'recoil',
                'zustand': 'zustand',
                'mobx-react': 'mobx',
                'styled-components': 'styled_components',
                'emotion': 'emotion',
                '@mui/material': 'material_ui',
                'antd': 'ant_design'
            }
            
            for lib, feature in react_libs.items():
                if lib in dependencies:
                    features.add(feature)
            
            # Check for testing libraries
            test_libs = ['@testing-library/react', 'enzyme', 'react-test-renderer']
            if any(lib in dependencies for lib in test_libs):
                features.add('testing_configured')
        
        # Check for directory structure
        if context.project_root:
            src_dir = context.project_root / 'src'
            if src_dir.exists():
                # Check for common React patterns
                if (src_dir / 'components').exists():
                    features.add('component_structure')
                
                if (src_dir / 'hooks').exists():
                    features.add('custom_hooks')
                
                if (src_dir / 'context').exists():
                    features.add('context_api')
                
                if (src_dir / 'pages').exists():
                    features.add('page_based_routing')
        
        return features
    
    def _analyze_framework_specific(self, file_path: Path, content: str, 
                                  context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze React specific security patterns."""
        
        vulnerabilities = []
        
        # Determine file type for context-aware analysis
        file_type = self._determine_react_file_type(file_path, content)
        
        # Analyze based on file type
        if file_type == 'component':
            vulnerabilities.extend(self._analyze_react_component(file_path, content, context))
        elif file_type == 'hook':
            vulnerabilities.extend(self._analyze_react_hook(file_path, content, context))
        elif file_type == 'context':
            vulnerabilities.extend(self._analyze_react_context(file_path, content, context))
        elif file_type == 'service':
            vulnerabilities.extend(self._analyze_react_service(file_path, content, context))
        
        # General React pattern analysis
        vulnerabilities.extend(self._analyze_react_patterns(file_path, content, context))
        
        # React hooks specific analysis
        vulnerabilities.extend(self._analyze_react_hooks_patterns(file_path, content, context))
        
        return vulnerabilities
    
    def _determine_react_file_type(self, file_path: Path, content: str) -> str:
        """Determine the type of React file."""
        
        path_str = str(file_path).lower()
        
        # Check by directory structure
        if '/components/' in path_str:
            return 'component'
        elif '/hooks/' in path_str:
            return 'hook'
        elif '/context/' in path_str:
            return 'context'
        elif '/services/' in path_str or '/api/' in path_str:
            return 'service'
        elif '/pages/' in path_str:
            return 'page'
        elif '/utils/' in path_str:
            return 'utility'
        
        # Check by content patterns
        if re.search(r'export.*function.*use[A-Z]', content):
            return 'hook'
        elif re.search(r'createContext\s*\(', content):
            return 'context'
        elif re.search(r'return\s*\(\s*<', content) or re.search(r'return\s*<', content):
            return 'component'
        elif re.search(r'fetch\s*\(|axios\.|api\.', content):
            return 'service'
        
        return 'unknown'
    
    def _analyze_react_component(self, file_path: Path, content: str, 
                                context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze React component for security issues."""
        
        vulnerabilities = []
        
        # Check for dangerous HTML usage
        dangerous_html_patterns = self.react_patterns['dangerous_html']
        for pattern in dangerous_html_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                # Check if the content is user-controlled
                is_user_controlled = self._is_user_controlled_content(match.group(), content)
                severity = "critical" if is_user_controlled else "high"
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"react_dangerous_html_{hash(str(match.group()))}",
                    title="Dangerous HTML Injection Risk",
                    description="Use of dangerouslySetInnerHTML with potentially unsafe content",
                    severity=severity,
                    confidence="high" if is_user_controlled else "medium",
                    framework="react",
                    category="xss",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    component_type="component",
                    affects_client_side=True,
                    requires_user_input=is_user_controlled,
                    attack_vector="xss",
                    fix_suggestion="Sanitize HTML content using DOMPurify or avoid dangerouslySetInnerHTML"
                ))
        
        # Check for unsafe ref DOM manipulation
        ref_patterns = self.react_patterns['ref_dom_manipulation']
        for pattern in ref_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"react_ref_dom_{hash(str(match.group()))}",
                    title="Unsafe DOM Manipulation via Ref",
                    description="Direct DOM manipulation through refs can lead to XSS",
                    severity="medium",
                    confidence="medium",
                    framework="react",
                    category="xss",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    component_type="component",
                    affects_client_side=True,
                    attack_vector="xss",
                    fix_suggestion="Use React's built-in DOM methods or sanitize content"
                ))
        
        # Check for deprecated/unsafe lifecycle methods
        unsafe_lifecycle_patterns = self.react_patterns['unsafe_lifecycle']
        for pattern in unsafe_lifecycle_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                severity = "high" if "UNSAFE_" in match.group() else "medium"
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"react_unsafe_lifecycle_{hash(str(match.group()))}",
                    title="Deprecated/Unsafe Lifecycle Method",
                    description="Use of deprecated or unsafe React lifecycle method",
                    severity=severity,
                    confidence="high",
                    framework="react",
                    category="deprecated",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    component_type="component",
                    fix_suggestion="Migrate to modern React patterns (hooks or safe lifecycle methods)"
                ))
        
        # Check for direct state mutations
        state_mutation_patterns = self.react_patterns['state_mutation']
        for pattern in state_mutation_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"react_state_mutation_{hash(str(match.group()))}",
                    title="Direct State Mutation",
                    description="Direct mutation of React state can cause security and stability issues",
                    severity="medium",
                    confidence="high",
                    framework="react",
                    category="state_management",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    component_type="component",
                    fix_suggestion="Use setState or state setter functions instead of direct mutation"
                ))
        
        # Check for insecure random keys
        random_key_patterns = self.react_patterns['insecure_random_keys']
        for pattern in random_key_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"react_insecure_keys_{hash(str(match.group()))}",
                    title="Insecure Random Keys",
                    description="Using Math.random() or Date.now() for React keys can cause issues",
                    severity="low",
                    confidence="high",
                    framework="react",
                    category="performance",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    component_type="component",
                    fix_suggestion="Use stable, unique identifiers for React keys"
                ))
        
        return vulnerabilities
    
    def _analyze_react_hook(self, file_path: Path, content: str, 
                           context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze React custom hooks for security issues."""
        
        vulnerabilities = []
        
        # Check for unsafe effect dependencies
        unsafe_effect_patterns = self.hooks_patterns['unsafe_effect_dependencies']
        for pattern in unsafe_effect_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"react_unsafe_effect_{hash(str(match.group()))}",
                    title="Unsafe useEffect Dependencies",
                    description="useEffect with empty dependencies making network requests",
                    severity="medium",
                    confidence="medium",
                    framework="react",
                    category="hooks",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=self._extract_code_snippet(content, match),
                    component_type="hook",
                    fix_suggestion="Include all dependencies in useEffect dependency array"
                ))
        
        # Check for potential memory leaks
        memory_leak_patterns = self.hooks_patterns['memory_leaks']
        for pattern in memory_leak_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"react_memory_leak_{hash(str(match.group()))}",
                    title="Potential Memory Leak in Hook",
                    description="Effect with timer/listener without cleanup function",
                    severity="medium",
                    confidence="medium",
                    framework="react",
                    category="hooks",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=self._extract_code_snippet(content, match),
                    component_type="hook",
                    fix_suggestion="Add cleanup function to clear timers/listeners"
                ))
        
        return vulnerabilities
    
    def _analyze_react_context(self, file_path: Path, content: str, 
                              context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze React Context for security issues."""
        
        vulnerabilities = []
        
        # Check for context injection vulnerabilities
        context_injection_patterns = self.react_patterns['context_injection']
        for pattern in context_injection_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"react_context_injection_{hash(str(match.group()))}",
                    title="Potential Context Injection",
                    description="React Context value contains user-controlled data",
                    severity="medium",
                    confidence="medium",
                    framework="react",
                    category="context",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    component_type="context",
                    requires_user_input=True,
                    fix_suggestion="Validate and sanitize data before storing in Context"
                ))
        
        # Check for sensitive data in context
        if re.search(r'(password|token|secret|key|credential)', content, re.IGNORECASE):
            vulnerabilities.append(FrameworkVulnerability(
                id=f"react_sensitive_context_{hash(str(file_path))}",
                title="Sensitive Data in React Context",
                description="Context may contain sensitive information",
                severity="medium",
                confidence="low",
                framework="react",
                category="context",
                file_path=str(file_path),
                component_type="context",
                fix_suggestion="Avoid storing sensitive data in React Context"
            ))
        
        return vulnerabilities
    
    def _analyze_react_service(self, file_path: Path, content: str, 
                              context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze React service/API files for security issues."""
        
        vulnerabilities = []
        
        # Check for hardcoded API endpoints
        api_patterns = [
            r'(fetch|axios)\s*\(\s*[\'"`]https?://[^\'"`]*[\'"`]',
            r'baseURL\s*:\s*[\'"`]https?://[^\'"`]*[\'"`]'
        ]
        
        for pattern in api_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"react_hardcoded_api_{hash(str(match.group()))}",
                    title="Hardcoded API Endpoint",
                    description="API endpoint is hardcoded in source code",
                    severity="low",
                    confidence="medium",
                    framework="react",
                    category="configuration",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    component_type="service",
                    fix_suggestion="Use environment variables for API endpoints"
                ))
        
        # Check for missing error handling
        if re.search(r'(fetch|axios)', content, re.IGNORECASE) and \
           not re.search(r'(catch|try.*catch|\.catch\()', content, re.IGNORECASE):
            
            vulnerabilities.append(FrameworkVulnerability(
                id=f"react_no_error_handling_{hash(str(file_path))}",
                title="Missing Error Handling in API Service",
                description="API calls lack proper error handling",
                severity="medium",
                confidence="medium",
                framework="react",
                category="error_handling",
                file_path=str(file_path),
                component_type="service",
                fix_suggestion="Add proper error handling for API calls"
            ))
        
        return vulnerabilities
    
    def _analyze_react_patterns(self, file_path: Path, content: str, 
                               context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze general React security patterns."""
        
        vulnerabilities = []
        
        # Check external script injection
        script_injection_patterns = self.react_patterns['external_script_injection']
        for pattern in script_injection_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"react_script_injection_{hash(str(match.group()))}",
                    title="External Script Injection Risk",
                    description="Dynamic script tag creation with user input",
                    severity="critical",
                    confidence="high",
                    framework="react",
                    category="xss",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    affects_client_side=True,
                    requires_user_input=True,
                    attack_vector="script_injection",
                    fix_suggestion="Avoid dynamic script creation or validate sources strictly"
                ))
        
        # Check for prop spreading security issues
        prop_injection_patterns = self.react_patterns['prop_injection']
        for pattern in prop_injection_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"react_prop_injection_{hash(str(match.group()))}",
                    title="Unsafe Prop Spreading",
                    description="Spreading props without validation can lead to security issues",
                    severity="medium",
                    confidence="low",
                    framework="react",
                    category="props",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=match.group(),
                    component_type="component",
                    fix_suggestion="Validate props before spreading or use explicit prop passing"
                ))
        
        return vulnerabilities
    
    def _analyze_react_hooks_patterns(self, file_path: Path, content: str, 
                                     context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze React hooks specific security patterns."""
        
        vulnerabilities = []
        
        # Check for state race conditions
        race_condition_patterns = self.hooks_patterns['state_race_conditions']
        for pattern in race_condition_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                
                vulnerabilities.append(FrameworkVulnerability(
                    id=f"react_race_condition_{hash(str(match.group()))}",
                    title="Potential State Race Condition",
                    description="Async state updates can cause race conditions",
                    severity="medium",
                    confidence="low",
                    framework="react",
                    category="hooks",
                    file_path=str(file_path),
                    line_number=line_number,
                    code_snippet=self._extract_code_snippet(content, match),
                    component_type="hook",
                    fix_suggestion="Use useCallback or useRef to handle async state updates safely"
                ))
        
        return vulnerabilities
    
    def _analyze_react_config(self, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze React configuration for security issues."""
        
        vulnerabilities = []
        
        # Check webpack configuration if present
        webpack_configs = [
            context.project_root / 'webpack.config.js',
            context.project_root / 'webpack.config.ts',
            context.project_root / 'craco.config.js'
        ]
        
        for config_file in webpack_configs:
            if config_file.exists():
                try:
                    content = config_file.read_text(encoding='utf-8')
                    vulnerabilities.extend(self._analyze_webpack_config(config_file, content))
                except Exception as e:
                    logger.error(f"Error reading webpack config {config_file}: {e}")
        
        return vulnerabilities
    
    def _analyze_webpack_config(self, config_file: Path, content: str) -> List[FrameworkVulnerability]:
        """Analyze webpack configuration for security issues."""
        
        vulnerabilities = []
        
        # Check for development mode in production
        if re.search(r'mode\s*:\s*[\'"`]development[\'"`]', content) and \
           'production' not in content.lower():
            
            vulnerabilities.append(FrameworkVulnerability(
                id="react_webpack_dev_mode",
                title="Development Mode in Production Build",
                description="Webpack configured for development mode",
                severity="medium",
                confidence="medium",
                framework="react",
                category="configuration",
                file_path=str(config_file),
                fix_suggestion="Use production mode for production builds"
            ))
        
        # Check for source maps in production
        if re.search(r'devtool\s*:\s*[\'"`].*source-?map[\'"`]', content):
            vulnerabilities.append(FrameworkVulnerability(
                id="react_webpack_source_maps",
                title="Source Maps Enabled",
                description="Source maps may expose source code in production",
                severity="low",
                confidence="medium",
                framework="react",
                category="configuration",
                file_path=str(config_file),
                fix_suggestion="Disable source maps in production builds"
            ))
        
        return vulnerabilities
    
    def _analyze_src_directory(self, src_dir: Path, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze src directory structure."""
        
        vulnerabilities = []
        
        for file_path in src_dir.rglob('*'):
            if file_path.is_file() and file_path.suffix in ['.js', '.jsx', '.ts', '.tsx']:
                try:
                    content = file_path.read_text(encoding='utf-8')
                    vulnerabilities.extend(self.analyze_file(file_path, content, context))
                except Exception as e:
                    logger.error(f"Error analyzing React file {file_path}: {e}")
        
        return vulnerabilities
    
    def _analyze_public_directory(self, public_dir: Path, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze public directory for security issues."""
        
        vulnerabilities = []
        
        # Check for sensitive files in public directory
        sensitive_patterns = [
            r'\.env', r'config\.json', r'\.key', r'\.pem',
            r'secrets?\.', r'credentials?\.', r'private',
            r'\.log', r'\.bak', r'\.backup'
        ]
        
        for file_path in public_dir.rglob('*'):
            if file_path.is_file():
                filename = file_path.name.lower()
                
                for pattern in sensitive_patterns:
                    if re.search(pattern, filename):
                        vulnerabilities.append(FrameworkVulnerability(
                            id=f"react_public_sensitive_{hash(str(file_path))}",
                            title="Sensitive File in Public Directory",
                            description=f"Potentially sensitive file exposed in public directory: {file_path.name}",
                            severity="high",
                            confidence="medium",
                            framework="react",
                            category="exposure",
                            file_path=str(file_path),
                            fix_suggestion="Remove sensitive files from public directory"
                        ))
                        break
        
        return vulnerabilities
    
    def _analyze_package_json_react(self, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze package.json for React specific issues."""
        
        vulnerabilities = []
        
        if not context.package_json:
            return vulnerabilities
        
        dependencies = {**context.dependencies, **context.dev_dependencies}
        
        # Check for outdated React version
        if 'react' in dependencies:
            react_version = dependencies['react']
            
            # Check for known vulnerable versions
            if any(old_version in react_version for old_version in ['15.', '16.0', '16.1', '16.2']):
                vulnerabilities.append(FrameworkVulnerability(
                    id="react_outdated_version",
                    title="Outdated React Version",
                    description=f"Using potentially vulnerable React version: {react_version}",
                    severity="medium",
                    confidence="high",
                    framework="react",
                    category="dependencies",
                    file_path="package.json",
                    fix_suggestion="Update React to the latest stable version"
                ))
        
        # Check for missing security-related dependencies
        security_deps = ['dompurify', 'helmet', 'prop-types']
        missing_security = [dep for dep in security_deps if dep not in dependencies]
        
        if len(missing_security) >= 2:
            vulnerabilities.append(FrameworkVulnerability(
                id="react_missing_security_deps",
                title="Missing Security Dependencies",
                description=f"Consider adding security dependencies: {', '.join(missing_security)}",
                severity="low",
                confidence="low",
                framework="react",
                category="dependencies",
                file_path="package.json",
                fix_suggestion="Add relevant security libraries for React applications"
            ))
        
        return vulnerabilities
    
    def _check_react_security_practices(self, project_path: Path, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Check for React security best practices."""
        
        vulnerabilities = []
        
        # Check for environment variables configuration
        env_files = [
            project_path / '.env',
            project_path / '.env.local',
            project_path / '.env.production'
        ]
        
        has_env_file = any(env_file.exists() for env_file in env_files)
        
        if not has_env_file:
            vulnerabilities.append(FrameworkVulnerability(
                id="react_no_env_config",
                title="Missing Environment Configuration",
                description="No environment variables file found",
                severity="low",
                confidence="medium",
                framework="react",
                category="configuration",
                file_path=str(project_path),
                fix_suggestion="Create .env files for environment-specific configuration"
            ))
        
        # Check for TypeScript usage
        has_typescript = (project_path / 'tsconfig.json').exists()
        
        if not has_typescript and context.package_json:
            dependencies = {**context.dependencies, **context.dev_dependencies}
            if 'typescript' not in dependencies and '@types/react' not in dependencies:
                vulnerabilities.append(FrameworkVulnerability(
                    id="react_no_typescript",
                    title="TypeScript Not Configured",
                    description="TypeScript provides additional type safety",
                    severity="info",
                    confidence="low",
                    framework="react",
                    category="configuration",
                    file_path=str(project_path),
                    fix_suggestion="Consider using TypeScript for better type safety"
                ))
        
        return vulnerabilities
    
    def _analyze_build_config(self, project_path: Path, context: FrameworkContext) -> List[FrameworkVulnerability]:
        """Analyze build configuration for security issues."""
        
        vulnerabilities = []
        
        # Check for Create React App eject
        if (project_path / 'config').exists() and (project_path / 'scripts').exists():
            vulnerabilities.append(FrameworkVulnerability(
                id="react_cra_ejected",
                title="Create React App Ejected",
                description="Ejected CRA apps require manual security configuration maintenance",
                severity="info",
                confidence="high",
                framework="react",
                category="configuration",
                file_path=str(project_path),
                fix_suggestion="Ensure webpack and build configurations follow security best practices"
            ))
        
        return vulnerabilities
    
    # Helper methods
    def _is_user_controlled_content(self, match_content: str, full_content: str) -> bool:
        """Check if content is user-controlled."""
        user_input_indicators = [
            'props.', 'state.', 'useState', 'useContext',
            'req.', 'params.', 'query.', 'body.',
            'input.', 'form.', 'event.target'
        ]
        
        return any(indicator in match_content for indicator in user_input_indicators)
    
    def _extract_code_snippet(self, content: str, match, context_lines: int = 2) -> str:
        """Extract code snippet with context."""
        lines = content.split('\n')
        start_line = content[:match.start()].count('\n')
        
        snippet_start = max(0, start_line - context_lines)
        snippet_end = min(len(lines), start_line + context_lines + 1)
        
        return '\n'.join(lines[snippet_start:snippet_end])
