"""
Advanced Next.js Security Scanner

Provides deep security analysis for Next.js applications.
"""

import re
import json
from pathlib import Path
from typing import List, Dict, Any
import sys
import os

# Add the plugins directory to the path
current_dir = Path(__file__).parent
plugins_dir = current_dir.parent.parent
sys.path.insert(0, str(plugins_dir))

from core.scanner_plugin import ScannerPlugin

class NextJSAdvancedScanner(ScannerPlugin):
    """Advanced Next.js security scanner."""
    
    def get_name(self) -> str:
        return "nextjs_advanced"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def is_compatible(self, njordscan_version: str) -> bool:
        # Simple version check
        return njordscan_version >= "0.1.0"
    
    def should_run(self, mode: str) -> bool:
        """Run in static and full modes for Next.js projects."""
        framework_match = getattr(self.config, 'framework', '') == 'nextjs'
        return mode in ['static', 'full'] and framework_match
    
    async def scan(self, target: str) -> List[Dict[str, Any]]:
        """Main scanning method."""
        vulnerabilities = []
        
        if target.startswith(('http://', 'https://')):
            return vulnerabilities  # Only scan local directories
        
        target_path = Path(target)
        if not target_path.exists():
            return vulnerabilities
        
        # Scan API routes
        if self._get_config_value('scan_api_routes', True):
            api_vulns = await self._scan_api_routes(target_path)
            vulnerabilities.extend(api_vulns)
        
        # Check middleware
        if self._get_config_value('check_middleware', True):
            middleware_vulns = await self._scan_middleware(target_path)
            vulnerabilities.extend(middleware_vulns)
        
        # Scan getServerSideProps/getStaticProps
        ssr_vulns = await self._scan_ssr_functions(target_path)
        vulnerabilities.extend(ssr_vulns)
        
        # Check Next.js configuration
        config_vulns = await self._scan_nextjs_config(target_path)
        vulnerabilities.extend(config_vulns)
        
        return vulnerabilities
    
    def _get_config_value(self, key: str, default: Any) -> Any:
        """Get plugin configuration value."""
        plugin_config = getattr(self.config, 'plugins', {}).get('nextjs_advanced', {})
        return plugin_config.get('config', {}).get(key, default)
    
    async def _scan_api_routes(self, target_path: Path) -> List[Dict[str, Any]]:
        """Scan Next.js API routes for security issues."""
        vulnerabilities = []
        
        # Find API route files
        api_patterns = [
            'pages/api/**/*.js',
            'pages/api/**/*.ts', 
            'app/api/**/*.js',
            'app/api/**/*.ts'
        ]
        
        api_files = []
        for pattern in api_patterns:
            api_files.extend(target_path.glob(pattern))
        
        for api_file in api_files:
            if self.should_skip_file(api_file):
                continue
            file_vulns = await self._analyze_api_route_file(api_file)
            vulnerabilities.extend(file_vulns)
        
        return vulnerabilities
    
    async def _analyze_api_route_file(self, api_file: Path) -> List[Dict[str, Any]]:
        """Analyze individual API route file."""
        vulnerabilities = []
        
        try:
            content = self.get_file_content(str(api_file))
            if not content:
                return vulnerabilities
            
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                # Check for missing input validation
                if re.search(r'req\.(body|query|params)\.[a-zA-Z_]+', line):
                    if not self._has_validation_nearby(lines, line_num):
                        vulnerabilities.append(self.create_vulnerability(
                            title="Missing Input Validation in API Route",
                            description="API route accesses request parameters without validation",
                            severity="medium",
                            vuln_type="missing_validation",
                            file_path=str(api_file),
                            line_number=line_num,
                            code_snippet=line.strip(),
                            fix="Implement input validation using libraries like Joi, Yup, or Zod"
                        ))
                
                # Check for SQL injection risks
                if re.search(r'(query|execute)\s*\([^)]*req\.(body|query)', line):
                    vulnerabilities.append(self.create_vulnerability(
                        title="Potential SQL Injection in API Route",
                        description="Database query uses unvalidated user input",
                        severity="critical",
                        vuln_type="sql_injection",
                        file_path=str(api_file),
                        line_number=line_num,
                        code_snippet=line.strip(),
                        fix="Use parameterized queries or ORM methods to prevent SQL injection"
                    ))
                
                # Check for CORS misconfigurations
                if 'res.setHeader' in line and 'Access-Control-Allow-Origin' in line:
                    if '*' in line:
                        vulnerabilities.append(self.create_vulnerability(
                            title="Overly Permissive CORS Configuration",
                            description="API route allows all origins with wildcard CORS",
                            severity="medium",
                            vuln_type="cors_misconfiguration",
                            file_path=str(api_file),
line_number=line_num,
                           code_snippet=line.strip(),
                           fix="Specify explicit allowed origins instead of using wildcard"
                       ))
           
           # Check for missing authentication at file level
           if 'export default' in content and 'handler' in content:
               if not self._has_auth_check(content):
                   vulnerabilities.append(self.create_vulnerability(
                       title="Missing Authentication in API Route",
                       description="API route handler lacks authentication checks",
                       severity="high",
                       vuln_type="missing_auth",
                       file_path=str(api_file),
                       line_number=1,
                       fix="Implement authentication middleware or JWT verification"
                   ))
       
       except Exception as e:
           if getattr(self.config, 'verbose', False):
               print(f"Error analyzing API route {api_file}: {e}")
       
       return vulnerabilities
   
   def _has_validation_nearby(self, lines: List[str], line_num: int) -> bool:
       """Check if validation exists near the given line."""
       validation_keywords = ['validate', 'schema', 'joi', 'yup', 'zod', 'check']
       
       # Check 5 lines before and after
       start = max(0, line_num - 5)
       end = min(len(lines), line_num + 5)
       
       for i in range(start, end):
           line_lower = lines[i].lower()
           if any(keyword in line_lower for keyword in validation_keywords):
               return True
       
       return False
   
   def _has_auth_check(self, content: str) -> bool:
       """Check if content has authentication logic."""
       auth_keywords = [
           'authenticate', 'authorize', 'jwt', 'token', 'session',
           'auth', 'login', 'bearer', 'getServerSession'
       ]
       
       content_lower = content.lower()
       return any(keyword in content_lower for keyword in auth_keywords)
   
   async def _scan_middleware(self, target_path: Path) -> List[Dict[str, Any]]:
       """Scan Next.js middleware for security issues."""
       vulnerabilities = []
       
       middleware_files = [
           target_path / 'middleware.js',
           target_path / 'middleware.ts',
           target_path / 'src' / 'middleware.js',
           target_path / 'src' / 'middleware.ts'
       ]
       
       for middleware_file in middleware_files:
           if middleware_file.exists():
               file_vulns = await self._analyze_middleware_file(middleware_file)
               vulnerabilities.extend(file_vulns)
       
       return vulnerabilities
   
   async def _analyze_middleware_file(self, middleware_file: Path) -> List[Dict[str, Any]]:
       """Analyze middleware file for security issues."""
       vulnerabilities = []
       
       try:
           content = self.get_file_content(str(middleware_file))
           if not content:
               return vulnerabilities
           
           lines = content.split('\n')
           
           for line_num, line in enumerate(lines, 1):
               # Check for overly broad middleware matchers
               if 'matcher:' in line and '*' in line:
                   vulnerabilities.append(self.create_vulnerability(
                       title="Overly Broad Middleware Matcher",
                       description="Middleware matcher uses wildcard which may impact performance",
                       severity="low",
                       vuln_type="broad_middleware",
                       file_path=str(middleware_file),
                       line_number=line_num,
                       code_snippet=line.strip(),
                       fix="Use specific path patterns instead of wildcards"
                   ))
           
           # Check for missing CSP headers in middleware
           if 'NextResponse' in content and 'Content-Security-Policy' not in content:
               vulnerabilities.append(self.create_vulnerability(
                   title="Missing CSP Headers in Middleware",
                   description="Middleware doesn't set Content Security Policy headers",
                   severity="medium",
                   vuln_type="missing_csp",
                   file_path=str(middleware_file),
                   line_number=1,
                   fix="Add Content-Security-Policy headers in middleware response"
               ))
       
       except Exception as e:
           if getattr(self.config, 'verbose', False):
               print(f"Error analyzing middleware {middleware_file}: {e}")
       
       return vulnerabilities
   
   async def _scan_ssr_functions(self, target_path: Path) -> List[Dict[str, Any]]:
       """Scan getServerSideProps and getStaticProps functions."""
       vulnerabilities = []
       
       # Find page files
       page_patterns = [
           'pages/**/*.js',
           'pages/**/*.ts',
           'pages/**/*.jsx', 
           'pages/**/*.tsx',
           'app/**/page.js',
           'app/**/page.ts',
           'app/**/page.jsx',
           'app/**/page.tsx'
       ]
       
       page_files = []
       for pattern in page_patterns:
           page_files.extend(target_path.glob(pattern))
       
       for page_file in page_files:
           if self.should_skip_file(page_file):
               continue
           file_vulns = await self._analyze_ssr_file(page_file)
           vulnerabilities.extend(file_vulns)
       
       return vulnerabilities
   
   async def _analyze_ssr_file(self, page_file: Path) -> List[Dict[str, Any]]:
       """Analyze SSR functions in page files."""
       vulnerabilities = []
       
       try:
           content = self.get_file_content(str(page_file))
           if not content:
               return vulnerabilities
           
           lines = content.split('\n')
           
           for line_num, line in enumerate(lines, 1):
               # Check for SSRF in getServerSideProps
               if 'getServerSideProps' in line or 'getStaticProps' in line:
                   # Look for fetch calls with user input
                   if re.search(r'fetch\s*\([^)]*req\.(query|params)', line):
                       vulnerabilities.append(self.create_vulnerability(
                           title="Potential SSRF in SSR Function",
                           description="SSR function makes external requests with user-controlled input",
                           severity="high",
                           vuln_type="ssrf",
                           file_path=str(page_file),
                           line_number=line_num,
                           code_snippet=line.strip(),
                           fix="Validate and whitelist URLs before making external requests"
                       ))
               
               # Check for sensitive data exposure
               if 'props:' in line and any(sensitive in line.lower() for sensitive in ['password', 'secret', 'key', 'token']):
                   vulnerabilities.append(self.create_vulnerability(
                       title="Sensitive Data in SSR Props",
                       description="SSR function may be exposing sensitive data in props",
                       severity="medium",
                       vuln_type="data_exposure",
                       file_path=str(page_file),
                       line_number=line_num,
                       code_snippet=line.strip(),
                       fix="Ensure sensitive data is not included in client-side props"
                   ))
       
       except Exception as e:
           if getattr(self.config, 'verbose', False):
               print(f"Error analyzing SSR file {page_file}: {e}")
       
       return vulnerabilities
   
   async def _scan_nextjs_config(self, target_path: Path) -> List[Dict[str, Any]]:
       """Scan Next.js configuration files."""
       vulnerabilities = []
       
       config_files = [
           target_path / 'next.config.js',
           target_path / 'next.config.ts',
           target_path / 'next.config.mjs'
       ]
       
       for config_file in config_files:
           if config_file.exists():
               file_vulns = await self._analyze_nextjs_config_file(config_file)
               vulnerabilities.extend(file_vulns)
       
       return vulnerabilities
   
   async def _analyze_nextjs_config_file(self, config_file: Path) -> List[Dict[str, Any]]:
       """Analyze Next.js configuration file."""
       vulnerabilities = []
       
       try:
           content = self.get_file_content(str(config_file))
           if not content:
               return vulnerabilities
           
           # Check for insecure redirects configuration
           if 'redirects' in content and 'destination:' in content:
               if re.search(r'destination:\s*[\'"][^\'"]*/.*\$', content):
                   vulnerabilities.append(self.create_vulnerability(
                       title="Potential Open Redirect in Next.js Config",
                       description="Redirect configuration may allow open redirects",
                       severity="medium",
                       vuln_type="open_redirect",
                       file_path=str(config_file),
                       fix="Validate redirect destinations and avoid user-controlled redirects"
                   ))
           
           # Check for experimental features in production
           if 'experimental:' in content:
               vulnerabilities.append(self.create_vulnerability(
                   title="Experimental Features Enabled",
                   description="Next.js experimental features should not be used in production",
                   severity="low",
                   vuln_type="experimental_features",
                   file_path=str(config_file),
                   fix="Remove experimental features for production builds"
               ))
           
           # Check for insecure image domains
           if re.search(r'images\s*:\s*{[^}]*domains\s*:\s*\[[^\]]*[\'"][*][\'"][^\]]*\]', content):
               vulnerabilities.append(self.create_vulnerability(
                   title="Wildcard Image Domain Configuration",
                   description="Next.js image configuration allows all domains (*) which may enable SSRF attacks",
                   severity="high",
                   vuln_type="wildcard_images",
                   file_path=str(config_file),
                   fix="Specify explicit allowed domains instead of using wildcards"
               ))
           
           # Check for disabled security features
           if 'poweredByHeader: false' not in content:
               vulnerabilities.append(self.create_vulnerability(
                   title="X-Powered-By Header Not Disabled",
                   description="Next.js X-Powered-By header disclosure is not disabled",
                   severity="low",
                   vuln_type="header_disclosure",
                   file_path=str(config_file),
                   fix="Add 'poweredByHeader: false' to next.config.js"
               ))
       
       except Exception as e:
           if getattr(self.config, 'verbose', False):
               print(f"Error analyzing Next.js config {config_file}: {e}")
       
       return vulnerabilities