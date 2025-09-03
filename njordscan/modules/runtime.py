"""
Runtime Security Module

Performs dynamic security testing against running applications.
"""

import asyncio
import aiohttp
import time
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Dict, Any, Optional
import re

from .base import BaseModule
from ..vulnerability import Vulnerability

class RuntimeModule(BaseModule):
    """Module for runtime security testing."""
    
    def __init__(self, config, vuln_id_generator):
        super().__init__(config, vuln_id_generator)
        
        # Test payloads for different vulnerability types
        self.test_payloads = {
            'xss': [
                '<script>alert("XSS")</script>',
                '"><script>alert("XSS")</script>',
                'javascript:alert("XSS")',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')"></iframe>',
                '\'"><script>alert(String.fromCharCode(88,83,83))</script>'
            ],
            'sql_injection': [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "' OR 1=1#",
                "admin'--",
                "' OR 'a'='a",
                "1' OR '1'='1' --"
            ],
            'command_injection': [
                '; ls -la',
                '| whoami',
                '&& cat /etc/passwd',
                '$(whoami)',
                '`whoami`',
                '; ping -c 1 127.0.0.1',
                '| echo "vulnerable"'
            ],
            'path_traversal': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '....//....//....//etc/passwd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                '..%252f..%252f..%252fetc%252fpasswd'
            ]
        }
        
        # Common endpoints to test
        self.common_endpoints = [
            '/admin', '/login', '/api', '/test', '/debug',
            '/config', '/status', '/health', '/info',
            '/users', '/user', '/profile', '/dashboard'
        ]
        
        # Information disclosure endpoints
        self.info_endpoints = [
            '/.env', '/.env.local', '/.env.production', '/.env.development',
            '/package.json', '/composer.json', '/README.md', '/config.json',
            '/backup.sql', '/database.sql', '/.git/config', '/.svn/entries',
            '/web.config', '/.htaccess', '/phpinfo.php', '/info.php',
            '/server-info', '/server-status', '/.well-known/security.txt'
        ]
    
    def should_run(self, mode: str) -> bool:
        """Runtime module runs in dynamic and full modes."""
        return mode in ['dynamic', 'full']
    
    async def scan(self, target: str) -> List[Vulnerability]:
        """Perform runtime security testing."""
        vulnerabilities = []
        
        if not target.startswith(('http://', 'https://')):
            return vulnerabilities  # Only scan URLs
        
        return await self.scan_url(target)
    
    async def scan_url(self, url: str) -> List[Vulnerability]:
        """Perform runtime security testing on a URL."""
        vulnerabilities = []
        
        # Create session with appropriate configuration
        connector = aiohttp.TCPConnector(
            limit=self.config.max_concurrent,
            limit_per_host=10,
            ssl=False  # Allow testing of SSL issues
        )
        
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'NjordScan Security Scanner'}
        ) as session:
            
            # Basic security tests
            basic_vulns = await self._test_basic_security(session, url)
            vulnerabilities.extend(basic_vulns)
            
            # Framework-specific tests
            framework_vulns = await self._test_framework_specific(session, url)
            vulnerabilities.extend(framework_vulns)
            
            # Information disclosure tests
            info_vulns = await self._test_information_disclosure(session, url)
            vulnerabilities.extend(info_vulns)
            
            # Advanced tests (only in pentest mode)
            if self.config.pentest_mode:
                pentest_vulns = await self._test_advanced_security(session, url)
                vulnerabilities.extend(pentest_vulns)
        
        return vulnerabilities
    
    async def _test_basic_security(self, session, target: str) -> List[Vulnerability]:
        """Test basic security configurations."""
        vulnerabilities = []
        
        try:
            # Test HTTP methods
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS', 'HEAD']
            
            for method in methods:
                try:
                    async with session.request(method, target) as response:
                        if method == 'TRACE' and response.status == 200:
                            # Check if body contains request headers (XST vulnerability)
                            body = await response.text()
                            if any(header in body.upper() for header in ['USER-AGENT', 'AUTHORIZATION', 'COOKIE']):
                                vulnerabilities.append(self.create_vulnerability(
                                    title="HTTP TRACE Method Enabled (XST Vulnerability)",
                                    description="HTTP TRACE method reflects request headers, enabling Cross-Site Tracing attacks",
                                    severity="medium",
                                    vuln_type="xss_reflected",
                                    fix="Disable HTTP TRACE method on the server",
                                    reference="https://owasp.org/www-community/attacks/Cross_Site_Tracing",
                                    metadata={
                                        'method': method,
                                        'status_code': response.status,
                                        'response_body_snippet': body[:200]
                                    }
                                ))
                        
                        # Check for dangerous methods
                        if method in ['PUT', 'DELETE'] and response.status not in [405, 501, 403]:
                            vulnerabilities.append(self.create_vulnerability(
                                title=f"HTTP {method} Method Allowed",
                                description=f"HTTP {method} method is allowed, which might pose security risks",
                                severity="low" if method == "PUT" else "medium",
                                vuln_type="insecure_configuration",
                                fix=f"Disable HTTP {method} method if not required",
                                metadata={
                                    'method': method,
                                    'status_code': response.status
                                }
                            ))
                
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue
            
            # Test for debug endpoints
            debug_endpoints = [
                '/debug', '/phpinfo.php', '/info.php', '/test.php',
                '/debug.php', '/server-info', '/server-status',
                '/_debug_toolbar/', '/debug_toolbar/'
            ]
            
            for endpoint in debug_endpoints:
                try:
                    test_url = urljoin(target, endpoint)
                    async with session.get(test_url) as response:
                        if response.status == 200:
                            content = await response.text()
                            if len(content) > 100:  # Substantial content
                                vulnerabilities.append(self.create_vulnerability(
                                    title=f"Debug Endpoint Accessible: {endpoint}",
                                    description=f"Debug endpoint {endpoint} is publicly accessible",
                                    severity="medium",
                                    vuln_type="debug_mode_enabled",
                                    fix=f"Disable or restrict access to {endpoint}",
                                    metadata={
                                        'endpoint': endpoint,
                                        'status_code': response.status,
                                        'content_length': len(content)
                                    }
                                ))
                
                except Exception:
                    continue
        
        except Exception as e:
            if self.config.verbose:
                print(f"Error in basic security tests: {e}")
        
        return vulnerabilities
    
    async def _test_framework_specific(self, session, target: str) -> List[Vulnerability]:
        """Test framework-specific vulnerabilities."""
        vulnerabilities = []
        
        if self.config.framework == 'nextjs':
            vulnerabilities.extend(await self._test_nextjs_specific(session, target))
        elif self.config.framework == 'vite':
            vulnerabilities.extend(await self._test_vite_specific(session, target))
        elif self.config.framework == 'react':
            vulnerabilities.extend(await self._test_react_specific(session, target))
        
        return vulnerabilities
    
    async def _test_nextjs_specific(self, session, target: str) -> List[Vulnerability]:
        """Test Next.js specific vulnerabilities."""
        vulnerabilities = []
        
        nextjs_endpoints = [
            '/_next/static/',
            '/_next/webpack-hmr',
            '/_next/image',
            '/api/',
            '/_next/server/',
            '/_next/trace'
        ]
        
        for endpoint in nextjs_endpoints:
            try:
                test_url = urljoin(target, endpoint)
                async with session.get(test_url) as response:
                    
                    # Check for development HMR endpoint
                    if endpoint == '/_next/webpack-hmr' and response.status == 200:
                        vulnerabilities.append(self.create_vulnerability(
                            title="Next.js HMR Endpoint Accessible in Production",
                            description="Next.js Hot Module Replacement endpoint is accessible, indicating development mode",
                            severity="medium",
                            vuln_type="debug_mode_enabled",
                            fix="Ensure production builds disable HMR",
                            metadata={
                                'endpoint': endpoint,
                                'status_code': response.status
                            }
                        ))
                    
                    # Test Next.js image optimization for SSRF
                    if endpoint == '/_next/image' and response.status == 200:
                        ssrf_test_urls = [
                            f"{test_url}?url=http://127.0.0.1:8080/test",
                            f"{test_url}?url=http://localhost:22",
                            f"{test_url}?url=file:///etc/passwd"
                        ]
                        
                        for ssrf_url in ssrf_test_urls:
                            try:
                                async with session.get(ssrf_url) as ssrf_response:
                                    # Look for successful requests or error messages indicating SSRF
                                    if ssrf_response.status == 200 or 'connection' in str(ssrf_response.status):
                                        vulnerabilities.append(self.create_vulnerability(
                                            title="Next.js Image Optimization SSRF Vulnerability",
                                            description="Next.js image optimization may be vulnerable to Server-Side Request Forgery",
                                            severity="high",
                                            vuln_type="ssrf",
                                            fix="Implement proper URL validation and whitelisting in image optimization",
                                            reference="https://nextjs.org/docs/basic-features/image-optimization#domains",
                                            metadata={
                                                'test_url': ssrf_url,
                                                'status_code': ssrf_response.status
                                            }
                                        ))
                                        break  # Stop testing once SSRF is confirmed
                            except Exception:
                                continue
                    
                    # Check for exposed API routes
                    if endpoint == '/api/' and response.status in [200, 404]:
                        # Test common API endpoints
                        api_endpoints = ['/api/auth', '/api/users', '/api/admin', '/api/config']
                        for api_endpoint in api_endpoints:
                            try:
                                api_url = urljoin(target, api_endpoint)
                                async with session.get(api_url) as api_response:
                                    if api_response.status == 200:
                                        content = await api_response.text()
                                        if any(indicator in content.lower() for indicator in ['user', 'admin', 'config', 'auth']):
                                            vulnerabilities.append(self.create_vulnerability(
                                                title=f"Potentially Exposed API Endpoint: {api_endpoint}",
                                                description=f"API endpoint {api_endpoint} is accessible and returns data",
                                                severity="medium",
                                                vuln_type="unauthorized_access",
                                                fix="Implement proper authentication and authorization for API endpoints",
                                                metadata={
                                                    'endpoint': api_endpoint,
                                                    'status_code': api_response.status
                                                }
                                            ))
                            except Exception:
                                continue
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_vite_specific(self, session, target: str) -> List[Vulnerability]:
        """Test Vite specific vulnerabilities."""
        vulnerabilities = []
        
        vite_endpoints = [
            '/@vite/client',
            '/@fs/',
            '/@id/',
            '/src/',
            '/vite.config.js',
            '/vite.config.ts',
            '/@vite/env'
        ]
        
        for endpoint in vite_endpoints:
            try:
                test_url = urljoin(target, endpoint)
                async with session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        vulnerabilities.append(self.create_vulnerability(
                            title=f"Vite Development Endpoint Accessible: {endpoint}",
                            description=f"Vite development endpoint {endpoint} is accessible in production",
                            severity="medium" if endpoint.startswith('/@') else "high",
                            vuln_type="debug_mode_enabled",
                            fix="Ensure Vite development endpoints are not accessible in production",
                            metadata={
                                'endpoint': endpoint,
                                'status_code': response.status,
                                'content_length': len(content)
                            }
                        ))
                        
                        # Check for file system access
                        if endpoint == '/@fs/' and len(content) > 50:
                            vulnerabilities.append(self.create_vulnerability(
                                title="Vite File System Access Exposed",
                                description="Vite @fs endpoint allows file system access",
                                severity="critical",
                                vuln_type="insecure_configuration",
                                fix="Disable Vite development server in production",
                                metadata={
                                    'endpoint': endpoint,
                                    'status_code': response.status
                                }
                            ))
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_react_specific(self, session, target: str) -> List[Vulnerability]:
        """Test React specific vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Check main page for React DevTools or development indicators
            async with session.get(target) as response:
                text = await response.text()
                
                # Check for React DevTools
                if 'react-devtools' in text.lower() or '__REACT_DEVTOOLS_GLOBAL_HOOK__' in text:
                    vulnerabilities.append(self.create_vulnerability(
                        title="React DevTools Detected in Production",
                        description="React DevTools references found in production build",
                        severity="low",
                        vuln_type="debug_mode_enabled",
                        fix="Remove React DevTools from production builds",
                        metadata={
                            'status_code': response.status
                        }
                    ))
                
                # Check for development mode indicators
                if 'development' in text and 'react' in text.lower():
                    vulnerabilities.append(self.create_vulnerability(
                        title="React Development Mode Detected",
                        description="React application appears to be running in development mode",
                        severity="medium",
                        vuln_type="debug_mode_enabled",
                        fix="Ensure React production builds are used in production",
                        metadata={
                            'status_code': response.status
                        }
                    ))
        
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _test_information_disclosure(self, session, target: str) -> List[Vulnerability]:
        """Test for information disclosure vulnerabilities."""
        vulnerabilities = []
        
        for endpoint in self.info_endpoints:
            try:
                test_url = urljoin(target, endpoint)
                async with session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check if content looks legitimate (not just error pages)
                        if len(content) > 50 and not all(word in content.lower() for word in ['not found', '404', 'error']):
                            severity = self._determine_info_disclosure_severity(endpoint, content)
                            
                            vulnerabilities.append(self.create_vulnerability(
                                title=f"Information Disclosure: {endpoint}",
                                description=f"Sensitive file {endpoint} is publicly accessible",
                                severity=severity,
                                vuln_type="secrets_exposure",
                                fix=f"Restrict access to {endpoint} or remove it from public directory",
                                metadata={
                                    'endpoint': endpoint,
                                    'status_code': response.status,
                                    'content_length': len(content),
                                    'content_type': response.headers.get('content-type', 'unknown')
                                }
                            ))
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_advanced_security(self, session, target: str) -> List[Vulnerability]:
        """Perform advanced security testing (pentest mode only)."""
        vulnerabilities = []
        
        if not self.config.pentest_mode:
            return vulnerabilities
        
        try:
            # Find forms and inputs for testing
            forms = await self._discover_forms(session, target)
            
            for form in forms:
                # Test for XSS vulnerabilities
                xss_vulns = await self._test_xss_vulnerabilities(session, form)
                vulnerabilities.extend(xss_vulns)
                
                # Test for SQL injection
                sqli_vulns = await self._test_sql_injection(session, form)
                vulnerabilities.extend(sqli_vulns)
                
                # Test for command injection
                cmd_vulns = await self._test_command_injection(session, form)
                vulnerabilities.extend(cmd_vulns)
                
                # Rate limiting to avoid overwhelming the target
                await asyncio.sleep(1)
        
        except Exception as e:
            if self.config.verbose:
                print(f"Error in advanced security tests: {e}")
        
        return vulnerabilities
    
    async def _discover_forms(self, session, target: str) -> List[Dict[str, Any]]:
        """Discover forms on the target for testing."""
        forms = []
        
        try:
            # Get main page
            async with session.get(target) as response:
                text = await response.text()
                
                # Simple form detection using regex
                form_pattern = r'<form[^>]*action=["\']?([^"\'>\s]+)["\']?[^>]*>(.*?)</form>'
                matches = re.finditer(form_pattern, text, re.DOTALL | re.IGNORECASE)
                
                for match in matches:
                    action = match.group(1)
                    form_content = match.group(2)
                    
                    # Extract input fields
                    input_pattern = r'<input[^>]*name=["\']?([^"\'>\s]+)["\']?[^>]*>'
                    inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
                    
                    forms.append({
                        'action': urljoin(target, action) if not action.startswith('http') else action,
                        'inputs': inputs,
                        'method': 'POST'  # Default to POST for testing
                    })
        
        except Exception:
            pass
        
        return forms
    
    async def _test_xss_vulnerabilities(self, session, form: Dict[str, Any]) -> List[Vulnerability]:
        """Test for XSS vulnerabilities in forms."""
        vulnerabilities = []
        
        for payload in self.test_payloads['xss'][:3]:  # Limit to first 3 payloads
            try:
                # Create form data with XSS payload
                data = {}
                for input_name in form['inputs']:
                    data[input_name] = payload
                
                async with session.post(form['action'], data=data) as response:
                    response_text = await response.text()
                    
                    # Check if payload is reflected unescaped
                    if payload in response_text and '<script>' in response_text:
                        vulnerabilities.append(self.create_vulnerability(
                            title="Reflected XSS Vulnerability",
                            description="Form input is reflected in the response without proper escaping",
                            severity="high",
                            vuln_type="xss_reflected",
                            fix="Implement proper input validation and output encoding",
                            reference="https://owasp.org/www-community/attacks/xss/",
                            metadata={
                                'form_action': form['action'],
                                'payload': payload,
                                'response_status': response.status
                            }
                        ))
                        break  # Stop testing once XSS is confirmed
                
                # Rate limiting
                await asyncio.sleep(0.5)
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_sql_injection(self, session, form: Dict[str, Any]) -> List[Vulnerability]:
        """Test for SQL injection vulnerabilities."""
        vulnerabilities = []
        
        for payload in self.test_payloads['sql_injection'][:3]:
            try:
                data = {}
                for input_name in form['inputs']:
                    data[input_name] = payload
                
                async with session.post(form['action'], data=data) as response:
                    response_text = await response.text()
                    
                    # Look for SQL error indicators
                    sql_errors = [
                        'mysql_fetch_array', 'ora-01756', 'microsoft ole db provider',
                        'sqlexception', 'postgresql query failed', 'warning: pg_connect',
                        'valid mysql result', 'mysqlclient', 'oledbexception',
                        'unclosed quotation mark', 'microsoft jet database engine'
                    ]
                    
                    if any(error in response_text.lower() for error in sql_errors):
                        vulnerabilities.append(self.create_vulnerability(
                            title="SQL Injection Vulnerability",
                            description="Form appears to be vulnerable to SQL injection attacks",
                            severity="critical",
                            vuln_type="sql_injection",
                            fix="Use parameterized queries and proper input validation",
                            reference="https://owasp.org/www-community/attacks/SQL_Injection",
                            metadata={
                                'form_action': form['action'],
                                'payload': payload,
                                'response_status': response.status
                            }
                        ))
                        break
                
                await asyncio.sleep(0.5)
            
            except Exception:
                continue
        
        return vulnerabilities
    
    async def _test_command_injection(self, session, form: Dict[str, Any]) -> List[Vulnerability]:
        """Test for command injection vulnerabilities."""
        vulnerabilities = []
        
        for payload in self.test_payloads['command_injection'][:2]:
            try:
                data = {}
                for input_name in form['inputs']:
                    data[input_name] = payload
                
                async with session.post(form['action'], data=data) as response:
                    response_text = await response.text()
                    
                    # Look for command execution indicators
                    if any(indicator in response_text.lower() for indicator in ['root:', 'bin/bash', 'vulnerable', 'uid=']):
                        vulnerabilities.append(self.create_vulnerability(
                            title="Command Injection Vulnerability",
                            description="Form appears to be vulnerable to command injection attacks",
                            severity="critical",
                            vuln_type="command_injection",
                            fix="Avoid executing system commands with user input or use proper sanitization",
                            reference="https://owasp.org/www-community/attacks/Command_Injection",
                            metadata={
                                'form_action': form['action'],
                                'payload': payload,
                                'response_status': response.status
                            }
                        ))
                        break
                
                await asyncio.sleep(0.5)
            
            except Exception:
                continue
        
        return vulnerabilities
    
    def _determine_info_disclosure_severity(self, endpoint: str, content: str) -> str:
        """Determine severity of information disclosure based on content."""
        critical_indicators = [
            'password', 'secret', 'key', 'token', 'api_key',
            'database', 'connection', 'credential'
        ]
        
        high_indicators = [
            'config', 'env', 'environment', 'settings'
        ]
        
        content_lower = content.lower()
        
        if any(indicator in content_lower for indicator in critical_indicators):
            return 'critical'
        elif any(indicator in content_lower for indicator in high_indicators):
            return 'high'
        elif endpoint.startswith('.'):
            return 'medium'
        else:
            return 'low'