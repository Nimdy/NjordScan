"""
HTTP Security Headers Module

Scans for missing or misconfigured security headers.
"""

import asyncio
import aiohttp
from typing import List
from urllib.parse import urljoin

from .base import BaseModule
from ..vulnerability import Vulnerability

class HeadersModule(BaseModule):
    """Module for scanning HTTP security headers."""
    
    def __init__(self, config, vuln_id_generator):
        super().__init__(config, vuln_id_generator)
        self.required_headers = {
            'Content-Security-Policy': {
                'severity': 'high',
                'description': 'Prevents XSS and code injection attacks',
                'fix': 'Implement a Content Security Policy header',
                'vuln_type': 'missing_security_headers',
                'explanation': 'Without CSP, attackers can inject malicious scripts into your website, potentially stealing user data or taking control of user accounts.'
            },
            'X-Frame-Options': {
                'severity': 'medium',
                'description': 'Prevents clickjacking attacks',
                'fix': 'Add X-Frame-Options: DENY or SAMEORIGIN header',
                'vuln_type': 'missing_security_headers',
                'explanation': 'Clickjacking allows attackers to trick users into clicking buttons they didn\'t intend to click, potentially making unauthorized purchases or actions.'
            },
            'X-Content-Type-Options': {
                'severity': 'medium',
                'description': 'Prevents MIME type sniffing',
                'fix': 'Add X-Content-Type-Options: nosniff header',
                'vuln_type': 'missing_security_headers',
                'explanation': 'MIME type sniffing can lead to security vulnerabilities where browsers execute files as different types than intended.'
            },
            'Strict-Transport-Security': {
                'severity': 'medium',
                'description': 'Enforces HTTPS connections',
                'fix': 'Add HSTS header with appropriate max-age',
                'vuln_type': 'missing_security_headers',
                'explanation': 'HSTS prevents attackers from downgrading HTTPS connections to HTTP, protecting user data from being intercepted.'
            },
            'Referrer-Policy': {
                'severity': 'low',
                'description': 'Controls referrer information leakage',
                'fix': 'Add Referrer-Policy header with strict-origin-when-cross-origin',
                'vuln_type': 'missing_security_headers',
                'explanation': 'Referrer information can leak sensitive data about your users and internal URLs to external websites.'
            },
            'Permissions-Policy': {
                'severity': 'low',
                'description': 'Controls browser feature access',
                'fix': 'Add Permissions-Policy header to restrict features',
                'vuln_type': 'missing_security_headers',
                'explanation': 'Permissions-Policy prevents websites from accessing sensitive browser features like camera, microphone, or geolocation without explicit user consent.'
            }
        }
    
    def should_run(self, mode: str) -> bool:
        """Headers module runs in dynamic and full modes."""
        return mode in ['dynamic', 'full']
    
    async def scan(self, target: str) -> List[Vulnerability]:
        """Scan for HTTP security headers."""
        vulnerabilities = []
        
        if not target.startswith(('http://', 'https://')):
            return vulnerabilities  # Only scan URLs
        
        return await self.scan_url(target)
    
    async def scan_url(self, url: str) -> List[Vulnerability]:
        """Scan a URL for HTTP security headers."""
        vulnerabilities = []
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            ) as session:
                # Test main page
                vulnerabilities.extend(await self._scan_url(session, url))
                
                # Test framework-specific endpoints
                test_endpoints = self._get_framework_endpoints()
                for endpoint in test_endpoints:
                    test_url = urljoin(url, endpoint)
                    endpoint_vulns = await self._scan_url(session, test_url, endpoint)
                    vulnerabilities.extend(endpoint_vulns)
                
        except Exception as e:
            if self.config.verbose:
                print(f"Headers scan error: {e}")
        
        return vulnerabilities
    
    async def _scan_url(self, session, url: str, endpoint: str = "") -> List[Vulnerability]:
        """Scan a specific URL for header issues."""
        vulnerabilities = []
        
        try:
            async with session.get(url) as response:
                headers = response.headers
                
                # Check for missing security headers
                for header_name, header_info in self.required_headers.items():
                    if header_name not in headers:
                        vulnerabilities.append(self.create_vulnerability(
                            title=f"Missing Security Header: {header_name}",
                            description=f"The {header_name} header is missing. {header_info['description']}",
                            severity=header_info['severity'],
                            vuln_type=header_info['vuln_type'],
                            fix=header_info['fix'],
                            reference=f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header_name}",
                            metadata={
                                'url': url,
                                'endpoint': endpoint,
                                'header_name': header_name,
                                'status_code': response.status,
                                'explanation': header_info['explanation']
                            }
                        ))
                
                # Check for insecure header values
                insecure_vulns = await self._check_insecure_headers(headers, url, endpoint)
                vulnerabilities.extend(insecure_vulns)
                
                # Check for information disclosure
                disclosure_vulns = await self._check_information_disclosure(headers, url, endpoint)
                vulnerabilities.extend(disclosure_vulns)
                
        except Exception as e:
            if self.config.verbose:
                print(f"Error scanning {url}: {e}")
        
        return vulnerabilities
    
    async def _check_insecure_headers(self, headers: dict, url: str, endpoint: str = "") -> List[Vulnerability]:
        """Check for insecure header configurations."""
        vulnerabilities = []
        
        # Check Content-Security-Policy
        if 'Content-Security-Policy' in headers:
            csp = headers['Content-Security-Policy'].lower()
            
            if 'unsafe-inline' in csp:
                vulnerabilities.append(self.create_vulnerability(
                    title="Unsafe CSP: unsafe-inline Directive",
                    description="Content Security Policy contains 'unsafe-inline' which allows inline scripts and styles",
                    severity="medium",
                    vuln_type="insecure_configuration",
                    fix="Remove 'unsafe-inline' and use nonces or hashes for inline content",
                    reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
                    metadata={
                        'url': url,
                        'endpoint': endpoint,
                        'csp_value': headers['Content-Security-Policy']
                    }
                ))
            
            if 'unsafe-eval' in csp:
                vulnerabilities.append(self.create_vulnerability(
                    title="Unsafe CSP: unsafe-eval Directive",
                    description="Content Security Policy contains 'unsafe-eval' which allows eval() and similar functions",
                    severity="high",
                    vuln_type="insecure_configuration",
                    fix="Remove 'unsafe-eval' directive from CSP",
                    reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
                    metadata={
                        'url': url,
                        'endpoint': endpoint,
                        'csp_value': headers['Content-Security-Policy']
                    }
                ))
            
            if '*' in csp and 'script-src' in csp:
                vulnerabilities.append(self.create_vulnerability(
                    title="Overly Permissive CSP",
                    description="Content Security Policy uses wildcard (*) in script-src directive",
                    severity="medium",
                    vuln_type="insecure_configuration",
                    fix="Specify explicit domains instead of using wildcards in CSP",
                    reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
                    metadata={
                        'url': url,
                        'endpoint': endpoint,
                        'csp_value': headers['Content-Security-Policy']
                    }
                ))
        
        # Check X-Frame-Options
        if 'X-Frame-Options' in headers:
            frame_options = headers['X-Frame-Options'].lower()
            if frame_options not in ['deny', 'sameorigin']:
                vulnerabilities.append(self.create_vulnerability(
                    title="Weak X-Frame-Options Configuration",
                    description=f"X-Frame-Options is set to '{frame_options}' which may allow clickjacking",
                    severity="medium",
                    vuln_type="insecure_configuration",
                    fix="Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'",
                    reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
                    metadata={
                        'url': url,
                        'endpoint': endpoint,
                        'frame_options_value': headers['X-Frame-Options']
                    }
                ))
        
        # Check HSTS configuration
        if 'Strict-Transport-Security' in headers:
            hsts = headers['Strict-Transport-Security'].lower()
            if 'max-age=' in hsts:
                # Extract max-age value
                import re
                max_age_match = re.search(r'max-age=(\d+)', hsts)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 31536000:  # Less than 1 year
                        vulnerabilities.append(self.create_vulnerability(
                            title="Short HSTS Max-Age",
                            description=f"HSTS max-age is {max_age} seconds, which is less than recommended 1 year",
                            severity="low",
                            vuln_type="insecure_configuration",
                            fix="Increase HSTS max-age to at least 31536000 seconds (1 year)",
                            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
                            metadata={
                                'url': url,
                                'endpoint': endpoint,
                                'hsts_value': headers['Strict-Transport-Security'],
                                'max_age': max_age
                            }
                        ))
        
        return vulnerabilities
    
    async def _check_information_disclosure(self, headers: dict, url: str, endpoint: str = "") -> List[Vulnerability]:
        """Check for information disclosure in headers."""
        vulnerabilities = []
        
        # Check for server information disclosure
        disclosure_headers = {
            'Server': 'web server',
            'X-Powered-By': 'application framework',
            'X-AspNet-Version': 'ASP.NET version',
            'X-AspNetMvc-Version': 'ASP.NET MVC version',
            'X-Generator': 'content generator'
        }
        
        for header, description in disclosure_headers.items():
            if header in headers:
                vulnerabilities.append(self.create_vulnerability(
                    title=f"Information Disclosure: {header} Header",
                    description=f"Server is disclosing {description} information via {header} header",
                    severity="low",
                    vuln_type="insecure_configuration",
                    fix=f"Remove or modify the {header} header to prevent information disclosure",
                    reference="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework",
                    metadata={
                        'url': url,
                        'endpoint': endpoint,
                        'header_name': header,
                        'header_value': headers[header]
                    }
                ))
        
        return vulnerabilities
    
    def _get_framework_endpoints(self) -> List[str]:
        """Get framework-specific endpoints to test."""
        endpoints = []
        
        if self.config.framework == 'nextjs':
            endpoints.extend([
                '/_next/static/chunks/main.js',
                '/_next/image',
                '/api/hello',
                '/_next/webpack-hmr'
            ])
        elif self.config.framework == 'vite':
            endpoints.extend([
                '/@vite/client',
                '/src/main.js',
                '/@fs/',
                '/@id/'
            ])
        elif self.config.framework == 'react':
            endpoints.extend([
                '/static/js/main.js',
                '/static/css/main.css'
            ])
        
        return endpoints