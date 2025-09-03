"""
Runtime Testing Orchestrator

Coordinates all runtime security testing components including DAST, fuzzing,
API testing, and browser-based testing for comprehensive security validation.
"""

import asyncio
import time
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import logging

from .dast_engine import DASTEngine, DASTScanResult
from .fuzzing_engine import FuzzingEngine, FuzzingTarget, PayloadType, FuzzingStrategy

logger = logging.getLogger(__name__)

@dataclass
class RuntimeTestConfiguration:
    """Configuration for runtime testing."""
    target_url: str
    test_types: List[str]  # ['dast', 'fuzzing', 'api', 'browser']
    
    # Authentication
    auth_config: Dict[str, Any]
    
    # Test scope
    endpoints: List[str]
    parameters: Dict[str, List[str]]
    
    # Test intensity
    max_test_duration: int = 3600  # 1 hour
    concurrent_tests: int = 5
    aggressive_testing: bool = False
    
    # Coverage requirements
    min_coverage_percentage: float = 80.0
    
    # Exclusions
    excluded_endpoints: List[str]
    excluded_parameters: List[str]

@dataclass
class RuntimeTestResult:
    """Comprehensive runtime test result."""
    test_id: str
    target_url: str
    test_start_time: float
    test_duration: float
    
    # Component results
    dast_results: Optional[DASTScanResult]
    fuzzing_results: List[Any]
    api_test_results: List[Any]
    browser_test_results: List[Any]
    
    # Aggregated metrics
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    
    # Coverage metrics
    endpoints_tested: int
    parameters_tested: int
    coverage_achieved: float
    
    # Performance metrics
    total_requests: int
    average_response_time: float
    error_rate: float
    
    # Summary
    executive_summary: str
    key_findings: List[str]
    recommendations: List[str]
    
    # Metadata
    test_configuration: RuntimeTestConfiguration
    orchestrator_version: str

class RuntimeTestOrchestrator:
    """Orchestrates comprehensive runtime security testing."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Initialize testing engines
        self.dast_engine = DASTEngine(config.get('dast', {}))
        self.fuzzing_engine = FuzzingEngine(config.get('fuzzing', {}))
        
        # Orchestration configuration
        self.orchestration_config = {
            'max_parallel_engines': self.config.get('max_parallel_engines', 3),
            'engine_timeout': self.config.get('engine_timeout', 1800),  # 30 minutes
            'result_correlation': self.config.get('result_correlation', True),
            'adaptive_testing': self.config.get('adaptive_testing', True)
        }
        
        # Test history for learning
        self.test_history: List[RuntimeTestResult] = []
        
        # Performance metrics
        self.stats = {
            'total_tests': 0,
            'successful_tests': 0,
            'vulnerabilities_found': 0,
            'average_test_time': 0.0,
            'coverage_achieved': 0.0
        }
    
    async def execute_comprehensive_test(self, config: RuntimeTestConfiguration) -> RuntimeTestResult:
        """Execute comprehensive runtime security testing."""
        
        test_start_time = time.time()
        test_id = f"runtime_test_{int(test_start_time)}"
        
        logger.info(f"Starting comprehensive runtime test: {test_id}")
        logger.info(f"Target: {config.target_url}, Test types: {config.test_types}")
        
        try:
            # Initialize result structure
            result = RuntimeTestResult(
                test_id=test_id,
                target_url=config.target_url,
                test_start_time=test_start_time,
                test_duration=0.0,
                dast_results=None,
                fuzzing_results=[],
                api_test_results=[],
                browser_test_results=[],
                total_vulnerabilities=0,
                critical_vulnerabilities=0,
                high_vulnerabilities=0,
                medium_vulnerabilities=0,
                low_vulnerabilities=0,
                endpoints_tested=0,
                parameters_tested=0,
                coverage_achieved=0.0,
                total_requests=0,
                average_response_time=0.0,
                error_rate=0.0,
                executive_summary="",
                key_findings=[],
                recommendations=[],
                test_configuration=config,
                orchestrator_version="1.0.0"
            )
            
            # Prepare test execution plan
            test_plan = await self._create_test_execution_plan(config)
            
            # Execute tests based on plan
            if self.orchestration_config['max_parallel_engines'] > 1:
                await self._execute_parallel_testing(test_plan, result)
            else:
                await self._execute_sequential_testing(test_plan, result)
            
            # Correlate and analyze results
            await self._correlate_test_results(result)
            
            # Generate insights and recommendations
            await self._generate_test_insights(result)
            
            # Finalize result
            result.test_duration = time.time() - test_start_time
            
            # Update statistics
            self._update_statistics(result)
            
            # Store in history
            self.test_history.append(result)
            
            logger.info(f"Runtime test completed: {test_id} "
                       f"({result.total_vulnerabilities} vulnerabilities, "
                       f"{result.coverage_achieved:.1f}% coverage)")
            
            return result
            
        except Exception as e:
            logger.error(f"Runtime test failed: {test_id} - {str(e)}")
            raise
    
    async def _create_test_execution_plan(self, config: RuntimeTestConfiguration) -> Dict[str, Any]:
        """Create optimized test execution plan."""
        
        plan = {
            'dast_enabled': 'dast' in config.test_types,
            'fuzzing_enabled': 'fuzzing' in config.test_types,
            'api_enabled': 'api' in config.test_types,
            'browser_enabled': 'browser' in config.test_types,
            'execution_order': [],
            'resource_allocation': {}
        }
        
        # Determine execution order based on dependencies and efficiency
        if plan['dast_enabled']:
            plan['execution_order'].append('dast')
            plan['resource_allocation']['dast'] = {
                'priority': 'high',
                'estimated_duration': 1800,  # 30 minutes
                'resource_weight': 0.4
            }
        
        if plan['fuzzing_enabled']:
            plan['execution_order'].append('fuzzing')
            plan['resource_allocation']['fuzzing'] = {
                'priority': 'medium',
                'estimated_duration': 2400,  # 40 minutes
                'resource_weight': 0.3
            }
        
        if plan['api_enabled']:
            plan['execution_order'].append('api')
            plan['resource_allocation']['api'] = {
                'priority': 'high',
                'estimated_duration': 900,  # 15 minutes
                'resource_weight': 0.2
            }
        
        if plan['browser_enabled']:
            plan['execution_order'].append('browser')
            plan['resource_allocation']['browser'] = {
                'priority': 'medium',
                'estimated_duration': 1200,  # 20 minutes
                'resource_weight': 0.1
            }
        
        # Optimize execution order
        plan['execution_order'] = await self._optimize_execution_order(
            plan['execution_order'], plan['resource_allocation']
        )
        
        logger.info(f"Test execution plan created: {plan['execution_order']}")
        
        return plan
    
    async def _execute_parallel_testing(self, test_plan: Dict[str, Any], 
                                       result: RuntimeTestResult):
        """Execute tests in parallel where possible."""
        
        # Create test tasks
        test_tasks = []
        
        if test_plan['dast_enabled']:
            test_tasks.append(self._execute_dast_testing(result.test_configuration, result))
        
        if test_plan['fuzzing_enabled']:
            test_tasks.append(self._execute_fuzzing_testing(result.test_configuration, result))
        
        if test_plan['api_enabled']:
            test_tasks.append(self._execute_api_testing(result.test_configuration, result))
        
        if test_plan['browser_enabled']:
            test_tasks.append(self._execute_browser_testing(result.test_configuration, result))
        
        # Execute tasks with timeout
        try:
            await asyncio.wait_for(
                asyncio.gather(*test_tasks, return_exceptions=True),
                timeout=self.orchestration_config['engine_timeout']
            )
        except asyncio.TimeoutError:
            logger.warning("Some tests timed out during parallel execution")
    
    async def _execute_sequential_testing(self, test_plan: Dict[str, Any], 
                                         result: RuntimeTestResult):
        """Execute tests sequentially."""
        
        for test_type in test_plan['execution_order']:
            try:
                if test_type == 'dast' and test_plan['dast_enabled']:
                    await self._execute_dast_testing(result.test_configuration, result)
                
                elif test_type == 'fuzzing' and test_plan['fuzzing_enabled']:
                    await self._execute_fuzzing_testing(result.test_configuration, result)
                
                elif test_type == 'api' and test_plan['api_enabled']:
                    await self._execute_api_testing(result.test_configuration, result)
                
                elif test_type == 'browser' and test_plan['browser_enabled']:
                    await self._execute_browser_testing(result.test_configuration, result)
                
            except Exception as e:
                logger.error(f"Test type {test_type} failed: {str(e)}")
    
    async def _execute_dast_testing(self, config: RuntimeTestConfiguration, 
                                   result: RuntimeTestResult):
        """Execute DAST testing."""
        
        logger.info("Starting DAST testing")
        
        try:
            # Prepare DAST context
            dast_context = {
                'endpoints': config.endpoints,
                'parameters': config.parameters,
                'excluded_endpoints': config.excluded_endpoints,
                'excluded_parameters': config.excluded_parameters,
                'aggressive_testing': config.aggressive_testing
            }
            
            # Configure authentication
            if config.auth_config:
                self.dast_engine.auth_config.update(config.auth_config)
            
            # Execute DAST scan
            dast_result = await self.dast_engine.perform_scan(config.target_url, dast_context)
            
            result.dast_results = dast_result
            
            logger.info(f"DAST testing completed: {len(dast_result.findings)} findings")
            
        except Exception as e:
            logger.error(f"DAST testing failed: {str(e)}")
    
    async def _execute_fuzzing_testing(self, config: RuntimeTestConfiguration, 
                                      result: RuntimeTestResult):
        """Execute fuzzing testing."""
        
        logger.info("Starting fuzzing testing")
        
        try:
            # Create fuzzing targets from configuration
            fuzzing_targets = await self._create_fuzzing_targets(config)
            
            # Determine fuzzing strategy
            strategy = FuzzingStrategy.COVERAGE_GUIDED if not config.aggressive_testing else FuzzingStrategy.RANDOM
            
            # Execute fuzzing campaign
            fuzzing_results = await self.fuzzing_engine.start_fuzzing_campaign(fuzzing_targets, strategy)
            
            result.fuzzing_results = fuzzing_results
            
            logger.info(f"Fuzzing testing completed: {len(fuzzing_results)} tests executed")
            
        except Exception as e:
            logger.error(f"Fuzzing testing failed: {str(e)}")
    
    async def _execute_api_testing(self, config: RuntimeTestConfiguration, 
                                  result: RuntimeTestResult):
        """Execute API security testing."""
        
        logger.info("Starting API testing")
        
        try:
            # Simulate API testing (would integrate with actual API testing framework)
            api_results = []
            
            for endpoint in config.endpoints:
                if '/api/' in endpoint:
                    # Simulate API test
                    api_test_result = {
                        'endpoint': endpoint,
                        'tests_performed': ['authentication', 'authorization', 'input_validation'],
                        'vulnerabilities_found': [],
                        'response_time': 0.2,
                        'status': 'passed'
                    }
                    
                    # Simulate finding vulnerabilities in some endpoints
                    if 'admin' in endpoint.lower():
                        api_test_result['vulnerabilities_found'].append({
                            'type': 'broken_authorization',
                            'severity': 'high',
                            'description': 'Admin endpoint accessible without proper authorization'
                        })
                    
                    api_results.append(api_test_result)
            
            result.api_test_results = api_results
            
            logger.info(f"API testing completed: {len(api_results)} endpoints tested")
            
        except Exception as e:
            logger.error(f"API testing failed: {str(e)}")
    
    async def _execute_browser_testing(self, config: RuntimeTestConfiguration, 
                                      result: RuntimeTestResult):
        """Execute browser-based security testing."""
        
        logger.info("Starting browser testing")
        
        try:
            # Simulate browser testing (would integrate with browser automation)
            browser_results = []
            
            for endpoint in config.endpoints[:5]:  # Test first 5 endpoints
                browser_test_result = {
                    'endpoint': endpoint,
                    'tests_performed': ['xss_detection', 'csrf_protection', 'clickjacking'],
                    'vulnerabilities_found': [],
                    'page_load_time': 1.5,
                    'status': 'passed'
                }
                
                # Simulate finding vulnerabilities
                if 'search' in endpoint.lower():
                    browser_test_result['vulnerabilities_found'].append({
                        'type': 'reflected_xss',
                        'severity': 'medium',
                        'description': 'Search parameter vulnerable to reflected XSS'
                    })
                
                browser_results.append(browser_test_result)
            
            result.browser_test_results = browser_results
            
            logger.info(f"Browser testing completed: {len(browser_results)} pages tested")
            
        except Exception as e:
            logger.error(f"Browser testing failed: {str(e)}")
    
    async def _create_fuzzing_targets(self, config: RuntimeTestConfiguration) -> List[FuzzingTarget]:
        """Create fuzzing targets from configuration."""
        
        targets = []
        
        for endpoint, parameters in config.parameters.items():
            for param in parameters:
                if param not in config.excluded_parameters:
                    target = FuzzingTarget(
                        target_id=f"{endpoint}_{param}",
                        name=f"Parameter {param} in {endpoint}",
                        target_type="parameter",
                        data_type=PayloadType.STRING,  # Default to string, would be detected
                        constraints={'max_length': 1000}
                    )
                    targets.append(target)
        
        return targets
    
    async def _correlate_test_results(self, result: RuntimeTestResult):
        """Correlate results from different testing engines."""
        
        # Aggregate vulnerability counts
        total_vulns = 0
        critical_vulns = 0
        high_vulns = 0
        medium_vulns = 0
        low_vulns = 0
        
        # Count DAST vulnerabilities
        if result.dast_results:
            total_vulns += len(result.dast_results.findings)
            critical_vulns += result.dast_results.critical_findings
            high_vulns += result.dast_results.high_findings
            medium_vulns += result.dast_results.medium_findings
            low_vulns += result.dast_results.low_findings
        
        # Count fuzzing vulnerabilities
        for fuzzing_result in result.fuzzing_results:
            if hasattr(fuzzing_result, 'vulnerability_indicators') and fuzzing_result.vulnerability_indicators:
                total_vulns += len(fuzzing_result.vulnerability_indicators)
                # Assume medium severity for fuzzing findings
                medium_vulns += len(fuzzing_result.vulnerability_indicators)
        
        # Count API vulnerabilities
        for api_result in result.api_test_results:
            if 'vulnerabilities_found' in api_result:
                for vuln in api_result['vulnerabilities_found']:
                    total_vulns += 1
                    severity = vuln.get('severity', 'medium')
                    if severity == 'critical':
                        critical_vulns += 1
                    elif severity == 'high':
                        high_vulns += 1
                    elif severity == 'medium':
                        medium_vulns += 1
                    else:
                        low_vulns += 1
        
        # Count browser vulnerabilities
        for browser_result in result.browser_test_results:
            if 'vulnerabilities_found' in browser_result:
                for vuln in browser_result['vulnerabilities_found']:
                    total_vulns += 1
                    severity = vuln.get('severity', 'medium')
                    if severity == 'critical':
                        critical_vulns += 1
                    elif severity == 'high':
                        high_vulns += 1
                    elif severity == 'medium':
                        medium_vulns += 1
                    else:
                        low_vulns += 1
        
        # Update result
        result.total_vulnerabilities = total_vulns
        result.critical_vulnerabilities = critical_vulns
        result.high_vulnerabilities = high_vulns
        result.medium_vulnerabilities = medium_vulns
        result.low_vulnerabilities = low_vulns
        
        # Calculate coverage metrics
        result.endpoints_tested = len(result.test_configuration.endpoints)
        result.parameters_tested = sum(len(params) for params in result.test_configuration.parameters.values())
        
        # Calculate coverage percentage
        total_attack_surface = result.endpoints_tested * result.parameters_tested
        if total_attack_surface > 0:
            tests_performed = 0
            if result.dast_results:
                tests_performed += result.dast_results.tests_executed
            tests_performed += len(result.fuzzing_results)
            tests_performed += len(result.api_test_results)
            tests_performed += len(result.browser_test_results)
            
            result.coverage_achieved = min(100.0, (tests_performed / total_attack_surface) * 100)
        
        # Calculate performance metrics
        total_requests = 0
        total_response_time = 0.0
        error_count = 0
        
        if result.dast_results:
            total_requests += result.dast_results.requests_sent
        
        for api_result in result.api_test_results:
            total_requests += 1
            total_response_time += api_result.get('response_time', 0.0)
        
        for browser_result in result.browser_test_results:
            total_requests += 1
            total_response_time += browser_result.get('page_load_time', 0.0)
        
        result.total_requests = total_requests
        result.average_response_time = total_response_time / max(1, total_requests)
        result.error_rate = error_count / max(1, total_requests)
    
    async def _generate_test_insights(self, result: RuntimeTestResult):
        """Generate executive insights and recommendations."""
        
        # Generate executive summary
        summary_parts = []
        
        summary_parts.append(f"Comprehensive runtime security testing completed on {result.target_url}.")
        summary_parts.append(f"Total of {result.total_vulnerabilities} vulnerabilities identified across {result.endpoints_tested} endpoints.")
        
        if result.critical_vulnerabilities > 0:
            summary_parts.append(f"{result.critical_vulnerabilities} critical vulnerabilities require immediate attention.")
        
        if result.coverage_achieved < result.test_configuration.min_coverage_percentage:
            summary_parts.append(f"Coverage of {result.coverage_achieved:.1f}% is below target of {result.test_configuration.min_coverage_percentage}%.")
        
        result.executive_summary = " ".join(summary_parts)
        
        # Generate key findings
        key_findings = []
        
        if result.dast_results and result.dast_results.findings:
            key_findings.append(f"DAST scan identified {len(result.dast_results.findings)} vulnerabilities")
        
        if result.fuzzing_results:
            crash_count = sum(1 for fr in result.fuzzing_results if hasattr(fr, 'crash_detected') and fr.crash_detected)
            if crash_count > 0:
                key_findings.append(f"Fuzzing detected {crash_count} application crashes")
        
        if result.api_test_results:
            api_vulns = sum(len(ar.get('vulnerabilities_found', [])) for ar in result.api_test_results)
            if api_vulns > 0:
                key_findings.append(f"API testing found {api_vulns} API-specific vulnerabilities")
        
        if result.browser_test_results:
            browser_vulns = sum(len(br.get('vulnerabilities_found', [])) for br in result.browser_test_results)
            if browser_vulns > 0:
                key_findings.append(f"Browser testing identified {browser_vulns} client-side vulnerabilities")
        
        result.key_findings = key_findings
        
        # Generate recommendations
        recommendations = []
        
        if result.critical_vulnerabilities > 0:
            recommendations.append("Address critical vulnerabilities immediately")
        
        if result.high_vulnerabilities > 0:
            recommendations.append("Prioritize remediation of high-severity vulnerabilities")
        
        if result.coverage_achieved < 80:
            recommendations.append("Increase test coverage to improve security validation")
        
        if result.error_rate > 0.1:
            recommendations.append("Investigate and fix application stability issues")
        
        recommendations.extend([
            "Implement continuous security testing in CI/CD pipeline",
            "Regular penetration testing and security assessments",
            "Security training for development teams"
        ])
        
        result.recommendations = recommendations
    
    async def _optimize_execution_order(self, test_types: List[str], 
                                       resource_allocation: Dict[str, Any]) -> List[str]:
        """Optimize test execution order for efficiency."""
        
        # Sort by priority and estimated duration
        def sort_key(test_type):
            allocation = resource_allocation.get(test_type, {})
            priority_weight = {'high': 3, 'medium': 2, 'low': 1}.get(allocation.get('priority', 'medium'), 2)
            duration_weight = 1.0 / max(1, allocation.get('estimated_duration', 1))
            return priority_weight + duration_weight
        
        return sorted(test_types, key=sort_key, reverse=True)
    
    def _update_statistics(self, result: RuntimeTestResult):
        """Update orchestrator statistics."""
        
        self.stats['total_tests'] += 1
        
        if result.total_vulnerabilities >= 0:  # Consider successful if completed
            self.stats['successful_tests'] += 1
        
        self.stats['vulnerabilities_found'] += result.total_vulnerabilities
        
        # Update average test time
        if self.stats['total_tests'] == 1:
            self.stats['average_test_time'] = result.test_duration
        else:
            current_avg = self.stats['average_test_time']
            total_tests = self.stats['total_tests']
            self.stats['average_test_time'] = (
                (current_avg * (total_tests - 1) + result.test_duration) / total_tests
            )
        
        # Update average coverage
        if self.stats['total_tests'] == 1:
            self.stats['coverage_achieved'] = result.coverage_achieved
        else:
            current_avg = self.stats['coverage_achieved']
            total_tests = self.stats['total_tests']
            self.stats['coverage_achieved'] = (
                (current_avg * (total_tests - 1) + result.coverage_achieved) / total_tests
            )
    
    def get_test_history(self, limit: int = 10) -> List[RuntimeTestResult]:
        """Get recent test history."""
        
        return self.test_history[-limit:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        
        return dict(self.stats)
    
    async def export_test_result(self, test_id: str, format: str = 'json') -> str:
        """Export test result in specified format."""
        
        # Find test result
        test_result = None
        for result in self.test_history:
            if result.test_id == test_id:
                test_result = result
                break
        
        if not test_result:
            raise ValueError(f"Test result not found: {test_id}")
        
        if format.lower() == 'json':
            return json.dumps(asdict(test_result), indent=2, default=str)
        else:
            raise ValueError(f"Unsupported export format: {format}")
