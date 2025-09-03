"""
AI Security Orchestrator

Coordinates all AI-powered security analysis components and provides
a unified interface for intelligent security scanning and analysis.
"""

import asyncio
import time
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import logging

from ..intelligence.threat_intelligence import ThreatIntelligenceEngine, ThreatIndicator
from .code_understanding import CodeUnderstandingEngine, CodeUnderstandingResult
from ..intelligence.behavioral_analyzer import BehavioralAnalyzer, AnomalyDetection
from .security_advisor import SecurityAdvisor, SecurityRecommendation, SecurityStrategy
from ..vulnerability_types import normalize_vulnerability_type, get_vulnerability_type_info

logger = logging.getLogger(__name__)

@dataclass
class AIAnalysisResult:
    """Comprehensive AI analysis result."""
    analysis_id: str
    target: str
    analysis_time: float
    
    # Component results
    threat_assessment: Optional[Dict[str, Any]]  # Threat landscape analysis result
    code_understanding: List[CodeUnderstandingResult]
    anomalies: List[AnomalyDetection]
    recommendations: List[SecurityRecommendation]
    security_strategy: Optional[SecurityStrategy]
    
    # Aggregated insights
    overall_security_score: float  # 0-100
    risk_level: str
    confidence: float
    
    # Summary and insights
    executive_summary: str
    key_findings: List[str]
    priority_actions: List[str]
    
    # Performance metrics
    analysis_duration: float
    components_analyzed: int
    ai_confidence: float
    
    # Metadata
    orchestrator_version: str

class AISecurityOrchestrator:
    """Orchestrates AI-powered security analysis components."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Initialize AI components
        self.threat_intelligence = ThreatIntelligenceEngine()
        self.code_understanding = CodeUnderstandingEngine()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.security_advisor = SecurityAdvisor()
        
        # Analysis configuration
        self.analysis_config = {
            'enable_threat_intelligence': self.config.get('enable_threat_intelligence', True),
            'enable_code_understanding': self.config.get('enable_code_understanding', True),
            'enable_anomaly_detection': self.config.get('enable_anomaly_detection', True),
            'enable_security_advisory': self.config.get('enable_security_advisory', True),
            'parallel_analysis': self.config.get('parallel_analysis', True),
            'max_concurrent_analyses': self.config.get('max_concurrent_analyses', 5),
            'analysis_timeout': self.config.get('analysis_timeout', 300)  # 5 minutes
        }
        
        # Performance tracking
        self.performance_metrics = {
            'total_analyses': 0,
            'successful_analyses': 0,
            'failed_analyses': 0,
            'average_analysis_time': 0.0,
            'component_performance': {
                'threat_intelligence': {'calls': 0, 'avg_time': 0.0, 'success_rate': 0.0},
                'code_understanding': {'calls': 0, 'avg_time': 0.0, 'success_rate': 0.0},
                'anomaly_detection': {'calls': 0, 'avg_time': 0.0, 'success_rate': 0.0},
                'security_advisory': {'calls': 0, 'avg_time': 0.0, 'success_rate': 0.0}
            }
        }
        
        # Analysis history for learning and improvement
        self.analysis_history: List[AIAnalysisResult] = []
        self.max_history_size = self.config.get('max_history_size', 1000)
    
    async def perform_comprehensive_analysis(self, target: str, data: Dict[str, Any], 
                                           context: Dict[str, Any] = None) -> AIAnalysisResult:
        """Perform comprehensive AI-powered security analysis."""
        
        start_time = time.time()
        analysis_id = f"ai_analysis_{target}_{int(start_time)}"
        
        logger.info(f"Starting comprehensive AI analysis: {analysis_id}")
        
        context = context or {}
        
        try:
            # Initialize result structure
            result = AIAnalysisResult(
                analysis_id=analysis_id,
                target=target,
                analysis_time=start_time,
                threat_assessment=None,
                code_understanding=[],
                anomalies=[],
                recommendations=[],
                security_strategy=None,
                overall_security_score=0.0,
                risk_level="unknown",
                confidence=0.0,
                executive_summary="",
                key_findings=[],
                priority_actions=[],
                analysis_duration=0.0,
                components_analyzed=0,
                ai_confidence=0.0,
                orchestrator_version="1.0.0"
            )
            
            # Prepare analysis tasks
            analysis_tasks = []
            
            if self.analysis_config['enable_threat_intelligence']:
                analysis_tasks.append(self._perform_threat_analysis(target, data, context))
            
            if self.analysis_config['enable_code_understanding']:
                analysis_tasks.append(self._perform_code_analysis(target, data, context))
            
            if self.analysis_config['enable_anomaly_detection']:
                analysis_tasks.append(self._perform_anomaly_analysis(target, data, context))
            
            # Execute analysis components
            if self.analysis_config['parallel_analysis']:
                component_results = await self._execute_parallel_analysis(analysis_tasks)
            else:
                component_results = await self._execute_sequential_analysis(analysis_tasks)
            
            # Process component results
            await self._process_component_results(result, component_results)
            
            # Generate security recommendations and strategy
            if self.analysis_config['enable_security_advisory']:
                await self._generate_security_guidance(result, data, context)
            
            # Calculate overall metrics
            await self._calculate_overall_metrics(result)
            
            # Generate executive summary and insights
            await self._generate_executive_insights(result)
            
            # Finalize analysis
            result.analysis_duration = time.time() - start_time
            result.components_analyzed = len([r for r in component_results if r is not None])
            
            # Update performance metrics
            self._update_performance_metrics(result, component_results)
            
            # Store in history
            self._store_analysis_result(result)
            
            logger.info(f"AI analysis completed: {analysis_id} "
                       f"(duration: {result.analysis_duration:.2f}s, "
                       f"score: {result.overall_security_score:.1f})")
            
            return result
            
        except Exception as e:
            logger.error(f"AI analysis failed: {analysis_id} - {str(e)}")
            self.performance_metrics['failed_analyses'] += 1
            raise
    
    async def _perform_threat_analysis(self, target: str, data: Dict[str, Any], 
                                     context: Dict[str, Any]) -> Tuple[str, Any]:
        """Perform threat intelligence analysis."""
        
        component_start = time.time()
        
        try:
            # Prepare threat analysis context
            threat_context = {
                'code_content': data.get('code_content', ''),
                'network_indicators': data.get('network_indicators', []),
                'file_hashes': data.get('file_hashes', []),
                'dependencies': data.get('dependencies', []),
                'exposed_services': data.get('exposed_services', []),
                'is_production': context.get('is_production', False),
                'has_sensitive_data': context.get('has_sensitive_data', False),
                'internet_facing': context.get('internet_facing', False)
            }
            
            assessment = await self.threat_intelligence.get_threat_landscape(timeframe_days=30)
            
            # Update component performance
            component_time = time.time() - component_start
            self._update_component_performance('threat_intelligence', component_time, True)
            
            return ('threat_intelligence', assessment)
            
        except Exception as e:
            logger.error(f"Threat analysis failed for {target}: {str(e)}")
            self._update_component_performance('threat_intelligence', time.time() - component_start, False)
            return ('threat_intelligence', None)
    
    async def _perform_code_analysis(self, target: str, data: Dict[str, Any], 
                                   context: Dict[str, Any]) -> Tuple[str, List[Any]]:
        """Perform code understanding analysis."""
        
        component_start = time.time()
        
        try:
            results = []
            
            # Analyze individual code files
            if 'files' in data:
                for file_info in data['files']:
                    file_path = file_info.get('path', 'unknown')
                    file_content = file_info.get('content', '')
                    
                    if file_content:
                        understanding_result = await self.code_understanding.analyze_code(
                            file_path, file_content, context
                        )
                        results.append(understanding_result)
            
            # Analyze bulk code content if provided
            elif 'code_content' in data:
                understanding_result = await self.code_understanding.analyze_code(
                    target, data['code_content'], context
                )
                results.append(understanding_result)
            
            # Update component performance
            component_time = time.time() - component_start
            self._update_component_performance('code_understanding', component_time, True)
            
            return ('code_understanding', results)
            
        except Exception as e:
            logger.error(f"Code analysis failed for {target}: {str(e)}")
            self._update_component_performance('code_understanding', time.time() - component_start, False)
            return ('code_understanding', [])
    
    async def _perform_anomaly_analysis(self, target: str, data: Dict[str, Any], 
                                      context: Dict[str, Any]) -> Tuple[str, List[Any]]:
        """Perform anomaly detection analysis."""
        
        component_start = time.time()
        
        try:
            # Prepare anomaly detection data
            anomaly_data = {
                'code_content': data.get('code_content', ''),
                'file_size': data.get('file_size', 0),
                'modification_time': data.get('modification_time', time.time()),
                'api_calls': data.get('api_calls', []),
                'errors': data.get('errors', []),
                'execution_times': data.get('execution_times', []),
                'memory_usage': data.get('memory_usage', 0),
                'cpu_usage': data.get('cpu_usage', 0),
                'vulnerabilities': data.get('vulnerabilities', []),
                'change_history': data.get('change_history', []),
                'file_hierarchy': data.get('file_hierarchy', {})
            }
            
            result = await self.behavioral_analyzer.analyze_code_behavior(target, anomaly_data.get('code_content', ''), context)
            anomalies = result.get('anomalies', [])
            
            # Update component performance
            component_time = time.time() - component_start
            self._update_component_performance('anomaly_detection', component_time, True)
            
            return ('anomaly_detection', anomalies)
            
        except Exception as e:
            logger.error(f"Anomaly analysis failed for {target}: {str(e)}")
            self._update_component_performance('anomaly_detection', time.time() - component_start, False)
            return ('anomaly_detection', [])
    
    async def _execute_parallel_analysis(self, tasks: List) -> List[Tuple[str, Any]]:
        """Execute analysis tasks in parallel."""
        
        try:
            # Create semaphore to limit concurrent analyses
            semaphore = asyncio.Semaphore(self.analysis_config['max_concurrent_analyses'])
            
            async def bounded_task(task):
                async with semaphore:
                    return await asyncio.wait_for(task, timeout=self.analysis_config['analysis_timeout'])
            
            # Execute all tasks in parallel
            results = await asyncio.gather(
                *[bounded_task(task) for task in tasks],
                return_exceptions=True
            )
            
            # Filter out exceptions
            valid_results = []
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Parallel analysis task failed: {str(result)}")
                else:
                    valid_results.append(result)
            
            return valid_results
            
        except Exception as e:
            logger.error(f"Parallel analysis execution failed: {str(e)}")
            return []
    
    async def _execute_sequential_analysis(self, tasks: List) -> List[Tuple[str, Any]]:
        """Execute analysis tasks sequentially."""
        
        results = []
        
        for task in tasks:
            try:
                result = await asyncio.wait_for(task, timeout=self.analysis_config['analysis_timeout'])
                results.append(result)
            except Exception as e:
                logger.error(f"Sequential analysis task failed: {str(e)}")
        
        return results
    
    async def _process_component_results(self, result: AIAnalysisResult, 
                                       component_results: List[Tuple[str, Any]]):
        """Process results from analysis components."""
        
        for component_name, component_result in component_results:
            if component_result is None:
                continue
                
            if component_name == 'threat_intelligence':
                result.threat_assessment = component_result
                
            elif component_name == 'code_understanding':
                result.code_understanding = component_result
                
            elif component_name == 'anomaly_detection':
                result.anomalies = component_result
    
    async def _generate_security_guidance(self, result: AIAnalysisResult, 
                                         data: Dict[str, Any], context: Dict[str, Any]):
        """Generate security recommendations and strategy."""
        
        component_start = time.time()
        
        try:
            # Prepare analysis results for advisor
            analysis_results = {
                'vulnerabilities': data.get('vulnerabilities', []),
                'anomalies': [asdict(anomaly) if hasattr(anomaly, '__dataclass_fields__') else anomaly for anomaly in result.anomalies],
                'threat_assessment': result.threat_assessment if isinstance(result.threat_assessment, dict) else (asdict(result.threat_assessment) if result.threat_assessment else {}),
                'code_analysis': [asdict(code_result) if hasattr(code_result, '__dataclass_fields__') else code_result for code_result in result.code_understanding]
            }
            
            # Generate recommendations
            recommendations = await self.security_advisor.generate_recommendations(
                analysis_results, context
            )
            result.recommendations = recommendations
            
            # Generate security strategy
            strategy = await self.security_advisor.create_security_strategy(
                analysis_results, recommendations, context
            )
            result.security_strategy = strategy
            
            # Update component performance
            component_time = time.time() - component_start
            self._update_component_performance('security_advisory', component_time, True)
            
        except Exception as e:
            logger.error(f"Security guidance generation failed: {str(e)}")
            self._update_component_performance('security_advisory', time.time() - component_start, False)
    
    async def _calculate_overall_metrics(self, result: AIAnalysisResult):
        """Calculate overall security metrics."""
        
        # Calculate overall security score
        score_components = []
        
        # Threat assessment contribution
        if result.threat_assessment:
            # Handle both dict and object formats
            if isinstance(result.threat_assessment, dict):
                threat_score = 100 - result.threat_assessment.get('overall_threat_score', 50)
            else:
                threat_score = 100 - getattr(result.threat_assessment, 'overall_threat_score', 50)
            score_components.append(threat_score * 0.4)  # 40% weight
        
        # Code understanding contribution
        if result.code_understanding:
            avg_code_score = sum(r.security_score for r in result.code_understanding) / len(result.code_understanding)
            score_components.append(avg_code_score * 0.3)  # 30% weight
        
        # Anomaly detection contribution
        if result.anomalies:
            # Lower score if critical anomalies found
            critical_anomalies = len([a for a in result.anomalies if a.severity.value == 'critical'])
            high_anomalies = len([a for a in result.anomalies if a.severity.value == 'high'])
            
            anomaly_penalty = critical_anomalies * 20 + high_anomalies * 10
            anomaly_score = max(0, 80 - anomaly_penalty)
            score_components.append(anomaly_score * 0.3)  # 30% weight
        
        # Calculate weighted average
        if score_components:
            result.overall_security_score = sum(score_components) / len(score_components)
        else:
            result.overall_security_score = 50.0  # Default neutral score
        
        # Determine risk level
        if result.overall_security_score >= 80:
            result.risk_level = "low"
        elif result.overall_security_score >= 60:
            result.risk_level = "medium"
        elif result.overall_security_score >= 40:
            result.risk_level = "high"
        else:
            result.risk_level = "critical"
        
        # Calculate overall confidence
        confidence_components = []
        
        if result.threat_assessment:
            # Handle both dict and object formats
            if isinstance(result.threat_assessment, dict):
                confidence_components.append(result.threat_assessment.get('confidence', 0.5))
            else:
                confidence_components.append(getattr(result.threat_assessment, 'confidence', 0.5))
        
        if result.code_understanding:
            avg_code_confidence = sum(r.confidence for r in result.code_understanding) / len(result.code_understanding)
            confidence_components.append(avg_code_confidence)
        
        if result.anomalies:
            avg_anomaly_confidence = sum(a.confidence for a in result.anomalies) / len(result.anomalies)
            confidence_components.append(avg_anomaly_confidence)
        
        if confidence_components:
            result.confidence = sum(confidence_components) / len(confidence_components)
            result.ai_confidence = result.confidence
        else:
            result.confidence = 0.5
            result.ai_confidence = 0.5
    
    async def _generate_executive_insights(self, result: AIAnalysisResult):
        """Generate executive summary and key insights."""
        
        # Generate executive summary
        summary_parts = []
        
        summary_parts.append(f"AI security analysis of {result.target} completed with "
                           f"overall security score of {result.overall_security_score:.1f}/100 "
                           f"({result.risk_level} risk level).")
        
        if result.threat_assessment:
            # Handle both dict and object formats
            if isinstance(result.threat_assessment, dict):
                threat_count = len(result.threat_assessment.get('active_threats', []))
            else:
                threat_count = len(getattr(result.threat_assessment, 'active_threats', []))
            if threat_count > 0:
                summary_parts.append(f"{threat_count} active threats identified requiring immediate attention.")
        
        if result.anomalies:
            critical_anomalies = len([a for a in result.anomalies if a.severity.value == 'critical'])
            if critical_anomalies > 0:
                summary_parts.append(f"{critical_anomalies} critical anomalies detected.")
        
        if result.recommendations:
            critical_recommendations = len([r for r in result.recommendations if r.priority.value == 'critical'])
            summary_parts.append(f"{len(result.recommendations)} security recommendations generated, "
                               f"including {critical_recommendations} critical priority items.")
        
        result.executive_summary = " ".join(summary_parts)
        
        # Generate key findings
        key_findings = []
        
        # Threat findings
        if result.threat_assessment:
            # Handle both dict and object formats
            if isinstance(result.threat_assessment, dict):
                active_threats = result.threat_assessment.get('active_threats', [])
            else:
                active_threats = getattr(result.threat_assessment, 'active_threats', [])
            if active_threats:
                key_findings.append(f"Active threats detected: {len(active_threats)}")
        
        # Code findings
        if result.code_understanding:
            suspicious_code = [r for r in result.code_understanding if r.intent.value in ['suspicious', 'malicious']]
            if suspicious_code:
                key_findings.append(f"Suspicious code patterns found in {len(suspicious_code)} files")
        
        # Anomaly findings
        if result.anomalies:
            high_severity_anomalies = [a for a in result.anomalies if a.severity.value in ['critical', 'high']]
            if high_severity_anomalies:
                key_findings.append(f"High-severity anomalies detected: {len(high_severity_anomalies)}")
        
        # Security posture findings
        if result.overall_security_score < 60:
            key_findings.append("Security posture requires significant improvement")
        elif result.overall_security_score < 80:
            key_findings.append("Security posture has room for improvement")
        else:
            key_findings.append("Strong security posture maintained")
        
        result.key_findings = key_findings
        
        # Generate priority actions
        priority_actions = []
        
        if result.recommendations:
            critical_recs = [r for r in result.recommendations if r.priority.value == 'critical']
            high_recs = [r for r in result.recommendations if r.priority.value == 'high']
            
            for rec in critical_recs[:3]:  # Top 3 critical
                priority_actions.append(rec.title)
            
            for rec in high_recs[:2]:  # Top 2 high priority
                priority_actions.append(rec.title)
        
        if not priority_actions:
            priority_actions = ["Continue monitoring security posture", "Regular security assessments"]
        
        result.priority_actions = priority_actions
    
    def _update_component_performance(self, component: str, execution_time: float, success: bool):
        """Update component performance metrics."""
        
        metrics = self.performance_metrics['component_performance'][component]
        
        metrics['calls'] += 1
        
        # Update average execution time
        if metrics['calls'] == 1:
            metrics['avg_time'] = execution_time
        else:
            metrics['avg_time'] = (metrics['avg_time'] * (metrics['calls'] - 1) + execution_time) / metrics['calls']
        
        # Update success rate
        if success:
            successful_calls = metrics['calls'] * metrics['success_rate'] + 1
        else:
            successful_calls = metrics['calls'] * metrics['success_rate']
        
        metrics['success_rate'] = successful_calls / metrics['calls']
    
    def _update_performance_metrics(self, result: AIAnalysisResult, component_results: List):
        """Update overall performance metrics."""
        
        self.performance_metrics['total_analyses'] += 1
        
        if result.overall_security_score > 0:  # Consider successful if we got some score
            self.performance_metrics['successful_analyses'] += 1
        
        # Update average analysis time
        total_analyses = self.performance_metrics['total_analyses']
        if total_analyses == 1:
            self.performance_metrics['average_analysis_time'] = result.analysis_duration
        else:
            current_avg = self.performance_metrics['average_analysis_time']
            self.performance_metrics['average_analysis_time'] = (
                (current_avg * (total_analyses - 1) + result.analysis_duration) / total_analyses
            )
    
    def _store_analysis_result(self, result: AIAnalysisResult):
        """Store analysis result in history."""
        
        self.analysis_history.append(result)
        
        # Maintain history size limit
        if len(self.analysis_history) > self.max_history_size:
            self.analysis_history = self.analysis_history[-self.max_history_size:]
    
    def get_analysis_history(self, limit: int = 10) -> List[AIAnalysisResult]:
        """Get recent analysis history."""
        
        return self.analysis_history[-limit:]
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics."""
        
        return dict(self.performance_metrics)
    
    def get_component_statistics(self) -> Dict[str, Any]:
        """Get statistics from all AI components."""
        
        return {
            'threat_intelligence': self.threat_intelligence.get_threat_statistics(),
            'code_understanding': self.code_understanding.get_statistics(),
            'anomaly_detection': self.anomaly_detector.get_detector_statistics(),
            'security_advisor': self.security_advisor.get_advisor_statistics(),
            'orchestrator': self.get_performance_metrics()
        }
    
    async def train_from_feedback(self, analysis_id: str, feedback: Dict[str, Any]):
        """Train AI components based on user feedback."""
        
        # Find the analysis result
        analysis_result = None
        for result in self.analysis_history:
            if result.analysis_id == analysis_id:
                analysis_result = result
                break
        
        if not analysis_result:
            logger.warning(f"Analysis result not found for training: {analysis_id}")
            return
        
        # Process feedback for each component
        # This would implement actual machine learning in a real system
        
        logger.info(f"Processed feedback for analysis: {analysis_id}")
    
    async def export_analysis_result(self, analysis_id: str, format: str = 'json') -> str:
        """Export analysis result in specified format."""
        
        # Find the analysis result
        analysis_result = None
        for result in self.analysis_history:
            if result.analysis_id == analysis_id:
                analysis_result = result
                break
        
        if not analysis_result:
            raise ValueError(f"Analysis result not found: {analysis_id}")
        
        if format.lower() == 'json':
            return json.dumps(asdict(analysis_result), indent=2, default=str)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def cleanup_resources(self):
        """Cleanup resources and perform maintenance."""
        
        # Clear old analysis history
        cutoff_time = time.time() - (30 * 24 * 60 * 60)  # 30 days ago
        self.analysis_history = [
            result for result in self.analysis_history 
            if result.analysis_time > cutoff_time
        ]
        
        logger.info("AI orchestrator resources cleaned up")
    
    def enhance_vulnerabilities_with_ai_analysis(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enhance vulnerabilities with AI analysis and standardized types."""
        enhanced_vulnerabilities = []
        
        for vuln_dict in vulnerabilities:
            # Normalize vulnerability type
            vuln_type = vuln_dict.get('vuln_type', '')
            normalized_type = normalize_vulnerability_type(vuln_type)
            
            if normalized_type:
                # Get type information from registry
                type_info = get_vulnerability_type_info(normalized_type)
                if type_info:
                    # Enhance vulnerability with AI analysis context
                    enhanced_vuln = vuln_dict.copy()
                    
                    # Add standardized type information
                    enhanced_vuln['vuln_type'] = normalized_type.value
                    enhanced_vuln['normalized_type'] = normalized_type.value
                    
                    # Add CWE codes and OWASP category
                    if 'metadata' not in enhanced_vuln:
                        enhanced_vuln['metadata'] = {}
                    
                    enhanced_vuln['metadata']['cwe_codes'] = [cwe.value for cwe in type_info.cwe_codes]
                    enhanced_vuln['metadata']['owasp_category'] = type_info.category.value
                    
                    # Add AI analysis context
                    enhanced_vuln['metadata']['ai_analysis'] = {
                        'analyzed': True,
                        'type_normalized': True,
                        'cwe_mapped': True,
                        'owasp_categorized': True,
                        'ai_enhanced': True,
                        'enhancement_timestamp': time.time(),
                        'orchestrator_version': '1.0.0'
                    }
                    
                    # Use registry information for missing fields
                    if not enhanced_vuln.get('fix') and type_info.remediation:
                        enhanced_vuln['fix'] = type_info.remediation
                    if not enhanced_vuln.get('reference') and type_info.references:
                        enhanced_vuln['reference'] = type_info.references[0]
                    if not enhanced_vuln.get('description') and type_info.description:
                        enhanced_vuln['description'] = type_info.description
                    
                    enhanced_vulnerabilities.append(enhanced_vuln)
                else:
                    enhanced_vulnerabilities.append(vuln_dict)
            else:
                enhanced_vulnerabilities.append(vuln_dict)
        
        return enhanced_vulnerabilities
