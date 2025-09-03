"""
Behavioral Analysis Engine

Advanced behavioral analysis for detecting sophisticated attack patterns:
- Code flow analysis and execution path tracking
- Anomaly detection in application behavior
- Pattern recognition for attack sequences
- Machine learning-based behavior modeling
- Temporal analysis and time-series patterns
- Context-aware behavioral signatures
- Advanced persistent threat (APT) detection
"""

import asyncio
import time
import ast
import re
import json
from typing import Dict, List, Any, Optional, Union, Set, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging
from collections import defaultdict, deque
import numpy as np
import statistics
from datetime import datetime, timedelta
import hashlib

# Import vulnerability type system
from ..vulnerability_types import normalize_vulnerability_type, get_vulnerability_type_info

logger = logging.getLogger(__name__)

class BehaviorType(Enum):
    """Types of behavioral patterns."""
    EXECUTION_FLOW = "execution_flow"
    DATA_ACCESS = "data_access"
    NETWORK_COMMUNICATION = "network_communication"
    FILE_OPERATIONS = "file_operations"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    EVASION = "evasion"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"
    COMMAND_EXECUTION = "command_execution"

class AnomalyType(Enum):
    """Types of behavioral anomalies."""
    STATISTICAL = "statistical"
    PATTERN_DEVIATION = "pattern_deviation"
    FREQUENCY = "frequency"
    SEQUENCE = "sequence"
    TEMPORAL = "temporal"
    CONTEXTUAL = "contextual"

class AnalysisScope(Enum):
    """Scope of behavioral analysis."""
    FUNCTION_LEVEL = "function_level"
    FILE_LEVEL = "file_level"
    MODULE_LEVEL = "module_level"
    APPLICATION_LEVEL = "application_level"
    CROSS_APPLICATION = "cross_application"

@dataclass
class BehaviorSignature:
    """Behavioral signature definition."""
    signature_id: str
    name: str
    description: str
    behavior_type: BehaviorType
    
    # Pattern definition
    pattern_elements: List[str] = field(default_factory=list)
    sequence_patterns: List[List[str]] = field(default_factory=list)
    temporal_constraints: Dict[str, Any] = field(default_factory=dict)
    
    # Matching criteria
    minimum_confidence: float = 0.7
    minimum_elements: int = 3
    allow_partial_match: bool = True
    
    # Context requirements
    required_context: Dict[str, Any] = field(default_factory=dict)
    excluded_context: Dict[str, Any] = field(default_factory=dict)
    
    # Threat information
    threat_level: str = "medium"
    mitre_techniques: Set[str] = field(default_factory=set)
    attack_categories: Set[str] = field(default_factory=set)
    
    # Performance metrics
    false_positive_rate: float = 0.0
    detection_accuracy: float = 1.0
    computational_cost: float = 1.0
    
    # Metadata
    created_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    match_count: int = 0
    
    def calculate_effectiveness(self) -> float:
        """Calculate signature effectiveness score."""
        accuracy_score = self.detection_accuracy
        fp_penalty = 1.0 - self.false_positive_rate
        usage_bonus = min(1.0, self.match_count / 100.0) * 0.1
        
        return (accuracy_score * fp_penalty) + usage_bonus

@dataclass
class BehaviorEvent:
    """Individual behavioral event."""
    event_id: str
    event_type: str
    timestamp: float
    
    # Event data
    source_location: str = ""  # File path, line number
    function_name: str = ""
    operation: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    
    # Context
    execution_context: Dict[str, Any] = field(default_factory=dict)
    data_flow_context: Dict[str, Any] = field(default_factory=dict)
    
    # Analysis results
    risk_score: float = 0.0
    anomaly_indicators: List[str] = field(default_factory=list)
    related_events: List[str] = field(default_factory=list)

@dataclass
class BehaviorSequence:
    """Sequence of related behavioral events."""
    sequence_id: str
    events: List[BehaviorEvent] = field(default_factory=list)
    
    # Sequence properties
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    duration: Optional[float] = None
    
    # Pattern matching
    matched_signatures: List[str] = field(default_factory=list)
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    
    # Risk assessment
    overall_risk_score: float = 0.0
    threat_indicators: List[str] = field(default_factory=list)
    
    def add_event(self, event: BehaviorEvent):
        """Add event to sequence."""
        self.events.append(event)
        
        # Update timing
        if not self.start_time or event.timestamp < self.start_time:
            self.start_time = event.timestamp
        if not self.end_time or event.timestamp > self.end_time:
            self.end_time = event.timestamp
        
        if self.start_time and self.end_time:
            self.duration = self.end_time - self.start_time

@dataclass
class AnomalyDetection:
    """Anomaly detection result."""
    anomaly_id: str
    anomaly_type: AnomalyType
    description: str
    
    # Anomaly details
    detected_value: Any
    expected_range: Tuple[Any, Any] = (None, None)
    deviation_score: float = 0.0
    confidence: float = 0.0
    
    # Context
    source_location: str = ""
    detection_time: float = field(default_factory=time.time)
    related_events: List[str] = field(default_factory=list)
    
    # Severity
    severity: str = "medium"
    impact_assessment: str = ""
    
    # False positive indicators
    false_positive_likelihood: float = 0.0
    validation_status: str = "pending"  # pending, confirmed, false_positive

@dataclass
class BehavioralAnalysisConfig:
    """Configuration for behavioral analysis engine."""
    
    # Analysis scope
    enable_function_analysis: bool = True
    enable_file_analysis: bool = True
    enable_cross_file_analysis: bool = True
    enable_temporal_analysis: bool = True
    
    # Event detection
    track_function_calls: bool = True
    track_data_access: bool = True
    track_network_operations: bool = True
    track_file_operations: bool = True
    track_execution_flow: bool = True
    
    # Anomaly detection
    enable_statistical_anomalies: bool = True
    enable_pattern_anomalies: bool = True
    enable_frequency_anomalies: bool = True
    enable_sequence_anomalies: bool = True
    
    # Thresholds
    anomaly_threshold: float = 0.7
    sequence_timeout_seconds: float = 300.0
    minimum_sequence_length: int = 3
    maximum_sequence_length: int = 100
    
    # Machine learning
    enable_ml_behavior_modeling: bool = True
    model_update_interval: int = 86400  # 24 hours
    training_data_size: int = 10000
    feature_extraction_enabled: bool = True
    
    # Performance
    max_concurrent_analyses: int = 10
    analysis_timeout_seconds: float = 60.0
    enable_caching: bool = True
    cache_ttl_seconds: int = 3600
    
    # Storage
    event_retention_days: int = 30
    sequence_retention_days: int = 90
    anomaly_retention_days: int = 180
    enable_persistent_storage: bool = True
    
    # Signature management
    enable_custom_signatures: bool = True
    signature_auto_tuning: bool = True
    signature_effectiveness_threshold: float = 0.6
    
    # Context analysis
    context_window_size: int = 50
    enable_deep_context_analysis: bool = True
    cross_reference_external_intel: bool = True

class BehavioralAnalyzer:
    """Advanced behavioral analysis engine."""
    
    def __init__(self, config: BehavioralAnalysisConfig = None):
        self.config = config or BehavioralAnalysisConfig()
        
        # Event storage and tracking
        self.events: Dict[str, BehaviorEvent] = {}
        self.sequences: Dict[str, BehaviorSequence] = {}
        self.active_sequences: Dict[str, BehaviorSequence] = {}
        
        # Signatures and patterns
        self.signatures: Dict[str, BehaviorSignature] = {}
        self.pattern_matcher = PatternMatcher(self.config)
        
        # Anomaly detection
        self.anomaly_detectors: Dict[AnomalyType, 'AnomalyDetector'] = {}
        self.detected_anomalies: Dict[str, AnomalyDetection] = {}
        
        # Analysis engines
        self.execution_analyzer = ExecutionFlowAnalyzer(self.config)
        self.data_flow_analyzer = DataFlowAnalyzer(self.config)
        self.temporal_analyzer = TemporalAnalyzer(self.config)
        
        # Machine learning components
        if self.config.enable_ml_behavior_modeling:
            self.behavior_modeler = BehaviorModeler(self.config)
            self.feature_extractor = BehaviorFeatureExtractor(self.config)
        else:
            self.behavior_modeler = None
            self.feature_extractor = None
        
        # Context and correlation
        self.context_analyzer = BehaviorContextAnalyzer(self.config)
        self.correlation_engine = BehaviorCorrelationEngine(self.config)
        
        # Background processing
        self.background_tasks: List[asyncio.Task] = []
        self.running = False
        self.shutdown_event = asyncio.Event()
        
        # Statistics
        self.stats = {
            'events_processed': 0,
            'sequences_created': 0,
            'anomalies_detected': 0,
            'signatures_matched': 0,
            'false_positives_filtered': 0,
            'analysis_time_total': 0.0,
            'average_analysis_time': 0.0
        }
        
        self.start_time = time.time()
    
    async def initialize(self):
        """Initialize behavioral analysis engine."""
        
        logger.info("Initializing Behavioral Analysis Engine")
        
        self.running = True
        
        # Initialize components
        await self.pattern_matcher.initialize()
        await self.execution_analyzer.initialize()
        await self.data_flow_analyzer.initialize()
        await self.temporal_analyzer.initialize()
        await self.context_analyzer.initialize()
        await self.correlation_engine.initialize()
        
        # Initialize anomaly detectors
        self.anomaly_detectors[AnomalyType.STATISTICAL] = StatisticalAnomalyDetector(self.config)
        self.anomaly_detectors[AnomalyType.PATTERN_DEVIATION] = PatternDeviationDetector(self.config)
        self.anomaly_detectors[AnomalyType.FREQUENCY] = FrequencyAnomalyDetector(self.config)
        self.anomaly_detectors[AnomalyType.SEQUENCE] = SequenceAnomalyDetector(self.config)
        self.anomaly_detectors[AnomalyType.TEMPORAL] = TemporalAnomalyDetector(self.config)
        self.anomaly_detectors[AnomalyType.CONTEXTUAL] = ContextualAnomalyDetector(self.config)
        
        for detector in self.anomaly_detectors.values():
            await detector.initialize()
        
        # Initialize ML components
        if self.behavior_modeler:
            await self.behavior_modeler.initialize()
            await self.feature_extractor.initialize()
        
        # Load built-in signatures
        await self._load_builtin_signatures()
        
        # Start background tasks
        self.background_tasks = [
            asyncio.create_task(self._sequence_processing_worker()),
            asyncio.create_task(self._anomaly_detection_worker()),
            asyncio.create_task(self._cleanup_worker())
        ]
        
        if self.config.enable_ml_behavior_modeling:
            self.background_tasks.append(
                asyncio.create_task(self._ml_training_worker())
            )
        
        logger.info(f"Behavioral Analysis Engine initialized with {len(self.signatures)} signatures")
    
    async def analyze_code_behavior(self, file_path: str, content: str, 
                                  context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze code for behavioral patterns and anomalies."""
        
        analysis_start = time.time()
        
        try:
            context = context or {}
            results = {
                'file_path': file_path,
                'analysis_timestamp': time.time(),
                'events': [],
                'sequences': [],
                'anomalies': [],
                'signature_matches': [],
                'risk_assessment': {
                    'overall_risk_score': 0.0,
                    'threat_indicators': [],
                    'recommendations': []
                }
            }
            
            # Extract behavioral events from code
            events = await self._extract_behavioral_events(file_path, content, context)
            results['events'] = [self._serialize_event(event) for event in events]
            
            # Store events
            for event in events:
                self.events[event.event_id] = event
            
            # Analyze execution flow
            if self.config.enable_function_analysis:
                flow_analysis = await self.execution_analyzer.analyze_flow(content, events, context)
                results['execution_flow'] = flow_analysis
            
            # Analyze data flow
            data_flow_analysis = await self.data_flow_analyzer.analyze_flow(content, events, context)
            results['data_flow'] = data_flow_analysis
            
            # Create and analyze sequences
            sequences = await self._create_behavior_sequences(events)
            results['sequences'] = [self._serialize_sequence(seq) for seq in sequences]
            
            # Pattern matching against signatures
            signature_matches = await self._match_signatures(events, sequences, context)
            results['signature_matches'] = signature_matches
            
            # Anomaly detection
            anomalies = await self._detect_anomalies(events, sequences, context)
            results['anomalies'] = [self._serialize_anomaly(anomaly) for anomaly in anomalies]
            
            # Risk assessment
            risk_assessment = await self._assess_risk(events, sequences, signature_matches, anomalies)
            results['risk_assessment'] = risk_assessment
            
            # ML-based analysis
            if self.behavior_modeler:
                ml_analysis = await self.behavior_modeler.analyze_behavior(events, sequences, context)
                results['ml_analysis'] = ml_analysis
            
            # Update statistics
            analysis_time = time.time() - analysis_start
            self.stats['events_processed'] += len(events)
            self.stats['sequences_created'] += len(sequences)
            self.stats['anomalies_detected'] += len(anomalies)
            self.stats['signatures_matched'] += len(signature_matches)
            self.stats['analysis_time_total'] += analysis_time
            
            if self.stats['events_processed'] > 0:
                self.stats['average_analysis_time'] = (
                    self.stats['analysis_time_total'] / self.stats['events_processed']
                )
            
            logger.debug(f"Behavioral analysis completed for {file_path}: "
                        f"{len(events)} events, {len(sequences)} sequences, "
                        f"{len(anomalies)} anomalies ({analysis_time:.3f}s)")
            
            return results
            
        except Exception as e:
            logger.error(f"Behavioral analysis error for {file_path}: {str(e)}")
            return {
                'file_path': file_path,
                'error': str(e),
                'analysis_timestamp': time.time()
            }
    
    async def add_custom_signature(self, signature: BehaviorSignature) -> bool:
        """Add custom behavioral signature."""
        
        try:
            # Validate signature
            if not await self._validate_signature(signature):
                logger.error(f"Signature validation failed: {signature.signature_id}")
                return False
            
            # Store signature
            self.signatures[signature.signature_id] = signature
            
            logger.info(f"Added custom behavioral signature: {signature.signature_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add custom signature: {str(e)}")
            return False
    
    async def get_behavior_profile(self, target: str, 
                                 profile_type: str = "file") -> Dict[str, Any]:
        """Get behavioral profile for a target (file, function, etc.)."""
        
        try:
            # Filter events for target
            target_events = [
                event for event in self.events.values()
                if self._event_matches_target(event, target, profile_type)
            ]
            
            if not target_events:
                return {'target': target, 'profile_type': profile_type, 'events': 0}
            
            # Calculate behavioral metrics
            behavior_metrics = await self._calculate_behavior_metrics(target_events)
            
            # Pattern analysis
            patterns = await self._analyze_behavior_patterns(target_events)
            
            # Anomaly summary
            target_anomalies = [
                anomaly for anomaly in self.detected_anomalies.values()
                if target in anomaly.source_location
            ]
            
            profile = {
                'target': target,
                'profile_type': profile_type,
                'analysis_period': {
                    'start': min(event.timestamp for event in target_events),
                    'end': max(event.timestamp for event in target_events),
                    'duration': max(event.timestamp for event in target_events) - 
                              min(event.timestamp for event in target_events)
                },
                'event_summary': {
                    'total_events': len(target_events),
                    'event_types': list(set(event.event_type for event in target_events)),
                    'unique_operations': list(set(event.operation for event in target_events))
                },
                'behavior_metrics': behavior_metrics,
                'patterns': patterns,
                'anomalies': len(target_anomalies),
                'risk_indicators': await self._get_risk_indicators(target_events),
                'recommendations': await self._generate_recommendations(target_events, target_anomalies)
            }
            
            return profile
            
        except Exception as e:
            logger.error(f"Failed to get behavior profile: {str(e)}")
            return {'error': str(e)}
    
    async def detect_apt_behavior(self, events: List[BehaviorEvent], 
                                context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Detect Advanced Persistent Threat (APT) behavioral patterns."""
        
        try:
            context = context or {}
            
            apt_indicators = {
                'persistence_mechanisms': [],
                'lateral_movement': [],
                'privilege_escalation': [],
                'data_exfiltration': [],
                'command_and_control': [],
                'evasion_techniques': [],
                'overall_apt_score': 0.0,
                'threat_assessment': 'low'
            }
            
            # Analyze for APT-specific patterns
            
            # 1. Persistence mechanisms
            persistence_events = [
                event for event in events
                if self._is_persistence_behavior(event)
            ]
            apt_indicators['persistence_mechanisms'] = [
                self._serialize_event(event) for event in persistence_events
            ]
            
            # 2. Lateral movement indicators
            lateral_movement_events = [
                event for event in events
                if self._is_lateral_movement_behavior(event)
            ]
            apt_indicators['lateral_movement'] = [
                self._serialize_event(event) for event in lateral_movement_events
            ]
            
            # 3. Privilege escalation
            privilege_escalation_events = [
                event for event in events
                if self._is_privilege_escalation_behavior(event)
            ]
            apt_indicators['privilege_escalation'] = [
                self._serialize_event(event) for event in privilege_escalation_events
            ]
            
            # 4. Data exfiltration patterns
            exfiltration_events = [
                event for event in events
                if self._is_exfiltration_behavior(event)
            ]
            apt_indicators['data_exfiltration'] = [
                self._serialize_event(event) for event in exfiltration_events
            ]
            
            # 5. Command and control
            c2_events = [
                event for event in events
                if self._is_c2_behavior(event)
            ]
            apt_indicators['command_and_control'] = [
                self._serialize_event(event) for event in c2_events
            ]
            
            # 6. Evasion techniques
            evasion_events = [
                event for event in events
                if self._is_evasion_behavior(event)
            ]
            apt_indicators['evasion_techniques'] = [
                self._serialize_event(event) for event in evasion_events
            ]
            
            # Calculate overall APT score
            category_scores = {
                'persistence': len(persistence_events) * 0.2,
                'lateral_movement': len(lateral_movement_events) * 0.25,
                'privilege_escalation': len(privilege_escalation_events) * 0.3,
                'data_exfiltration': len(exfiltration_events) * 0.35,
                'command_and_control': len(c2_events) * 0.25,
                'evasion': len(evasion_events) * 0.15
            }
            
            apt_indicators['overall_apt_score'] = min(1.0, sum(category_scores.values()) / 6.0)
            
            # Threat assessment
            if apt_indicators['overall_apt_score'] >= 0.8:
                apt_indicators['threat_assessment'] = 'critical'
            elif apt_indicators['overall_apt_score'] >= 0.6:
                apt_indicators['threat_assessment'] = 'high'
            elif apt_indicators['overall_apt_score'] >= 0.4:
                apt_indicators['threat_assessment'] = 'medium'
            else:
                apt_indicators['threat_assessment'] = 'low'
            
            return apt_indicators
            
        except Exception as e:
            logger.error(f"APT behavior detection error: {str(e)}")
            return {'error': str(e)}
    
    # Private methods
    
    async def _extract_behavioral_events(self, file_path: str, content: str, 
                                       context: Dict[str, Any]) -> List[BehaviorEvent]:
        """Extract behavioral events from code content."""
        
        events = []
        
        try:
            # Parse code to AST
            try:
                tree = ast.parse(content)
            except SyntaxError:
                # If not Python, try to extract events using regex patterns
                return await self._extract_events_with_regex(file_path, content, context)
            
            # Walk AST and extract behavioral events
            for node in ast.walk(tree):
                event = await self._create_event_from_ast_node(node, file_path, context)
                if event:
                    events.append(event)
            
            return events
            
        except Exception as e:
            logger.error(f"Event extraction error: {str(e)}")
            return []
    
    async def _create_event_from_ast_node(self, node: ast.AST, file_path: str, 
                                        context: Dict[str, Any]) -> Optional[BehaviorEvent]:
        """Create behavioral event from AST node."""
        
        try:
            event_id = f"{file_path}_{getattr(node, 'lineno', 0)}_{id(node)}"
            
            if isinstance(node, ast.FunctionDef):
                return BehaviorEvent(
                    event_id=event_id,
                    event_type="function_definition",
                    timestamp=time.time(),
                    source_location=f"{file_path}:{getattr(node, 'lineno', 0)}",
                    function_name=node.name,
                    operation="define_function",
                    parameters={'args': [arg.arg for arg in node.args.args]},
                    execution_context=context
                )
            
            elif isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                
                return BehaviorEvent(
                    event_id=event_id,
                    event_type="function_call",
                    timestamp=time.time(),
                    source_location=f"{file_path}:{getattr(node, 'lineno', 0)}",
                    function_name=func_name,
                    operation="call_function",
                    parameters={'args_count': len(node.args)},
                    execution_context=context
                )
            
            elif isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom):
                modules = []
                if isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                else:
                    modules = [node.module] if node.module else []
                
                return BehaviorEvent(
                    event_id=event_id,
                    event_type="import_statement",
                    timestamp=time.time(),
                    source_location=f"{file_path}:{getattr(node, 'lineno', 0)}",
                    operation="import_module",
                    parameters={'modules': modules},
                    execution_context=context
                )
            
            elif isinstance(node, ast.Assign):
                targets = []
                if node.targets:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            targets.append(target.id)
                
                return BehaviorEvent(
                    event_id=event_id,
                    event_type="assignment",
                    timestamp=time.time(),
                    source_location=f"{file_path}:{getattr(node, 'lineno', 0)}",
                    operation="assign_variable",
                    parameters={'targets': targets},
                    execution_context=context
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Event creation error: {str(e)}")
            return None
    
    async def _extract_events_with_regex(self, file_path: str, content: str, 
                                       context: Dict[str, Any]) -> List[BehaviorEvent]:
        """Extract events using regex patterns for non-Python code."""
        
        events = []
        
        # JavaScript/TypeScript function definitions
        func_pattern = re.compile(r'function\s+(\w+)\s*\([^)]*\)', re.IGNORECASE)
        for match in func_pattern.finditer(content):
            line_num = content[:match.start()].count('\n') + 1
            event = BehaviorEvent(
                event_id=f"{file_path}_{line_num}_{match.start()}",
                event_type="function_definition",
                timestamp=time.time(),
                source_location=f"{file_path}:{line_num}",
                function_name=match.group(1),
                operation="define_function",
                execution_context=context
            )
            events.append(event)
        
        # Function calls
        call_pattern = re.compile(r'(\w+)\s*\([^)]*\)', re.IGNORECASE)
        for match in call_pattern.finditer(content):
            line_num = content[:match.start()].count('\n') + 1
            event = BehaviorEvent(
                event_id=f"{file_path}_{line_num}_{match.start()}_call",
                event_type="function_call",
                timestamp=time.time(),
                source_location=f"{file_path}:{line_num}",
                function_name=match.group(1),
                operation="call_function",
                execution_context=context
            )
            events.append(event)
        
        return events
    
    async def _create_behavior_sequences(self, events: List[BehaviorEvent]) -> List[BehaviorSequence]:
        """Create behavior sequences from events."""
        
        sequences = []
        
        try:
            # Enhanced sequence creation with multiple strategies
            
            # Strategy 1: Group by source location/context
            sequences.extend(await self._create_location_based_sequences(events))
            
            # Strategy 2: Group by function call chains
            sequences.extend(await self._create_function_chain_sequences(events))
            
            # Strategy 3: Group by temporal proximity
            sequences.extend(await self._create_temporal_sequences(events))
            
            # Strategy 4: Group by suspicious patterns
            sequences.extend(await self._create_suspicious_pattern_sequences(events))
            
            # Store all sequences
            for sequence in sequences:
                self.sequences[sequence.sequence_id] = sequence
            
            return sequences
            
        except Exception as e:
            logger.error(f"Sequence creation error: {str(e)}")
            return []
    
    async def _create_location_based_sequences(self, events: List[BehaviorEvent]) -> List[BehaviorSequence]:
        """Create sequences based on source location."""
        sequences = []
        
        try:
            # Group events by source location/context
            event_groups = defaultdict(list)
            for event in events:
                # Group by file and function
                group_key = f"{event.source_location}_{event.function_name}"
                event_groups[group_key].append(event)
            
            # Create sequences from groups
            for group_key, group_events in event_groups.items():
                if len(group_events) >= self.config.minimum_sequence_length:
                    sequence = BehaviorSequence(
                        sequence_id=f"loc_seq_{hashlib.md5(group_key.encode()).hexdigest()[:8]}"
                    )
                    
                    # Sort events by timestamp
                    group_events.sort(key=lambda e: e.timestamp)
                    
                    for event in group_events:
                        sequence.add_event(event)
                    
                    sequences.append(sequence)
            
            return sequences
            
        except Exception as e:
            logger.error(f"Location-based sequence creation error: {str(e)}")
            return []
    
    async def _create_function_chain_sequences(self, events: List[BehaviorEvent]) -> List[BehaviorSequence]:
        """Create sequences based on function call chains."""
        sequences = []
        
        try:
            # Find function call chains
            function_calls = [event for event in events if event.event_type == "function_call"]
            
            if len(function_calls) < 2:
                return sequences
            
            # Group consecutive function calls
            current_chain = []
            for i, event in enumerate(function_calls):
                if not current_chain:
                    current_chain.append(event)
                else:
                    # Check if this is a continuation of the chain
                    last_event = current_chain[-1]
                    time_diff = event.timestamp - last_event.timestamp
                    
                    # If within 1 second and same source location, continue chain
                    if time_diff <= 1.0 and event.source_location == last_event.source_location:
                        current_chain.append(event)
                    else:
                        # End current chain and start new one
                        if len(current_chain) >= 2:  # Minimum chain length
                            sequence = BehaviorSequence(
                                sequence_id=f"chain_seq_{hashlib.md5(str(current_chain[0].timestamp).encode()).hexdigest()[:8]}"
                            )
                            for chain_event in current_chain:
                                sequence.add_event(chain_event)
                            sequences.append(sequence)
                        current_chain = [event]
            
            # Handle the last chain
            if len(current_chain) >= 2:
                sequence = BehaviorSequence(
                    sequence_id=f"chain_seq_{hashlib.md5(str(current_chain[0].timestamp).encode()).hexdigest()[:8]}"
                )
                for chain_event in current_chain:
                    sequence.add_event(chain_event)
                sequences.append(sequence)
            
            return sequences
            
        except Exception as e:
            logger.error(f"Function chain sequence creation error: {str(e)}")
            return []
    
    async def _create_temporal_sequences(self, events: List[BehaviorEvent]) -> List[BehaviorSequence]:
        """Create sequences based on temporal proximity."""
        sequences = []
        
        try:
            if len(events) < 3:
                return sequences
            
            # Sort events by timestamp
            sorted_events = sorted(events, key=lambda e: e.timestamp)
            
            # Group events within time windows
            time_window = 5.0  # 5 seconds
            current_window = []
            window_start = sorted_events[0].timestamp
            
            for event in sorted_events:
                if event.timestamp - window_start <= time_window:
                    current_window.append(event)
                else:
                    # End current window and start new one
                    if len(current_window) >= 3:  # Minimum window size
                        sequence = BehaviorSequence(
                            sequence_id=f"temp_seq_{hashlib.md5(str(window_start).encode()).hexdigest()[:8]}"
                        )
                        for window_event in current_window:
                            sequence.add_event(window_event)
                        sequences.append(sequence)
                    
                    current_window = [event]
                    window_start = event.timestamp
            
            # Handle the last window
            if len(current_window) >= 3:
                sequence = BehaviorSequence(
                    sequence_id=f"temp_seq_{hashlib.md5(str(window_start).encode()).hexdigest()[:8]}"
                )
                for window_event in current_window:
                    sequence.add_event(window_event)
                sequences.append(sequence)
            
            return sequences
            
        except Exception as e:
            logger.error(f"Temporal sequence creation error: {str(e)}")
            return []
    
    async def _create_suspicious_pattern_sequences(self, events: List[BehaviorEvent]) -> List[BehaviorSequence]:
        """Create sequences based on suspicious patterns."""
        sequences = []
        
        try:
            # Define suspicious function patterns
            suspicious_functions = {
                'eval', 'exec', 'setTimeout', 'setInterval', 'fetch', 'XMLHttpRequest',
                'fs.readFileSync', 'fs.writeFileSync', 'child_process.exec', 'child_process.spawn'
            }
            
            # Find suspicious events
            suspicious_events = [
                event for event in events 
                if event.function_name in suspicious_functions
            ]
            
            if len(suspicious_events) < 2:
                return sequences
            
            # Group suspicious events by proximity
            sorted_suspicious = sorted(suspicious_events, key=lambda e: e.timestamp)
            current_pattern = []
            
            for i, event in enumerate(sorted_suspicious):
                if not current_pattern:
                    current_pattern.append(event)
                else:
                    # Check if this continues the pattern
                    last_event = current_pattern[-1]
                    time_diff = event.timestamp - last_event.timestamp
                    
                    # If within 10 seconds, continue pattern
                    if time_diff <= 10.0:
                        current_pattern.append(event)
                    else:
                        # End current pattern and start new one
                        if len(current_pattern) >= 2:
                            sequence = BehaviorSequence(
                                sequence_id=f"susp_seq_{hashlib.md5(str(current_pattern[0].timestamp).encode()).hexdigest()[:8]}"
                            )
                            for pattern_event in current_pattern:
                                sequence.add_event(pattern_event)
                            sequences.append(sequence)
                        current_pattern = [event]
            
            # Handle the last pattern
            if len(current_pattern) >= 2:
                sequence = BehaviorSequence(
                    sequence_id=f"susp_seq_{hashlib.md5(str(current_pattern[0].timestamp).encode()).hexdigest()[:8]}"
                )
                for pattern_event in current_pattern:
                    sequence.add_event(pattern_event)
                sequences.append(sequence)
            
            return sequences
            
        except Exception as e:
            logger.error(f"Suspicious pattern sequence creation error: {str(e)}")
            return []
    
    async def _match_signatures(self, events: List[BehaviorEvent], 
                              sequences: List[BehaviorSequence],
                              context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Match events and sequences against behavioral signatures."""
        
        matches = []
        
        try:
            for signature in self.signatures.values():
                # Check sequence patterns
                for sequence in sequences:
                    match_result = await self.pattern_matcher.match_sequence(
                        signature, sequence, context
                    )
                    
                    if match_result['matched']:
                        matches.append({
                            'signature_id': signature.signature_id,
                            'signature_name': signature.name,
                            'behavior_type': signature.behavior_type.value,
                            'confidence': match_result['confidence'],
                            'threat_level': signature.threat_level,
                            'mitre_techniques': list(signature.mitre_techniques),
                            'sequence_id': sequence.sequence_id,
                            'matched_elements': match_result['matched_elements']
                        })
                        
                        # Update signature statistics
                        signature.match_count += 1
                        signature.last_updated = time.time()
            
            return matches
            
        except Exception as e:
            logger.error(f"Signature matching error: {str(e)}")
            return []
    
    async def _detect_anomalies(self, events: List[BehaviorEvent], 
                              sequences: List[BehaviorSequence],
                              context: Dict[str, Any]) -> List[AnomalyDetection]:
        """Detect behavioral anomalies."""
        
        anomalies = []
        
        try:
            # Enhanced anomaly detection patterns
            anomalies.extend(await self._detect_suspicious_patterns(events, context))
            anomalies.extend(await self._detect_timing_anomalies(events, context))
            anomalies.extend(await self._detect_frequency_anomalies(events, context))
            anomalies.extend(await self._detect_sequence_anomalies(sequences, context))
            anomalies.extend(await self._detect_statistical_anomalies(events, context))
            
            # Run each anomaly detector if available
            for anomaly_type, detector in self.anomaly_detectors.items():
                try:
                    detector_anomalies = await detector.detect_anomalies(events, sequences, context)
                    anomalies.extend(detector_anomalies)
                except Exception as e:
                    logger.warning(f"Anomaly detector {anomaly_type} failed: {str(e)}")
            
            # Store anomalies
            for anomaly in anomalies:
                self.detected_anomalies[anomaly.anomaly_id] = anomaly
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Anomaly detection error: {str(e)}")
            return []
    
    async def _assess_risk(self, events: List[BehaviorEvent], sequences: List[BehaviorSequence],
                         signature_matches: List[Dict[str, Any]], 
                         anomalies: List[AnomalyDetection]) -> Dict[str, Any]:
        """Assess overall risk based on behavioral analysis."""
        
        try:
            risk_factors = []
            threat_indicators = []
            recommendations = []
            
            # Signature-based risk
            high_risk_matches = [
                match for match in signature_matches
                if match['threat_level'] in ['high', 'critical']
            ]
            
            if high_risk_matches:
                risk_factors.append(len(high_risk_matches) * 0.3)
                threat_indicators.extend([match['signature_name'] for match in high_risk_matches])
                recommendations.append("Review high-risk behavioral patterns detected")
            
            # Anomaly-based risk
            high_severity_anomalies = [
                anomaly for anomaly in anomalies
                if anomaly.severity in ['high', 'critical']
            ]
            
            if high_severity_anomalies:
                risk_factors.append(len(high_severity_anomalies) * 0.25)
                threat_indicators.extend([anomaly.description for anomaly in high_severity_anomalies])
                recommendations.append("Investigate behavioral anomalies")
            
            # Sequence complexity risk
            complex_sequences = [
                seq for seq in sequences
                if len(seq.events) > 20  # Arbitrary threshold
            ]
            
            if complex_sequences:
                risk_factors.append(len(complex_sequences) * 0.1)
                threat_indicators.append(f"{len(complex_sequences)} complex behavioral sequences")
                recommendations.append("Review complex execution patterns")
            
            # Calculate overall risk score
            overall_risk_score = min(1.0, sum(risk_factors))
            
            # Risk level classification
            if overall_risk_score >= 0.8:
                risk_level = "critical"
            elif overall_risk_score >= 0.6:
                risk_level = "high"
            elif overall_risk_score >= 0.4:
                risk_level = "medium"
            elif overall_risk_score >= 0.2:
                risk_level = "low"
            else:
                risk_level = "minimal"
            
            return {
                'overall_risk_score': overall_risk_score,
                'risk_level': risk_level,
                'threat_indicators': threat_indicators,
                'recommendations': recommendations,
                'risk_breakdown': {
                    'signature_matches': len(signature_matches),
                    'high_risk_matches': len(high_risk_matches),
                    'anomalies': len(anomalies),
                    'high_severity_anomalies': len(high_severity_anomalies),
                    'complex_sequences': len(complex_sequences)
                }
            }
            
        except Exception as e:
            logger.error(f"Risk assessment error: {str(e)}")
            return {'overall_risk_score': 0.0, 'risk_level': 'unknown', 'error': str(e)}
    
    async def _load_builtin_signatures(self):
        """Load built-in behavioral signatures."""
        
        # SQL Injection behavioral signature
        sql_injection_signature = BehaviorSignature(
            signature_id="sql_injection_behavior",
            name="SQL Injection Behavioral Pattern",
            description="Detects behavioral patterns indicative of SQL injection attempts",
            behavior_type=BehaviorType.DATA_ACCESS,
            pattern_elements=[
                "string_concatenation",
                "database_query",
                "user_input_handling"
            ],
            sequence_patterns=[
                ["user_input", "string_concat", "database_execute"],
                ["parameter_access", "sql_construction", "query_execution"]
            ],
            minimum_confidence=0.7,
            threat_level="high",
            mitre_techniques={"T1190"},  # Exploit Public-Facing Application
            attack_categories={"injection"}
        )
        self.signatures[sql_injection_signature.signature_id] = sql_injection_signature
        
        # Command injection signature
        command_injection_signature = BehaviorSignature(
            signature_id="command_injection_behavior",
            name="Command Injection Behavioral Pattern",
            description="Detects behavioral patterns indicative of command injection",
            behavior_type=BehaviorType.COMMAND_EXECUTION,
            pattern_elements=[
                "system_call",
                "shell_execution",
                "process_creation"
            ],
            sequence_patterns=[
                ["user_input", "command_construction", "system_execute"],
                ["parameter_processing", "shell_command", "process_spawn"]
            ],
            minimum_confidence=0.8,
            threat_level="critical",
            mitre_techniques={"T1059"},  # Command and Scripting Interpreter
            attack_categories={"injection", "execution"}
        )
        self.signatures[command_injection_signature.signature_id] = command_injection_signature
        
        # Data exfiltration signature
        data_exfil_signature = BehaviorSignature(
            signature_id="data_exfiltration_behavior",
            name="Data Exfiltration Behavioral Pattern",
            description="Detects behavioral patterns indicative of data exfiltration",
            behavior_type=BehaviorType.EXFILTRATION,
            pattern_elements=[
                "data_collection",
                "data_compression",
                "network_transmission"
            ],
            sequence_patterns=[
                ["file_read", "data_encode", "network_send"],
                ["database_query", "data_serialize", "external_request"]
            ],
            minimum_confidence=0.6,
            threat_level="high",
            mitre_techniques={"T1041"},  # Exfiltration Over C2 Channel
            attack_categories={"exfiltration"}
        )
        self.signatures[data_exfil_signature.signature_id] = data_exfil_signature
        
        # Privilege escalation signature
        privilege_esc_signature = BehaviorSignature(
            signature_id="privilege_escalation_behavior",
            name="Privilege Escalation Behavioral Pattern",
            description="Detects behavioral patterns indicative of privilege escalation",
            behavior_type=BehaviorType.PRIVILEGE_ESCALATION,
            pattern_elements=[
                "permission_check",
                "role_modification",
                "access_elevation"
            ],
            sequence_patterns=[
                ["auth_check", "permission_bypass", "elevated_access"],
                ["user_validation", "role_change", "admin_function"]
            ],
            minimum_confidence=0.7,
            threat_level="high",
            mitre_techniques={"T1068"},  # Exploitation for Privilege Escalation
            attack_categories={"privilege_escalation"}
        )
        self.signatures[privilege_esc_signature.signature_id] = privilege_esc_signature
        
        logger.info(f"Loaded {len(self.signatures)} built-in behavioral signatures")
    
    # Helper methods for APT detection
    
    def _is_persistence_behavior(self, event: BehaviorEvent) -> bool:
        """Check if event indicates persistence mechanism."""
        persistence_indicators = [
            'startup', 'registry', 'service', 'scheduled_task',
            'autostart', 'boot', 'login', 'cron'
        ]
        
        return any(indicator in event.operation.lower() or 
                  indicator in event.function_name.lower()
                  for indicator in persistence_indicators)
    
    def _is_lateral_movement_behavior(self, event: BehaviorEvent) -> bool:
        """Check if event indicates lateral movement."""
        lateral_indicators = [
            'remote', 'network_share', 'credential', 'ssh',
            'rdp', 'smb', 'wmi', 'psexec'
        ]
        
        return any(indicator in event.operation.lower() or 
                  indicator in event.function_name.lower()
                  for indicator in lateral_indicators)
    
    def _is_privilege_escalation_behavior(self, event: BehaviorEvent) -> bool:
        """Check if event indicates privilege escalation."""
        privesc_indicators = [
            'sudo', 'admin', 'root', 'privilege', 'elevation',
            'runas', 'impersonate', 'token'
        ]
        
        return any(indicator in event.operation.lower() or 
                  indicator in event.function_name.lower()
                  for indicator in privesc_indicators)
    
    def _is_exfiltration_behavior(self, event: BehaviorEvent) -> bool:
        """Check if event indicates data exfiltration."""
        exfil_indicators = [
            'upload', 'send', 'transmit', 'export', 'copy',
            'ftp', 'http_post', 'email', 'compress'
        ]
        
        return any(indicator in event.operation.lower() or 
                  indicator in event.function_name.lower()
                  for indicator in exfil_indicators)
    
    def _is_c2_behavior(self, event: BehaviorEvent) -> bool:
        """Check if event indicates command and control."""
        c2_indicators = [
            'beacon', 'heartbeat', 'callback', 'download',
            'command', 'control', 'c2', 'remote_shell'
        ]
        
        return any(indicator in event.operation.lower() or 
                  indicator in event.function_name.lower()
                  for indicator in c2_indicators)
    
    def _is_evasion_behavior(self, event: BehaviorEvent) -> bool:
        """Check if event indicates evasion techniques."""
        evasion_indicators = [
            'obfuscate', 'encode', 'encrypt', 'hide', 'steganography',
            'polymorphic', 'packer', 'anti_debug', 'sandbox_evasion'
        ]
        
        return any(indicator in event.operation.lower() or 
                  indicator in event.function_name.lower()
                  for indicator in evasion_indicators)
    
    # Serialization methods
    
    def _serialize_event(self, event: BehaviorEvent) -> Dict[str, Any]:
        """Serialize behavioral event."""
        return {
            'event_id': event.event_id,
            'event_type': event.event_type,
            'timestamp': event.timestamp,
            'source_location': event.source_location,
            'function_name': event.function_name,
            'operation': event.operation,
            'parameters': event.parameters,
            'risk_score': event.risk_score,
            'anomaly_indicators': event.anomaly_indicators
        }
    
    def _serialize_sequence(self, sequence: BehaviorSequence) -> Dict[str, Any]:
        """Serialize behavioral sequence."""
        return {
            'sequence_id': sequence.sequence_id,
            'event_count': len(sequence.events),
            'start_time': sequence.start_time,
            'end_time': sequence.end_time,
            'duration': sequence.duration,
            'matched_signatures': sequence.matched_signatures,
            'overall_risk_score': sequence.overall_risk_score,
            'threat_indicators': sequence.threat_indicators
        }
    
    def _serialize_anomaly(self, anomaly: AnomalyDetection) -> Dict[str, Any]:
        """Serialize anomaly detection."""
        return {
            'anomaly_id': anomaly.anomaly_id,
            'anomaly_type': anomaly.anomaly_type.value,
            'description': anomaly.description,
            'confidence': anomaly.confidence,
            'severity': anomaly.severity,
            'source_location': anomaly.source_location,
            'detection_time': anomaly.detection_time,
            'false_positive_likelihood': anomaly.false_positive_likelihood
        }
    
    # Background workers
    
    async def _sequence_processing_worker(self):
        """Background sequence processing worker."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(60)  # Process every minute
                
                # Process active sequences
                current_time = time.time()
                expired_sequences = []
                
                for seq_id, sequence in self.active_sequences.items():
                    if (sequence.end_time and 
                        current_time - sequence.end_time > self.config.sequence_timeout_seconds):
                        expired_sequences.append(seq_id)
                
                # Move expired sequences to completed
                for seq_id in expired_sequences:
                    sequence = self.active_sequences.pop(seq_id)
                    self.sequences[seq_id] = sequence
                
            except Exception as e:
                logger.error(f"Sequence processing worker error: {str(e)}")
    
    async def _anomaly_detection_worker(self):
        """Background anomaly detection worker."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                
                # Run periodic anomaly detection on stored events
                recent_events = [
                    event for event in self.events.values()
                    if time.time() - event.timestamp < 3600  # Last hour
                ]
                
                if recent_events:
                    sequences = await self._create_behavior_sequences(recent_events)
                    anomalies = await self._detect_anomalies(recent_events, sequences, {})
                    
                    logger.debug(f"Background anomaly detection: {len(anomalies)} anomalies found")
                
            except Exception as e:
                logger.error(f"Anomaly detection worker error: {str(e)}")
    
    async def _cleanup_worker(self):
        """Background cleanup worker."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(3600)  # Run every hour
                
                current_time = time.time()
                
                # Clean up old events
                event_retention_seconds = self.config.event_retention_days * 86400
                expired_events = [
                    event_id for event_id, event in self.events.items()
                    if current_time - event.timestamp > event_retention_seconds
                ]
                
                for event_id in expired_events:
                    del self.events[event_id]
                
                # Clean up old anomalies
                anomaly_retention_seconds = self.config.anomaly_retention_days * 86400
                expired_anomalies = [
                    anomaly_id for anomaly_id, anomaly in self.detected_anomalies.items()
                    if current_time - anomaly.detection_time > anomaly_retention_seconds
                ]
                
                for anomaly_id in expired_anomalies:
                    del self.detected_anomalies[anomaly_id]
                
                logger.debug(f"Cleanup completed: removed {len(expired_events)} events, "
                           f"{len(expired_anomalies)} anomalies")
                
            except Exception as e:
                logger.error(f"Cleanup worker error: {str(e)}")
    
    async def _ml_training_worker(self):
        """Background ML training worker."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(self.config.model_update_interval)
                
                if self.behavior_modeler and len(self.events) >= self.config.training_data_size:
                    logger.info("Starting ML model training")
                    await self.behavior_modeler.train_models(list(self.events.values()))
                    logger.info("ML model training completed")
                
            except Exception as e:
                logger.error(f"ML training worker error: {str(e)}")
    
    # Placeholder methods (would be implemented based on specific requirements)
    
    async def _validate_signature(self, signature: BehaviorSignature) -> bool:
        """Validate behavioral signature."""
        return bool(signature.signature_id and signature.name)
    
    def _event_matches_target(self, event: BehaviorEvent, target: str, profile_type: str) -> bool:
        """Check if event matches target for profiling."""
        if profile_type == "file":
            return target in event.source_location
        elif profile_type == "function":
            return target == event.function_name
        return False
    
    async def _calculate_behavior_metrics(self, events: List[BehaviorEvent]) -> Dict[str, Any]:
        """Calculate behavioral metrics for events."""
        return {
            'event_frequency': len(events),
            'unique_operations': len(set(event.operation for event in events)),
            'average_risk_score': statistics.mean([event.risk_score for event in events]) if events else 0.0
        }
    
    async def _analyze_behavior_patterns(self, events: List[BehaviorEvent]) -> Dict[str, Any]:
        """Analyze behavioral patterns in events."""
        return {
            'common_operations': [],
            'temporal_patterns': [],
            'complexity_metrics': {}
        }
    
    async def _get_risk_indicators(self, events: List[BehaviorEvent]) -> List[str]:
        """Get risk indicators from events."""
        return [
            indicator for event in events
            for indicator in event.anomaly_indicators
        ]
    
    async def _generate_recommendations(self, events: List[BehaviorEvent], 
                                      anomalies: List[AnomalyDetection]) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []
        
        if len(anomalies) > 5:
            recommendations.append("High number of anomalies detected - review code logic")
        
        high_risk_events = [event for event in events if event.risk_score > 0.7]
        if high_risk_events:
            recommendations.append(f"Review {len(high_risk_events)} high-risk behavioral events")
        
        return recommendations
    
    async def shutdown(self):
        """Shutdown behavioral analysis engine."""
        
        logger.info("Shutting down Behavioral Analysis Engine")
        
        self.running = False
        self.shutdown_event.set()
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        # Wait for background tasks to complete
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        # Shutdown components
        await self.pattern_matcher.shutdown()
        await self.execution_analyzer.shutdown()
        await self.data_flow_analyzer.shutdown()
        await self.temporal_analyzer.shutdown()
        await self.context_analyzer.shutdown()
        await self.correlation_engine.shutdown()
        
        for detector in self.anomaly_detectors.values():
            await detector.shutdown()
        
        if self.behavior_modeler:
            await self.behavior_modeler.shutdown()
            await self.feature_extractor.shutdown()
        
        logger.info("Behavioral Analysis Engine shutdown completed")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get behavioral analysis statistics."""
        
        stats = dict(self.stats)
        stats['uptime'] = time.time() - self.start_time
        stats['total_events'] = len(self.events)
        stats['total_sequences'] = len(self.sequences)
        stats['total_anomalies'] = len(self.detected_anomalies)
        stats['total_signatures'] = len(self.signatures)
        stats['active_sequences'] = len(self.active_sequences)
        
        return stats
    
    def enhance_vulnerability_with_behavioral_context(self, vulnerability: 'Vulnerability') -> 'Vulnerability':
        """Enhance a vulnerability with behavioral analysis context and standardized types."""
        from ..vulnerability import Vulnerability
        
        # Normalize vulnerability type
        normalized_type = normalize_vulnerability_type(vulnerability.vuln_type)
        if normalized_type:
            # Get type information from registry
            type_info = get_vulnerability_type_info(normalized_type)
            if type_info:
                # Enhance metadata with behavioral context
                enhanced_metadata = vulnerability.metadata.copy() if vulnerability.metadata else {}
                
                # Add CWE codes and OWASP category if not present
                if 'cwe_codes' not in enhanced_metadata:
                    enhanced_metadata['cwe_codes'] = [cwe.value for cwe in type_info.cwe_codes]
                if 'owasp_category' not in enhanced_metadata:
                    enhanced_metadata['owasp_category'] = type_info.category.value
                if 'normalized_type' not in enhanced_metadata:
                    enhanced_metadata['normalized_type'] = normalized_type.value
                
                # Add behavioral analysis context
                enhanced_metadata['behavioral_analysis'] = {
                    'analyzed': True,
                    'signature_matches': len([s for s in self.signatures.values() 
                                            if s.match_count > 0]),
                    'anomalies_detected': len(self.detected_anomalies),
                    'risk_indicators': self._get_behavioral_risk_indicators(vulnerability)
                }
                
                # Create enhanced vulnerability
                enhanced_vuln = Vulnerability(
                    id=vulnerability.id,
                    title=vulnerability.title,
                    severity=vulnerability.severity,
                    confidence=vulnerability.confidence,
                    description=vulnerability.description,
                    fix=vulnerability.fix or type_info.remediation,
                    reference=vulnerability.reference or (type_info.references[0] if type_info.references else ""),
                    vuln_type=normalized_type.value,
                    location=vulnerability.location,
                    file_path=vulnerability.file_path,
                    line_number=vulnerability.line_number,
                    code_snippet=vulnerability.code_snippet,
                    framework=vulnerability.framework,
                    module=vulnerability.module,
                    metadata=enhanced_metadata
                )
                
                return enhanced_vuln
        
        return vulnerability
    
    def _get_behavioral_risk_indicators(self, vulnerability: 'Vulnerability') -> List[str]:
        """Get behavioral risk indicators for a vulnerability."""
        indicators = []
        
        # Check for related behavioral events
        related_events = [
            event for event in self.events.values()
            if vulnerability.file_path in event.source_location
        ]
        
        if related_events:
            indicators.append(f"Found {len(related_events)} related behavioral events")
        
        # Check for signature matches
        signature_matches = [
            sig for sig in self.signatures.values()
            if sig.match_count > 0 and vulnerability.vuln_type in str(sig.attack_categories)
        ]
        
        if signature_matches:
            indicators.append(f"Matched {len(signature_matches)} behavioral signatures")
        
        # Check for anomalies
        related_anomalies = [
            anomaly for anomaly in self.detected_anomalies.values()
            if vulnerability.file_path in anomaly.source_location
        ]
        
        if related_anomalies:
            indicators.append(f"Detected {len(related_anomalies)} behavioral anomalies")
        
        return indicators
    
    # Enhanced anomaly detection methods
    
    async def _detect_suspicious_patterns(self, events: List[BehaviorEvent], 
                                        context: Dict[str, Any]) -> List[AnomalyDetection]:
        """Detect suspicious behavioral patterns."""
        anomalies = []
        
        try:
            # Suspicious function patterns
            suspicious_functions = {
                'eval', 'exec', 'setTimeout', 'setInterval', 'fetch', 'XMLHttpRequest',
                'fs.readFileSync', 'fs.writeFileSync', 'child_process.exec', 'child_process.spawn',
                'document.cookie', 'localStorage', 'sessionStorage', 'crypto.subtle'
            }
            
            # Check for suspicious function calls
            suspicious_calls = [
                event for event in events 
                if event.function_name in suspicious_functions
            ]
            
            if suspicious_calls:
                anomaly = AnomalyDetection(
                    anomaly_id=f"suspicious_patterns_{int(time.time())}",
                    anomaly_type=AnomalyType.PATTERN_ANOMALY.value,
                    description=f"Detected {len(suspicious_calls)} suspicious function calls",
                    severity="medium",
                    confidence=0.8,
                    source_location=suspicious_calls[0].source_location,
                    detection_time=time.time(),
                    evidence=[{
                        'type': 'suspicious_functions',
                        'functions': [call.function_name for call in suspicious_calls],
                        'count': len(suspicious_calls)
                    }],
                    risk_score=0.7,
                    false_positive_likelihood=0.2
                )
                anomalies.append(anomaly)
            
            # Check for eval/exec usage (high risk)
            eval_calls = [event for event in events if event.function_name in ['eval', 'exec']]
            if eval_calls:
                anomaly = AnomalyDetection(
                    anomaly_id=f"code_injection_risk_{int(time.time())}",
                    anomaly_type=AnomalyType.PATTERN_ANOMALY.value,
                    description="Code injection risk detected - eval/exec usage",
                    severity="high",
                    confidence=0.9,
                    source_location=eval_calls[0].source_location,
                    detection_time=time.time(),
                    evidence=[{
                        'type': 'code_injection',
                        'functions': [call.function_name for call in eval_calls],
                        'risk': 'high'
                    }],
                    risk_score=0.9,
                    false_positive_likelihood=0.1
                )
                anomalies.append(anomaly)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Suspicious pattern detection error: {str(e)}")
            return []
    
    async def _detect_timing_anomalies(self, events: List[BehaviorEvent], 
                                     context: Dict[str, Any]) -> List[AnomalyDetection]:
        """Detect timing-based anomalies."""
        anomalies = []
        
        try:
            # Check for timing-based functions
            timing_functions = {'setTimeout', 'setInterval', 'setImmediate'}
            timing_events = [event for event in events if event.function_name in timing_functions]
            
            if len(timing_events) > 3:  # Threshold for suspicious timing usage
                anomaly = AnomalyDetection(
                    anomaly_id=f"timing_anomaly_{int(time.time())}",
                    anomaly_type=AnomalyType.TIMING_ANOMALY.value,
                    description=f"Excessive timing function usage: {len(timing_events)} calls",
                    severity="medium",
                    confidence=0.7,
                    source_location=timing_events[0].source_location,
                    detection_time=time.time(),
                    evidence=[{
                        'type': 'timing_anomaly',
                        'timing_functions': [event.function_name for event in timing_events],
                        'count': len(timing_events)
                    }],
                    risk_score=0.6,
                    false_positive_likelihood=0.3
                )
                anomalies.append(anomaly)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Timing anomaly detection error: {str(e)}")
            return []
    
    async def _detect_frequency_anomalies(self, events: List[BehaviorEvent], 
                                        context: Dict[str, Any]) -> List[AnomalyDetection]:
        """Detect frequency-based anomalies."""
        anomalies = []
        
        try:
            # Count function call frequencies
            function_counts = {}
            for event in events:
                if event.function_name:
                    function_counts[event.function_name] = function_counts.get(event.function_name, 0) + 1
            
            # Check for unusually high frequency calls
            for func_name, count in function_counts.items():
                if count > 5:  # Threshold for high frequency
                    anomaly = AnomalyDetection(
                        anomaly_id=f"frequency_anomaly_{func_name}_{int(time.time())}",
                        anomaly_type=AnomalyType.FREQUENCY_ANOMALY.value,
                        description=f"High frequency function calls: {func_name} called {count} times",
                        severity="low",
                        confidence=0.6,
                        source_location=events[0].source_location,
                        detection_time=time.time(),
                        evidence=[{
                            'type': 'frequency_anomaly',
                            'function': func_name,
                            'count': count,
                            'threshold': 5
                        }],
                        risk_score=0.4,
                        false_positive_likelihood=0.4
                    )
                    anomalies.append(anomaly)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Frequency anomaly detection error: {str(e)}")
            return []
    
    async def _detect_sequence_anomalies(self, sequences: List[BehaviorSequence], 
                                       context: Dict[str, Any]) -> List[AnomalyDetection]:
        """Detect sequence-based anomalies."""
        anomalies = []
        
        try:
            # Check for suspicious event sequences
            for sequence in sequences:
                if len(sequence.events) > 10:  # Long sequences might be suspicious
                    anomaly = AnomalyDetection(
                        anomaly_id=f"sequence_anomaly_{sequence.sequence_id}",
                        anomaly_type=AnomalyType.SEQUENCE_ANOMALY.value,
                        description=f"Long behavioral sequence detected: {len(sequence.events)} events",
                        severity="medium",
                        confidence=0.7,
                        source_location=sequence.events[0].source_location if sequence.events else "unknown",
                        detection_time=time.time(),
                        evidence=[{
                            'type': 'sequence_anomaly',
                            'sequence_length': len(sequence.events),
                            'sequence_id': sequence.sequence_id
                        }],
                        risk_score=0.6,
                        false_positive_likelihood=0.3
                    )
                    anomalies.append(anomaly)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Sequence anomaly detection error: {str(e)}")
            return []
    
    async def _detect_statistical_anomalies(self, events: List[BehaviorEvent], 
                                          context: Dict[str, Any]) -> List[AnomalyDetection]:
        """Detect statistical anomalies."""
        anomalies = []
        
        try:
            if len(events) < 5:  # Need minimum events for statistical analysis
                return anomalies
            
            # Calculate event type distribution
            event_types = {}
            for event in events:
                event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
            
            # Check for unusual distributions
            total_events = len(events)
            for event_type, count in event_types.items():
                percentage = (count / total_events) * 100
                
                # If one event type dominates (>80%), it might be suspicious
                if percentage > 80:
                    anomaly = AnomalyDetection(
                        anomaly_id=f"statistical_anomaly_{event_type}_{int(time.time())}",
                        anomaly_type=AnomalyType.STATISTICAL_ANOMALY.value,
                        description=f"Unusual event type distribution: {event_type} represents {percentage:.1f}% of events",
                        severity="low",
                        confidence=0.6,
                        source_location=events[0].source_location,
                        detection_time=time.time(),
                        evidence=[{
                            'type': 'statistical_anomaly',
                            'event_type': event_type,
                            'percentage': percentage,
                            'count': count,
                            'total_events': total_events
                        }],
                        risk_score=0.3,
                        false_positive_likelihood=0.5
                    )
                    anomalies.append(anomaly)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Statistical anomaly detection error: {str(e)}")
            return []


# Helper classes (stubs - would be implemented based on specific requirements)

class PatternMatcher:
    """Behavioral pattern matcher."""
    
    def __init__(self, config: BehavioralAnalysisConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def match_sequence(self, signature: BehaviorSignature, 
                           sequence: BehaviorSequence, 
                           context: Dict[str, Any]) -> Dict[str, Any]:
        return {'matched': False, 'confidence': 0.0, 'matched_elements': []}
    
    async def shutdown(self):
        pass


class ExecutionFlowAnalyzer:
    """Execution flow analysis engine."""
    
    def __init__(self, config: BehavioralAnalysisConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def analyze_flow(self, content: str, events: List[BehaviorEvent], 
                         context: Dict[str, Any]) -> Dict[str, Any]:
        return {}
    
    async def shutdown(self):
        pass


class DataFlowAnalyzer:
    """Data flow analysis engine."""
    
    def __init__(self, config: BehavioralAnalysisConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def analyze_flow(self, content: str, events: List[BehaviorEvent], 
                         context: Dict[str, Any]) -> Dict[str, Any]:
        return {}
    
    async def shutdown(self):
        pass


class TemporalAnalyzer:
    """Temporal pattern analysis engine."""
    
    def __init__(self, config: BehavioralAnalysisConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def shutdown(self):
        pass


class BehaviorModeler:
    """Machine learning behavior modeler."""
    
    def __init__(self, config: BehavioralAnalysisConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def analyze_behavior(self, events: List[BehaviorEvent], 
                             sequences: List[BehaviorSequence], 
                             context: Dict[str, Any]) -> Dict[str, Any]:
        return {}
    
    async def train_models(self, events: List[BehaviorEvent]):
        pass
    
    async def shutdown(self):
        pass


class BehaviorFeatureExtractor:
    """Behavioral feature extraction."""
    
    def __init__(self, config: BehavioralAnalysisConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def shutdown(self):
        pass


class BehaviorContextAnalyzer:
    """Behavioral context analyzer."""
    
    def __init__(self, config: BehavioralAnalysisConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def shutdown(self):
        pass


class BehaviorCorrelationEngine:
    """Behavioral correlation engine."""
    
    def __init__(self, config: BehavioralAnalysisConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def shutdown(self):
        pass


# Anomaly detector classes

class AnomalyDetector:
    """Base anomaly detector."""
    
    def __init__(self, config: BehavioralAnalysisConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def detect_anomalies(self, events: List[BehaviorEvent], 
                             sequences: List[BehaviorSequence], 
                             context: Dict[str, Any]) -> List[AnomalyDetection]:
        return []
    
    async def shutdown(self):
        pass


class StatisticalAnomalyDetector(AnomalyDetector):
    """Statistical anomaly detector."""
    pass


class PatternDeviationDetector(AnomalyDetector):
    """Pattern deviation detector."""
    pass


class FrequencyAnomalyDetector(AnomalyDetector):
    """Frequency anomaly detector."""
    pass


class SequenceAnomalyDetector(AnomalyDetector):
    """Sequence anomaly detector."""
    pass


class TemporalAnomalyDetector(AnomalyDetector):
    """Temporal anomaly detector."""
    pass


class ContextualAnomalyDetector(AnomalyDetector):
    """Contextual anomaly detector."""
    pass
