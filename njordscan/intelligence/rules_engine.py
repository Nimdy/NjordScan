"""
Security Rules Intelligence Engine

Advanced rule-based security analysis with:
- Dynamic rule generation and learning
- Context-aware vulnerability detection
- Machine learning-enhanced pattern matching
- Behavioral analysis and anomaly detection
- Custom rule development framework
- Rule performance optimization
- Intelligent false positive reduction
"""

import asyncio
import time
import re
import ast
import json
import yaml
from typing import Dict, List, Any, Optional, Union, Set, Tuple, Callable, Pattern
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging
from collections import defaultdict, Counter
import hashlib
import pickle
from concurrent.futures import ThreadPoolExecutor
import threading

logger = logging.getLogger(__name__)

class RuleType(Enum):
    """Types of security rules."""
    STATIC_PATTERN = "static_pattern"
    DYNAMIC_BEHAVIOR = "dynamic_behavior"
    CONTEXT_AWARE = "context_aware"
    MACHINE_LEARNING = "machine_learning"
    COMPOSITE = "composite"
    CUSTOM = "custom"

class RuleSeverity(Enum):
    """Rule severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class RuleCategory(Enum):
    """Security rule categories."""
    INJECTION = "injection"
    XSS = "xss"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CRYPTOGRAPHY = "cryptography"
    CONFIGURATION = "configuration"
    DEPENDENCY = "dependency"
    BUSINESS_LOGIC = "business_logic"
    DATA_EXPOSURE = "data_exposure"
    DENIAL_OF_SERVICE = "denial_of_service"

class RuleConfidence(Enum):
    """Rule confidence levels."""
    LOW = 0.3
    MEDIUM = 0.6
    HIGH = 0.8
    VERY_HIGH = 0.95

class MatchType(Enum):
    """Pattern matching types."""
    EXACT = "exact"
    REGEX = "regex"
    FUZZY = "fuzzy"
    SEMANTIC = "semantic"
    BEHAVIORAL = "behavioral"

@dataclass
class RulePattern:
    """Security rule pattern definition."""
    pattern_id: str
    pattern: str
    match_type: MatchType
    case_sensitive: bool = True
    multiline: bool = False
    flags: Set[str] = field(default_factory=set)
    context_requirements: Dict[str, Any] = field(default_factory=dict)
    
    # Compiled pattern cache
    _compiled_pattern: Optional[Pattern] = field(default=None, init=False, repr=False)
    
    def compile_pattern(self) -> Optional[Pattern]:
        """Compile regex pattern with appropriate flags."""
        if self.match_type != MatchType.REGEX:
            return None
        
        if self._compiled_pattern is None:
            try:
                flags = 0
                if not self.case_sensitive:
                    flags |= re.IGNORECASE
                if self.multiline:
                    flags |= re.MULTILINE | re.DOTALL
                
                self._compiled_pattern = re.compile(self.pattern, flags)
            except re.error as e:
                logger.error(f"Failed to compile pattern {self.pattern_id}: {str(e)}")
                return None
        
        return self._compiled_pattern

@dataclass
class RuleCondition:
    """Rule execution condition."""
    condition_id: str
    condition_type: str  # file_type, file_size, framework, etc.
    operator: str  # equals, contains, matches, greater_than, etc.
    value: Any
    negated: bool = False

@dataclass
class RuleAction:
    """Action to take when rule matches."""
    action_type: str  # report, suppress, escalate, etc.
    parameters: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SecurityRule:
    """Comprehensive security rule definition."""
    rule_id: str
    name: str
    description: str
    category: RuleCategory
    severity: RuleSeverity
    confidence: RuleConfidence
    rule_type: RuleType
    
    # Pattern matching
    patterns: List[RulePattern] = field(default_factory=list)
    
    # Execution conditions
    conditions: List[RuleCondition] = field(default_factory=list)
    
    # Actions
    actions: List[RuleAction] = field(default_factory=list)
    
    # Metadata
    tags: Set[str] = field(default_factory=set)
    references: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    owasp_categories: List[str] = field(default_factory=list)
    
    # Framework specific
    frameworks: Set[str] = field(default_factory=set)  # nextjs, react, vite, etc.
    file_types: Set[str] = field(default_factory=set)  # js, ts, json, etc.
    
    # Performance and optimization
    enabled: bool = True
    priority: int = 100  # Higher number = higher priority
    performance_weight: float = 1.0  # Execution cost weight
    
    # Learning and adaptation
    false_positive_rate: float = 0.0
    true_positive_rate: float = 1.0
    adaptation_weight: float = 1.0
    
    # Temporal aspects
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    last_matched: Optional[float] = None
    match_count: int = 0
    
    # Custom validation function
    custom_validator: Optional[Callable] = field(default=None, repr=False)
    
    def calculate_effectiveness_score(self) -> float:
        """Calculate rule effectiveness score."""
        if self.match_count == 0:
            return 0.5  # Neutral for new rules
        
        # Factor in true positive rate and false positive rate
        effectiveness = (
            self.true_positive_rate * 0.7 +
            (1.0 - self.false_positive_rate) * 0.3
        )
        
        # Adjust for match frequency (more matches can indicate better rule)
        frequency_factor = min(1.0, self.match_count / 100.0)
        
        return effectiveness * (0.8 + 0.2 * frequency_factor)

@dataclass
class RuleMatch:
    """Result of rule matching."""
    rule_id: str
    match_id: str
    file_path: str
    line_number: int
    column_number: int = 0
    matched_text: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    confidence_score: float = 1.0
    severity_override: Optional[RuleSeverity] = None
    
    # Match details
    pattern_id: str = ""
    match_type: MatchType = MatchType.EXACT
    
    # Temporal
    timestamp: float = field(default_factory=time.time)

@dataclass
class RuleEngineConfig:
    """Configuration for rules engine."""
    
    # Rule loading
    rules_directories: List[str] = field(default_factory=lambda: ["rules"])
    enable_custom_rules: bool = True
    auto_reload_rules: bool = True
    rules_cache_size: int = 1000
    
    # Pattern matching
    enable_regex_optimization: bool = True
    max_pattern_complexity: int = 1000
    pattern_timeout_seconds: float = 5.0
    enable_fuzzy_matching: bool = True
    fuzzy_threshold: float = 0.8
    
    # Performance
    max_concurrent_rules: int = 100
    rule_execution_timeout: float = 30.0
    enable_rule_caching: bool = True
    cache_ttl_seconds: int = 3600
    
    # Machine learning
    enable_ml_enhancement: bool = True
    ml_model_update_interval: int = 86400  # 24 hours
    min_samples_for_learning: int = 100
    feature_extraction_enabled: bool = True
    
    # Adaptation and learning
    enable_adaptive_rules: bool = True
    false_positive_threshold: float = 0.3
    adaptation_learning_rate: float = 0.1
    rule_retirement_threshold: float = 0.1
    
    # Context analysis
    enable_context_analysis: bool = True
    context_window_lines: int = 10
    enable_semantic_analysis: bool = True
    
    # Rule management
    enable_rule_versioning: bool = True
    max_rule_versions: int = 10
    enable_rule_metrics: bool = True
    metrics_retention_days: int = 30

class RulesEngine:
    """Advanced security rules intelligence engine."""
    
    def __init__(self, config: RuleEngineConfig = None):
        self.config = config or RuleEngineConfig()
        
        # Rule storage
        self.rules: Dict[str, SecurityRule] = {}
        self.rule_categories: Dict[RuleCategory, List[str]] = defaultdict(list)
        self.rule_patterns_cache: Dict[str, List[Pattern]] = {}
        
        # Performance optimization
        self.rule_executor = RuleExecutor(self.config)
        self.pattern_optimizer = PatternOptimizer(self.config)
        self.context_analyzer = ContextAnalyzer(self.config)
        
        # Machine learning components
        if self.config.enable_ml_enhancement:
            self.ml_enhancer = MLRuleEnhancer(self.config)
            self.feature_extractor = FeatureExtractor(self.config)
        else:
            self.ml_enhancer = None
            self.feature_extractor = None
        
        # Adaptation and learning
        if self.config.enable_adaptive_rules:
            self.rule_learner = RuleLearner(self.config)
            self.false_positive_detector = FalsePositiveDetector(self.config)
        else:
            self.rule_learner = None
            self.false_positive_detector = None
        
        # Rule management
        self.rule_manager = RuleManager(self.config)
        self.rule_loader = RuleLoader(self.config)
        
        # Statistics and metrics
        self.stats = {
            'rules_loaded': 0,
            'rules_executed': 0,
            'matches_found': 0,
            'false_positives_detected': 0,
            'rules_adapted': 0,
            'execution_time_total': 0.0,
            'average_execution_time': 0.0,
            'cache_hits': 0,
            'cache_misses': 0
        }
        
        # Background tasks
        self.background_tasks: List[asyncio.Task] = []
        self.running = False
        self.shutdown_event = asyncio.Event()
        
        # Thread pool for CPU-intensive operations
        self.thread_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="rules_engine")
        
        # Synchronization
        self.rules_lock = threading.RLock()
        self.stats_lock = threading.Lock()
        
        self.start_time = time.time()
    
    async def initialize(self):
        """Initialize the rules engine."""
        
        logger.info("Initializing Security Rules Intelligence Engine")
        
        self.running = True
        
        # Initialize components
        await self.rule_executor.initialize()
        await self.pattern_optimizer.initialize()
        await self.context_analyzer.initialize()
        
        if self.ml_enhancer:
            await self.ml_enhancer.initialize()
            await self.feature_extractor.initialize()
        
        if self.rule_learner:
            await self.rule_learner.initialize()
            await self.false_positive_detector.initialize()
        
        await self.rule_manager.initialize()
        
        # Load rules
        await self.load_rules()
        
        # Start background tasks
        self.background_tasks = [
            asyncio.create_task(self._rule_maintenance_worker()),
            asyncio.create_task(self._metrics_collection_worker())
        ]
        
        if self.config.enable_ml_enhancement:
            self.background_tasks.append(
                asyncio.create_task(self._ml_enhancement_worker())
            )
        
        if self.config.enable_adaptive_rules:
            self.background_tasks.append(
                asyncio.create_task(self._adaptation_worker())
            )
        
        logger.info(f"Rules Engine initialized with {len(self.rules)} rules")
    
    async def load_rules(self):
        """Load security rules from various sources."""
        
        logger.info("Loading security rules")
        
        try:
            # Load from directories
            loaded_rules = await self.rule_loader.load_from_directories(
                self.config.rules_directories
            )
            
            # Load built-in rules
            builtin_rules = await self._load_builtin_rules()
            loaded_rules.extend(builtin_rules)
            
            # Process and store rules
            with self.rules_lock:
                for rule in loaded_rules:
                    self.rules[rule.rule_id] = rule
                    self.rule_categories[rule.category].append(rule.rule_id)
                
                # Optimize patterns
                await self._optimize_rule_patterns()
            
            self.stats['rules_loaded'] = len(self.rules)
            
            logger.info(f"Loaded {len(loaded_rules)} security rules")
            
        except Exception as e:
            logger.error(f"Failed to load rules: {str(e)}")
    
    async def analyze_code(self, file_path: str, content: str, 
                          context: Dict[str, Any] = None) -> List[RuleMatch]:
        """Analyze code content against security rules."""
        
        start_time = time.time()
        
        try:
            matches = []
            context = context or {}
            
            # Determine applicable rules
            applicable_rules = await self._get_applicable_rules(file_path, content, context)
            
            # Execute rules
            for rule in applicable_rules:
                rule_matches = await self._execute_rule(rule, file_path, content, context)
                matches.extend(rule_matches)
            
            # Post-process matches
            matches = await self._post_process_matches(matches, file_path, content, context)
            
            # Update statistics
            execution_time = time.time() - start_time
            with self.stats_lock:
                self.stats['rules_executed'] += len(applicable_rules)
                self.stats['matches_found'] += len(matches)
                self.stats['execution_time_total'] += execution_time
                
                if self.stats['rules_executed'] > 0:
                    self.stats['average_execution_time'] = (
                        self.stats['execution_time_total'] / self.stats['rules_executed']
                    )
            
            logger.debug(f"Code analysis completed: {len(matches)} matches found "
                        f"({execution_time:.3f}s, {len(applicable_rules)} rules)")
            
            return matches
            
        except Exception as e:
            logger.error(f"Code analysis error: {str(e)}")
            return []
    
    async def add_rule(self, rule: SecurityRule) -> bool:
        """Add new security rule."""
        
        try:
            # Validate rule
            if not await self._validate_rule(rule):
                logger.error(f"Rule validation failed: {rule.rule_id}")
                return False
            
            # Optimize rule patterns
            await self._optimize_rule_patterns_for_rule(rule)
            
            # Add rule
            with self.rules_lock:
                self.rules[rule.rule_id] = rule
                self.rule_categories[rule.category].append(rule.rule_id)
            
            logger.info(f"Added security rule: {rule.rule_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add rule: {str(e)}")
            return False
    
    async def remove_rule(self, rule_id: str) -> bool:
        """Remove security rule."""
        
        try:
            with self.rules_lock:
                if rule_id not in self.rules:
                    return False
                
                rule = self.rules[rule_id]
                del self.rules[rule_id]
                
                # Remove from category
                if rule_id in self.rule_categories[rule.category]:
                    self.rule_categories[rule.category].remove(rule_id)
                
                # Clear pattern cache
                if rule_id in self.rule_patterns_cache:
                    del self.rule_patterns_cache[rule_id]
            
            logger.info(f"Removed security rule: {rule_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove rule: {str(e)}")
            return False
    
    async def update_rule(self, rule: SecurityRule) -> bool:
        """Update existing security rule."""
        
        try:
            if rule.rule_id not in self.rules:
                logger.error(f"Rule not found for update: {rule.rule_id}")
                return False
            
            # Validate updated rule
            if not await self._validate_rule(rule):
                logger.error(f"Updated rule validation failed: {rule.rule_id}")
                return False
            
            # Update timestamp
            rule.updated_at = time.time()
            
            # Optimize patterns
            await self._optimize_rule_patterns_for_rule(rule)
            
            # Update rule
            with self.rules_lock:
                old_category = self.rules[rule.rule_id].category
                self.rules[rule.rule_id] = rule
                
                # Update category if changed
                if old_category != rule.category:
                    if rule.rule_id in self.rule_categories[old_category]:
                        self.rule_categories[old_category].remove(rule.rule_id)
                    self.rule_categories[rule.category].append(rule.rule_id)
            
            logger.info(f"Updated security rule: {rule.rule_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update rule: {str(e)}")
            return False
    
    async def get_rule_statistics(self) -> Dict[str, Any]:
        """Get comprehensive rule statistics."""
        
        try:
            with self.rules_lock:
                # Basic statistics
                stats = dict(self.stats)
                stats['total_rules'] = len(self.rules)
                stats['uptime'] = time.time() - self.start_time
                
                # Rule breakdown by category
                stats['rules_by_category'] = {}
                for category, rule_ids in self.rule_categories.items():
                    stats['rules_by_category'][category.value] = len(rule_ids)
                
                # Rule breakdown by severity
                stats['rules_by_severity'] = {}
                severity_counts = Counter(rule.severity.value for rule in self.rules.values())
                stats['rules_by_severity'] = dict(severity_counts)
                
                # Rule breakdown by type
                stats['rules_by_type'] = {}
                type_counts = Counter(rule.rule_type.value for rule in self.rules.values())
                stats['rules_by_type'] = dict(type_counts)
                
                # Performance statistics
                stats['enabled_rules'] = sum(1 for rule in self.rules.values() if rule.enabled)
                stats['disabled_rules'] = len(self.rules) - stats['enabled_rules']
                
                # Effectiveness statistics
                effective_rules = [
                    rule for rule in self.rules.values()
                    if rule.calculate_effectiveness_score() > 0.7
                ]
                stats['effective_rules'] = len(effective_rules)
                stats['effectiveness_rate'] = len(effective_rules) / max(1, len(self.rules))
                
                # Cache statistics
                stats['pattern_cache_size'] = len(self.rule_patterns_cache)
                
                return stats
                
        except Exception as e:
            logger.error(f"Failed to get rule statistics: {str(e)}")
            return {}
    
    async def optimize_rules(self) -> Dict[str, Any]:
        """Optimize rule performance and effectiveness."""
        
        logger.info("Starting rule optimization")
        
        try:
            optimization_results = {
                'optimizations_applied': [],
                'performance_improvement': 0.0,
                'rules_optimized': 0
            }
            
            # Pattern optimization
            pattern_results = await self.pattern_optimizer.optimize_patterns(self.rules)
            if pattern_results['optimized_count'] > 0:
                optimization_results['optimizations_applied'].append('pattern_optimization')
                optimization_results['rules_optimized'] += pattern_results['optimized_count']
            
            # Rule prioritization optimization
            priority_results = await self._optimize_rule_priorities()
            if priority_results['reordered_count'] > 0:
                optimization_results['optimizations_applied'].append('priority_optimization')
                optimization_results['rules_optimized'] += priority_results['reordered_count']
            
            # False positive reduction
            if self.false_positive_detector:
                fp_results = await self.false_positive_detector.reduce_false_positives(self.rules)
                if fp_results['rules_adjusted'] > 0:
                    optimization_results['optimizations_applied'].append('false_positive_reduction')
                    optimization_results['rules_optimized'] += fp_results['rules_adjusted']
            
            # Machine learning enhancement
            if self.ml_enhancer:
                ml_results = await self.ml_enhancer.enhance_rules(self.rules)
                if ml_results['rules_enhanced'] > 0:
                    optimization_results['optimizations_applied'].append('ml_enhancement')
                    optimization_results['rules_optimized'] += ml_results['rules_enhanced']
            
            logger.info(f"Rule optimization completed: {len(optimization_results['optimizations_applied'])} "
                       f"optimizations applied to {optimization_results['rules_optimized']} rules")
            
            return optimization_results
            
        except Exception as e:
            logger.error(f"Rule optimization failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    # Private methods
    
    async def _load_builtin_rules(self) -> List[SecurityRule]:
        """Load built-in security rules."""
        
        builtin_rules = []
        
        # SQL Injection rules
        sql_injection_rule = SecurityRule(
            rule_id="sql_injection_basic",
            name="Basic SQL Injection Detection",
            description="Detects basic SQL injection patterns",
            category=RuleCategory.INJECTION,
            severity=RuleSeverity.HIGH,
            confidence=RuleConfidence.HIGH,
            rule_type=RuleType.STATIC_PATTERN,
            patterns=[
                RulePattern(
                    pattern_id="sql_injection_1",
                    pattern=r"(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*\s+(FROM|INTO|SET|WHERE)",
                    match_type=MatchType.REGEX,
                    case_sensitive=False
                ),
                RulePattern(
                    pattern_id="sql_injection_2",
                    pattern=r"(UNION\s+SELECT|OR\s+1\s*=\s*1|AND\s+1\s*=\s*1)",
                    match_type=MatchType.REGEX,
                    case_sensitive=False
                )
            ],
            frameworks={"nextjs", "react", "vite"},
            file_types={"js", "ts", "jsx", "tsx"},
            cwe_ids=["CWE-89"],
            owasp_categories=["A03:2021 - Injection"]
        )
        builtin_rules.append(sql_injection_rule)
        
        # XSS rules
        xss_rule = SecurityRule(
            rule_id="xss_basic",
            name="Basic XSS Detection",
            description="Detects basic cross-site scripting patterns",
            category=RuleCategory.XSS,
            severity=RuleSeverity.HIGH,
            confidence=RuleConfidence.HIGH,
            rule_type=RuleType.STATIC_PATTERN,
            patterns=[
                RulePattern(
                    pattern_id="xss_script_tag",
                    pattern=r"<script[^>]*>.*?</script>",
                    match_type=MatchType.REGEX,
                    case_sensitive=False,
                    multiline=True
                ),
                RulePattern(
                    pattern_id="xss_event_handler",
                    pattern=r"on(click|load|error|mouseover)\s*=\s*[\"'].*?[\"']",
                    match_type=MatchType.REGEX,
                    case_sensitive=False
                ),
                RulePattern(
                    pattern_id="xss_javascript_protocol",
                    pattern=r"javascript\s*:",
                    match_type=MatchType.REGEX,
                    case_sensitive=False
                )
            ],
            frameworks={"nextjs", "react", "vite"},
            file_types={"js", "ts", "jsx", "tsx", "html"},
            cwe_ids=["CWE-79"],
            owasp_categories=["A03:2021 - Injection"]
        )
        builtin_rules.append(xss_rule)
        
        # Hardcoded secrets rule
        secrets_rule = SecurityRule(
            rule_id="hardcoded_secrets",
            name="Hardcoded Secrets Detection",
            description="Detects hardcoded secrets and credentials",
            category=RuleCategory.CRYPTOGRAPHY,
            severity=RuleSeverity.CRITICAL,
            confidence=RuleConfidence.MEDIUM,
            rule_type=RuleType.STATIC_PATTERN,
            patterns=[
                RulePattern(
                    pattern_id="api_key_pattern",
                    pattern=r"(api[_-]?key|apikey)\s*[=:]\s*[\"']([a-zA-Z0-9]{20,})[\"']",
                    match_type=MatchType.REGEX,
                    case_sensitive=False
                ),
                RulePattern(
                    pattern_id="password_pattern",
                    pattern=r"(password|pwd|pass)\s*[=:]\s*[\"']([^\"']{8,})[\"']",
                    match_type=MatchType.REGEX,
                    case_sensitive=False
                ),
                RulePattern(
                    pattern_id="token_pattern",
                    pattern=r"(token|secret|key)\s*[=:]\s*[\"']([a-zA-Z0-9+/]{32,})[\"']",
                    match_type=MatchType.REGEX,
                    case_sensitive=False
                )
            ],
            frameworks={"nextjs", "react", "vite"},
            file_types={"js", "ts", "json", "env"},
            cwe_ids=["CWE-798"],
            owasp_categories=["A07:2021 - Identification and Authentication Failures"]
        )
        builtin_rules.append(secrets_rule)
        
        # Insecure random number generation
        random_rule = SecurityRule(
            rule_id="insecure_random",
            name="Insecure Random Number Generation",
            description="Detects use of insecure random number generators",
            category=RuleCategory.CRYPTOGRAPHY,
            severity=RuleSeverity.MEDIUM,
            confidence=RuleConfidence.HIGH,
            rule_type=RuleType.STATIC_PATTERN,
            patterns=[
                RulePattern(
                    pattern_id="math_random",
                    pattern=r"Math\.random\(\)",
                    match_type=MatchType.REGEX
                ),
                RulePattern(
                    pattern_id="weak_random_functions",
                    pattern=r"(rand\(\)|random\(\)|srand\(\))",
                    match_type=MatchType.REGEX
                )
            ],
            frameworks={"nextjs", "react", "vite"},
            file_types={"js", "ts"},
            cwe_ids=["CWE-338"],
            owasp_categories=["A02:2021 - Cryptographic Failures"]
        )
        builtin_rules.append(random_rule)
        
        # Eval usage rule
        eval_rule = SecurityRule(
            rule_id="dangerous_eval",
            name="Dangerous eval() Usage",
            description="Detects dangerous use of eval() function",
            category=RuleCategory.INJECTION,
            severity=RuleSeverity.HIGH,
            confidence=RuleConfidence.VERY_HIGH,
            rule_type=RuleType.STATIC_PATTERN,
            patterns=[
                RulePattern(
                    pattern_id="eval_function",
                    pattern=r"\beval\s*\(",
                    match_type=MatchType.REGEX
                ),
                RulePattern(
                    pattern_id="function_constructor",
                    pattern=r"new\s+Function\s*\(",
                    match_type=MatchType.REGEX
                ),
                RulePattern(
                    pattern_id="settimeout_string",
                    pattern=r"setTimeout\s*\(\s*[\"'].*[\"']\s*,",
                    match_type=MatchType.REGEX
                )
            ],
            frameworks={"nextjs", "react", "vite"},
            file_types={"js", "ts"},
            cwe_ids=["CWE-95"],
            owasp_categories=["A03:2021 - Injection"]
        )
        builtin_rules.append(eval_rule)
        
        logger.info(f"Loaded {len(builtin_rules)} built-in security rules")
        
        return builtin_rules
    
    async def _get_applicable_rules(self, file_path: str, content: str, 
                                   context: Dict[str, Any]) -> List[SecurityRule]:
        """Get rules applicable to the given file and context."""
        
        applicable_rules = []
        file_extension = Path(file_path).suffix.lstrip('.')
        
        with self.rules_lock:
            for rule in self.rules.values():
                if not rule.enabled:
                    continue
                
                # Check file type compatibility
                if rule.file_types and file_extension not in rule.file_types:
                    continue
                
                # Check framework compatibility
                framework = context.get('framework')
                if rule.frameworks and framework and framework not in rule.frameworks:
                    continue
                
                # Check conditions
                if not await self._check_rule_conditions(rule, file_path, content, context):
                    continue
                
                applicable_rules.append(rule)
        
        # Sort by priority (higher priority first)
        applicable_rules.sort(key=lambda r: r.priority, reverse=True)
        
        return applicable_rules
    
    async def _check_rule_conditions(self, rule: SecurityRule, file_path: str, 
                                   content: str, context: Dict[str, Any]) -> bool:
        """Check if rule conditions are met."""
        
        try:
            for condition in rule.conditions:
                if not await self._evaluate_condition(condition, file_path, content, context):
                    return False
            return True
        except Exception as e:
            logger.error(f"Condition evaluation error for rule {rule.rule_id}: {str(e)}")
            return False
    
    async def _evaluate_condition(self, condition: RuleCondition, file_path: str,
                                content: str, context: Dict[str, Any]) -> bool:
        """Evaluate a single rule condition."""
        
        try:
            if condition.condition_type == "file_type":
                file_ext = Path(file_path).suffix.lstrip('.')
                result = self._apply_operator(condition.operator, file_ext, condition.value)
            
            elif condition.condition_type == "file_size":
                file_size = len(content)
                result = self._apply_operator(condition.operator, file_size, condition.value)
            
            elif condition.condition_type == "framework":
                framework = context.get('framework', '')
                result = self._apply_operator(condition.operator, framework, condition.value)
            
            elif condition.condition_type == "content_contains":
                result = self._apply_operator(condition.operator, content, condition.value)
            
            else:
                logger.warning(f"Unknown condition type: {condition.condition_type}")
                result = True
            
            return not result if condition.negated else result
            
        except Exception as e:
            logger.error(f"Condition evaluation error: {str(e)}")
            return False
    
    def _apply_operator(self, operator: str, actual: Any, expected: Any) -> bool:
        """Apply comparison operator."""
        
        try:
            if operator == "equals":
                return actual == expected
            elif operator == "contains":
                return expected in actual
            elif operator == "matches":
                return bool(re.search(expected, str(actual)))
            elif operator == "greater_than":
                return actual > expected
            elif operator == "less_than":
                return actual < expected
            elif operator == "in":
                return actual in expected
            else:
                logger.warning(f"Unknown operator: {operator}")
                return True
        except Exception:
            return False
    
    async def _execute_rule(self, rule: SecurityRule, file_path: str, 
                          content: str, context: Dict[str, Any]) -> List[RuleMatch]:
        """Execute a single security rule."""
        
        try:
            matches = []
            
            # Execute patterns
            for pattern in rule.patterns:
                pattern_matches = await self._execute_pattern(
                    rule, pattern, file_path, content, context
                )
                matches.extend(pattern_matches)
            
            # Execute custom validator if present
            if rule.custom_validator:
                try:
                    custom_matches = await asyncio.get_event_loop().run_in_executor(
                        self.thread_pool, rule.custom_validator, file_path, content, context
                    )
                    if custom_matches:
                        matches.extend(custom_matches)
                except Exception as e:
                    logger.error(f"Custom validator error for rule {rule.rule_id}: {str(e)}")
            
            # Update rule statistics
            if matches:
                rule.last_matched = time.time()
                rule.match_count += len(matches)
            
            return matches
            
        except Exception as e:
            logger.error(f"Rule execution error for {rule.rule_id}: {str(e)}")
            return []
    
    async def _execute_pattern(self, rule: SecurityRule, pattern: RulePattern,
                             file_path: str, content: str, context: Dict[str, Any]) -> List[RuleMatch]:
        """Execute a single pattern within a rule."""
        
        try:
            matches = []
            
            if pattern.match_type == MatchType.EXACT:
                matches = self._find_exact_matches(rule, pattern, file_path, content)
            
            elif pattern.match_type == MatchType.REGEX:
                matches = self._find_regex_matches(rule, pattern, file_path, content)
            
            elif pattern.match_type == MatchType.FUZZY:
                matches = await self._find_fuzzy_matches(rule, pattern, file_path, content)
            
            elif pattern.match_type == MatchType.SEMANTIC:
                matches = await self._find_semantic_matches(rule, pattern, file_path, content, context)
            
            elif pattern.match_type == MatchType.BEHAVIORAL:
                matches = await self._find_behavioral_matches(rule, pattern, file_path, content, context)
            
            return matches
            
        except Exception as e:
            logger.error(f"Pattern execution error for {pattern.pattern_id}: {str(e)}")
            return []
    
    def _find_exact_matches(self, rule: SecurityRule, pattern: RulePattern,
                           file_path: str, content: str) -> List[RuleMatch]:
        """Find exact string matches."""
        
        matches = []
        lines = content.split('\n')
        
        search_text = pattern.pattern
        if not pattern.case_sensitive:
            search_text = search_text.lower()
            search_content = content.lower()
        else:
            search_content = content
        
        start_pos = 0
        while True:
            pos = search_content.find(search_text, start_pos)
            if pos == -1:
                break
            
            # Find line number
            line_num = search_content[:pos].count('\n') + 1
            line_start = search_content.rfind('\n', 0, pos) + 1
            col_num = pos - line_start + 1
            
            match = RuleMatch(
                rule_id=rule.rule_id,
                match_id=f"{rule.rule_id}_{pattern.pattern_id}_{pos}",
                file_path=file_path,
                line_number=line_num,
                column_number=col_num,
                matched_text=content[pos:pos+len(pattern.pattern)],
                pattern_id=pattern.pattern_id,
                match_type=MatchType.EXACT,
                confidence_score=rule.confidence.value
            )
            
            matches.append(match)
            start_pos = pos + 1
        
        return matches
    
    def _find_regex_matches(self, rule: SecurityRule, pattern: RulePattern,
                           file_path: str, content: str) -> List[RuleMatch]:
        """Find regex pattern matches."""
        
        matches = []
        compiled_pattern = pattern.compile_pattern()
        
        if not compiled_pattern:
            return matches
        
        try:
            for match in compiled_pattern.finditer(content):
                # Find line number
                line_num = content[:match.start()].count('\n') + 1
                line_start = content.rfind('\n', 0, match.start()) + 1
                col_num = match.start() - line_start + 1
                
                rule_match = RuleMatch(
                    rule_id=rule.rule_id,
                    match_id=f"{rule.rule_id}_{pattern.pattern_id}_{match.start()}",
                    file_path=file_path,
                    line_number=line_num,
                    column_number=col_num,
                    matched_text=match.group(0),
                    pattern_id=pattern.pattern_id,
                    match_type=MatchType.REGEX,
                    confidence_score=rule.confidence.value
                )
                
                matches.append(rule_match)
                
        except Exception as e:
            logger.error(f"Regex matching error: {str(e)}")
        
        return matches
    
    async def _find_fuzzy_matches(self, rule: SecurityRule, pattern: RulePattern,
                                file_path: str, content: str) -> List[RuleMatch]:
        """Find fuzzy pattern matches."""
        
        # This would implement fuzzy string matching
        # For now, return empty list
        return []
    
    async def _find_semantic_matches(self, rule: SecurityRule, pattern: RulePattern,
                                   file_path: str, content: str, context: Dict[str, Any]) -> List[RuleMatch]:
        """Find semantic pattern matches using context analysis."""
        
        if not self.context_analyzer:
            return []
        
        return await self.context_analyzer.find_semantic_matches(
            rule, pattern, file_path, content, context
        )
    
    async def _find_behavioral_matches(self, rule: SecurityRule, pattern: RulePattern,
                                     file_path: str, content: str, context: Dict[str, Any]) -> List[RuleMatch]:
        """Find behavioral pattern matches."""
        
        # This would implement behavioral analysis
        # For now, return empty list
        return []
    
    async def _post_process_matches(self, matches: List[RuleMatch], file_path: str,
                                  content: str, context: Dict[str, Any]) -> List[RuleMatch]:
        """Post-process matches to reduce false positives and enhance results."""
        
        if not matches:
            return matches
        
        processed_matches = []
        
        for match in matches:
            # Context enhancement
            if self.context_analyzer:
                enhanced_match = await self.context_analyzer.enhance_match(
                    match, file_path, content, context
                )
                if enhanced_match:
                    processed_matches.append(enhanced_match)
            else:
                processed_matches.append(match)
        
        # False positive detection
        if self.false_positive_detector:
            filtered_matches = await self.false_positive_detector.filter_matches(
                processed_matches, file_path, content, context
            )
            processed_matches = filtered_matches
        
        return processed_matches
    
    async def _validate_rule(self, rule: SecurityRule) -> bool:
        """Validate security rule."""
        
        try:
            # Basic validation
            if not rule.rule_id or not rule.name:
                return False
            
            # Pattern validation
            for pattern in rule.patterns:
                if pattern.match_type == MatchType.REGEX:
                    compiled = pattern.compile_pattern()
                    if not compiled:
                        return False
            
            # Condition validation
            for condition in rule.conditions:
                if not condition.condition_id or not condition.condition_type:
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Rule validation error: {str(e)}")
            return False
    
    async def _optimize_rule_patterns(self):
        """Optimize patterns for all rules."""
        
        with self.rules_lock:
            for rule in self.rules.values():
                await self._optimize_rule_patterns_for_rule(rule)
    
    async def _optimize_rule_patterns_for_rule(self, rule: SecurityRule):
        """Optimize patterns for a specific rule."""
        
        try:
            optimized_patterns = []
            
            for pattern in rule.patterns:
                if pattern.match_type == MatchType.REGEX:
                    # Compile and cache pattern
                    compiled = pattern.compile_pattern()
                    if compiled:
                        optimized_patterns.append(compiled)
            
            if optimized_patterns:
                self.rule_patterns_cache[rule.rule_id] = optimized_patterns
                
        except Exception as e:
            logger.error(f"Pattern optimization error for rule {rule.rule_id}: {str(e)}")
    
    async def _optimize_rule_priorities(self) -> Dict[str, Any]:
        """Optimize rule execution priorities based on performance and effectiveness."""
        
        reordered_count = 0
        
        try:
            with self.rules_lock:
                # Calculate new priorities based on effectiveness and performance
                for rule in self.rules.values():
                    effectiveness = rule.calculate_effectiveness_score()
                    
                    # Adjust priority based on effectiveness
                    new_priority = int(rule.priority * effectiveness)
                    
                    if new_priority != rule.priority:
                        rule.priority = new_priority
                        reordered_count += 1
            
            return {
                'reordered_count': reordered_count,
                'success': True
            }
            
        except Exception as e:
            logger.error(f"Rule priority optimization error: {str(e)}")
            return {'reordered_count': 0, 'success': False}
    
    # Background workers
    
    async def _rule_maintenance_worker(self):
        """Background rule maintenance worker."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(3600)  # Run every hour
                
                # Perform rule maintenance tasks
                await self._cleanup_ineffective_rules()
                await self._update_rule_statistics()
                
            except Exception as e:
                logger.error(f"Rule maintenance worker error: {str(e)}")
    
    async def _metrics_collection_worker(self):
        """Background metrics collection worker."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                
                # Collect and update metrics
                await self._collect_performance_metrics()
                
            except Exception as e:
                logger.error(f"Metrics collection worker error: {str(e)}")
    
    async def _ml_enhancement_worker(self):
        """Background ML enhancement worker."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(self.config.ml_model_update_interval)
                
                if self.ml_enhancer:
                    await self.ml_enhancer.update_models(self.rules)
                
            except Exception as e:
                logger.error(f"ML enhancement worker error: {str(e)}")
    
    async def _adaptation_worker(self):
        """Background adaptation worker."""
        
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(1800)  # Run every 30 minutes
                
                if self.rule_learner:
                    await self.rule_learner.adapt_rules(self.rules)
                
            except Exception as e:
                logger.error(f"Adaptation worker error: {str(e)}")
    
    async def _cleanup_ineffective_rules(self):
        """Clean up rules with low effectiveness."""
        
        try:
            with self.rules_lock:
                ineffective_rules = [
                    rule_id for rule_id, rule in self.rules.items()
                    if (rule.calculate_effectiveness_score() < self.config.rule_retirement_threshold and
                        rule.match_count > 10)  # Only consider rules with some history
                ]
                
                for rule_id in ineffective_rules:
                    logger.info(f"Disabling ineffective rule: {rule_id}")
                    self.rules[rule_id].enabled = False
                    
        except Exception as e:
            logger.error(f"Rule cleanup error: {str(e)}")
    
    async def _update_rule_statistics(self):
        """Update rule performance statistics."""
        
        # This would implement detailed statistics updates
        pass
    
    async def _collect_performance_metrics(self):
        """Collect performance metrics."""
        
        # This would implement performance metrics collection
        pass
    
    async def shutdown(self):
        """Shutdown rules engine."""
        
        logger.info("Shutting down Security Rules Intelligence Engine")
        
        self.running = False
        self.shutdown_event.set()
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        # Wait for background tasks to complete
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        # Shutdown components
        await self.rule_executor.shutdown()
        await self.pattern_optimizer.shutdown()
        await self.context_analyzer.shutdown()
        
        if self.ml_enhancer:
            await self.ml_enhancer.shutdown()
            await self.feature_extractor.shutdown()
        
        if self.rule_learner:
            await self.rule_learner.shutdown()
            await self.false_positive_detector.shutdown()
        
        await self.rule_manager.shutdown()
        
        # Shutdown thread pool
        self.thread_pool.shutdown(wait=True)
        
        logger.info("Security Rules Intelligence Engine shutdown completed")


# Helper classes (stubs for now - would be implemented based on specific requirements)

class RuleExecutor:
    """Rule execution engine."""
    
    def __init__(self, config: RuleEngineConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def shutdown(self):
        pass


class PatternOptimizer:
    """Pattern optimization engine."""
    
    def __init__(self, config: RuleEngineConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def optimize_patterns(self, rules: Dict[str, SecurityRule]) -> Dict[str, Any]:
        return {'optimized_count': 0}
    
    async def shutdown(self):
        pass


class ContextAnalyzer:
    """Context analysis engine."""
    
    def __init__(self, config: RuleEngineConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def find_semantic_matches(self, rule: SecurityRule, pattern: RulePattern,
                                  file_path: str, content: str, context: Dict[str, Any]) -> List[RuleMatch]:
        return []
    
    async def enhance_match(self, match: RuleMatch, file_path: str,
                          content: str, context: Dict[str, Any]) -> Optional[RuleMatch]:
        return match
    
    async def shutdown(self):
        pass


class MLRuleEnhancer:
    """Machine learning rule enhancement."""
    
    def __init__(self, config: RuleEngineConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def enhance_rules(self, rules: Dict[str, SecurityRule]) -> Dict[str, Any]:
        return {'rules_enhanced': 0}
    
    async def update_models(self, rules: Dict[str, SecurityRule]):
        pass
    
    async def shutdown(self):
        pass


class FeatureExtractor:
    """Feature extraction for ML."""
    
    def __init__(self, config: RuleEngineConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def shutdown(self):
        pass


class RuleLearner:
    """Rule learning and adaptation."""
    
    def __init__(self, config: RuleEngineConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def adapt_rules(self, rules: Dict[str, SecurityRule]):
        pass
    
    async def shutdown(self):
        pass


class FalsePositiveDetector:
    """False positive detection and reduction."""
    
    def __init__(self, config: RuleEngineConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def reduce_false_positives(self, rules: Dict[str, SecurityRule]) -> Dict[str, Any]:
        return {'rules_adjusted': 0}
    
    async def filter_matches(self, matches: List[RuleMatch], file_path: str,
                           content: str, context: Dict[str, Any]) -> List[RuleMatch]:
        return matches
    
    async def shutdown(self):
        pass


class RuleManager:
    """Rule management and versioning."""
    
    def __init__(self, config: RuleEngineConfig):
        self.config = config
    
    async def initialize(self):
        pass
    
    async def shutdown(self):
        pass


class RuleLoader:
    """Rule loading from various sources."""
    
    def __init__(self, config: RuleEngineConfig):
        self.config = config
    
    async def load_from_directories(self, directories: List[str]) -> List[SecurityRule]:
        """Load rules from directories."""
        # This would implement actual rule loading from files
        return []
