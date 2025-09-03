"""
Quality Gates Engine

Comprehensive quality gate system for security policy enforcement including:
- Configurable security policies and rules
- Multi-level quality gates (project, branch, environment)
- Risk-based decision making
- Compliance validation
- Automated approval workflows
- Policy violation tracking and reporting
"""

import json
import time
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class PolicyLevel(Enum):
    """Policy enforcement levels."""
    PROJECT = "project"
    BRANCH = "branch"
    ENVIRONMENT = "environment"
    GLOBAL = "global"

class RuleOperator(Enum):
    """Rule comparison operators."""
    GREATER_THAN = "gt"
    GREATER_THAN_EQUAL = "gte"
    LESS_THAN = "lt"
    LESS_THAN_EQUAL = "lte"
    EQUAL = "eq"
    NOT_EQUAL = "ne"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    IN = "in"
    NOT_IN = "not_in"

class RuleSeverity(Enum):
    """Rule severity levels."""
    BLOCKER = "blocker"
    CRITICAL = "critical"
    MAJOR = "major"
    MINOR = "minor"
    INFO = "info"

class GateStatus(Enum):
    """Quality gate status."""
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    ERROR = "error"
    PENDING = "pending"

@dataclass
class QualityRule:
    """Individual quality rule definition."""
    rule_id: str
    name: str
    description: str
    
    # Rule conditions
    metric: str
    operator: RuleOperator
    threshold: Union[int, float, str, List[Any]]
    
    # Rule metadata
    severity: RuleSeverity = RuleSeverity.MAJOR
    category: str = "security"
    enabled: bool = True
    
    # Scope and applicability
    applies_to_branches: List[str] = field(default_factory=list)  # Empty = all branches
    applies_to_environments: List[str] = field(default_factory=list)  # Empty = all environments
    applies_to_file_patterns: List[str] = field(default_factory=list)  # Empty = all files
    
    # Advanced conditions
    conditions: List[Dict[str, Any]] = field(default_factory=list)  # Additional AND conditions
    exceptions: List[Dict[str, Any]] = field(default_factory=list)  # Exception conditions
    
    # Rule behavior
    block_deployment: bool = True
    send_notification: bool = True
    auto_waiver_conditions: List[Dict[str, Any]] = field(default_factory=list)
    
    # Metadata
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    created_by: str = "system"
    tags: List[str] = field(default_factory=list)

@dataclass
class QualityPolicy:
    """Quality policy containing multiple rules."""
    policy_id: str
    name: str
    description: str
    
    # Policy rules
    rules: List[QualityRule] = field(default_factory=list)
    
    # Policy configuration
    level: PolicyLevel = PolicyLevel.PROJECT
    enabled: bool = True
    strict_mode: bool = False  # If true, all rules must pass
    
    # Scope
    applies_to_repositories: List[str] = field(default_factory=list)
    applies_to_branches: List[str] = field(default_factory=list)
    applies_to_environments: List[str] = field(default_factory=list)
    
    # Policy behavior
    allow_overrides: bool = True
    require_approval_for_overrides: bool = True
    override_approvers: List[str] = field(default_factory=list)
    
    # Notification settings
    notification_channels: List[str] = field(default_factory=list)
    escalation_rules: List[Dict[str, Any]] = field(default_factory=list)
    
    # Metadata
    version: str = "1.0"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    created_by: str = "system"

@dataclass
class RuleEvaluation:
    """Result of rule evaluation."""
    rule_id: str
    rule_name: str
    
    # Evaluation result
    passed: bool
    actual_value: Any
    threshold_value: Any
    
    # Details
    metric: str
    operator: str
    severity: str
    message: str
    
    # Context
    evaluation_time: float = field(default_factory=time.time)
    context: Dict[str, Any] = field(default_factory=dict)
    
    # Waiver information
    waived: bool = False
    waiver_reason: str = ""
    waiver_approved_by: str = ""
    waiver_expires_at: Optional[float] = None

@dataclass
class QualityGateResult:
    """Result of quality gate evaluation."""
    gate_id: str
    repository: str
    branch: str
    commit_sha: str
    
    # Overall result
    status: GateStatus
    passed: bool
    score: float  # 0-100
    
    # Rule evaluations
    rule_evaluations: List[RuleEvaluation] = field(default_factory=list)
    
    # Summary
    total_rules: int = 0
    passed_rules: int = 0
    failed_rules: int = 0
    waived_rules: int = 0
    
    # Severity breakdown
    blocker_failures: int = 0
    critical_failures: int = 0
    major_failures: int = 0
    minor_failures: int = 0
    
    # Metadata
    evaluation_time: float = field(default_factory=time.time)
    evaluation_duration: float = 0.0
    policy_version: str = "1.0"
    
    # Additional context
    scan_data: Dict[str, Any] = field(default_factory=dict)
    environment: str = "default"
    triggered_by: str = "system"

@dataclass
class PolicyViolation:
    """Policy violation record."""
    violation_id: str
    rule_id: str
    rule_name: str
    
    # Violation details
    repository: str
    branch: str
    commit_sha: str
    severity: str
    
    # Violation data
    actual_value: Any
    threshold_value: Any
    message: str
    
    # Status
    status: str = "open"  # open, acknowledged, waived, resolved
    resolution: str = ""
    resolved_by: str = ""
    resolved_at: Optional[float] = None
    
    # Tracking
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    occurrence_count: int = 1
    
    # Context
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    context_data: Dict[str, Any] = field(default_factory=dict)

class QualityGateEngine:
    """Comprehensive quality gate enforcement engine."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Engine configuration
        self.engine_config = {
            'default_policy_file': self.config.get('default_policy_file', 'quality_policies.json'),
            'enable_caching': self.config.get('enable_caching', True),
            'cache_duration': self.config.get('cache_duration', 300),  # 5 minutes
            'enable_notifications': self.config.get('enable_notifications', True),
            'violation_retention_days': self.config.get('violation_retention_days', 90),
            'auto_waiver_enabled': self.config.get('auto_waiver_enabled', True)
        }
        
        # Policies and rules
        self.policies: Dict[str, QualityPolicy] = {}
        self.global_rules: List[QualityRule] = []
        
        # Evaluation cache
        self.evaluation_cache: Dict[str, QualityGateResult] = {}
        self.cache_timestamps: Dict[str, float] = {}
        
        # Violation tracking
        self.violations: Dict[str, PolicyViolation] = {}
        self.violation_history: List[PolicyViolation] = []
        
        # Built-in rule templates
        self.rule_templates = self._initialize_rule_templates()
        
        # Statistics
        self.stats = {
            'total_evaluations': 0,
            'passed_gates': 0,
            'failed_gates': 0,
            'rules_evaluated': 0,
            'violations_detected': 0,
            'waivers_granted': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }
    
    async def initialize(self):
        """Initialize the quality gate engine."""
        
        logger.info("Initializing Quality Gate Engine")
        
        # Load default policies
        await self._load_default_policies()
        
        # Initialize built-in security policies
        await self._initialize_security_policies()
        
        # Load custom policies if configured
        if 'custom_policies' in self.config:
            await self._load_custom_policies(self.config['custom_policies'])
        
        logger.info(f"Quality Gate Engine initialized with {len(self.policies)} policies")
    
    async def evaluate(self, scan_data: Dict[str, Any], repository: str, 
                      branch: str, commit_sha: str = "", environment: str = "default") -> Dict[str, Any]:
        """Evaluate quality gates for scan results."""
        
        evaluation_start_time = time.time()
        gate_id = f"gate_{repository}_{branch}_{commit_sha}_{int(evaluation_start_time)}"
        
        logger.info(f"Evaluating quality gates: {gate_id}")
        
        try:
            # Check cache
            cache_key = self._generate_cache_key(scan_data, repository, branch, commit_sha)
            if self.engine_config['enable_caching'] and self._is_cache_valid(cache_key):
                cached_result = self.evaluation_cache[cache_key]
                self.stats['cache_hits'] += 1
                logger.debug(f"Returning cached quality gate result: {gate_id}")
                return self._result_to_dict(cached_result)
            
            self.stats['cache_misses'] += 1
            
            # Initialize result
            result = QualityGateResult(
                gate_id=gate_id,
                repository=repository,
                branch=branch,
                commit_sha=commit_sha,
                status=GateStatus.PENDING,
                passed=False,
                score=0.0,
                environment=environment,
                scan_data=scan_data
            )
            
            # Get applicable policies
            applicable_policies = await self._get_applicable_policies(repository, branch, environment)
            
            if not applicable_policies:
                logger.warning(f"No applicable policies found for {repository}/{branch}")
                result.status = GateStatus.PASSED
                result.passed = True
                result.score = 100.0
                return self._result_to_dict(result)
            
            # Collect all rules from applicable policies
            all_rules = []
            for policy in applicable_policies:
                all_rules.extend(policy.rules)
            
            # Add global rules
            all_rules.extend(self.global_rules)
            
            # Filter rules by applicability
            applicable_rules = await self._filter_applicable_rules(all_rules, repository, branch, environment)
            
            logger.info(f"Evaluating {len(applicable_rules)} rules for {repository}/{branch}")
            
            # Evaluate each rule
            rule_evaluations = []
            for rule in applicable_rules:
                evaluation = await self._evaluate_rule(rule, scan_data, repository, branch, environment)
                rule_evaluations.append(evaluation)
                
                # Track violations
                if not evaluation.passed and not evaluation.waived:
                    await self._track_violation(evaluation, repository, branch, commit_sha)
            
            result.rule_evaluations = rule_evaluations
            result.total_rules = len(rule_evaluations)
            
            # Calculate summary statistics
            result.passed_rules = sum(1 for e in rule_evaluations if e.passed)
            result.failed_rules = sum(1 for e in rule_evaluations if not e.passed and not e.waived)
            result.waived_rules = sum(1 for e in rule_evaluations if e.waived)
            
            # Calculate severity breakdown
            result.blocker_failures = sum(1 for e in rule_evaluations 
                                        if not e.passed and not e.waived and e.severity == 'blocker')
            result.critical_failures = sum(1 for e in rule_evaluations 
                                         if not e.passed and not e.waived and e.severity == 'critical')
            result.major_failures = sum(1 for e in rule_evaluations 
                                      if not e.passed and not e.waived and e.severity == 'major')
            result.minor_failures = sum(1 for e in rule_evaluations 
                                      if not e.passed and not e.waived and e.severity == 'minor')
            
            # Determine overall status
            result = await self._determine_gate_status(result, applicable_policies)
            
            # Calculate quality score
            result.score = await self._calculate_quality_score(result)
            
            # Finalize result
            result.evaluation_duration = time.time() - evaluation_start_time
            
            # Cache result
            if self.engine_config['enable_caching']:
                self.evaluation_cache[cache_key] = result
                self.cache_timestamps[cache_key] = time.time()
            
            # Update statistics
            self._update_statistics(result)
            
            logger.info(f"Quality gate evaluation completed: {gate_id} "
                       f"(Status: {result.status.value}, Score: {result.score:.1f}, "
                       f"Failed: {result.failed_rules}/{result.total_rules})")
            
            return self._result_to_dict(result)
            
        except Exception as e:
            logger.error(f"Quality gate evaluation failed: {gate_id} - {str(e)}")
            
            # Return error result
            error_result = QualityGateResult(
                gate_id=gate_id,
                repository=repository,
                branch=branch,
                commit_sha=commit_sha,
                status=GateStatus.ERROR,
                passed=False,
                score=0.0,
                evaluation_duration=time.time() - evaluation_start_time
            )
            
            return self._result_to_dict(error_result)
    
    async def add_policy(self, policy: QualityPolicy) -> bool:
        """Add or update a quality policy."""
        
        logger.info(f"Adding quality policy: {policy.policy_id}")
        
        try:
            # Validate policy
            if not await self._validate_policy(policy):
                logger.error(f"Policy validation failed: {policy.policy_id}")
                return False
            
            # Update timestamp
            policy.updated_at = time.time()
            
            # Store policy
            self.policies[policy.policy_id] = policy
            
            # Clear cache since policies changed
            self._clear_cache()
            
            logger.info(f"Quality policy added successfully: {policy.policy_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add policy {policy.policy_id}: {str(e)}")
            return False
    
    async def remove_policy(self, policy_id: str) -> bool:
        """Remove a quality policy."""
        
        if policy_id in self.policies:
            del self.policies[policy_id]
            self._clear_cache()
            logger.info(f"Quality policy removed: {policy_id}")
            return True
        
        return False
    
    async def get_policy(self, policy_id: str) -> Optional[QualityPolicy]:
        """Get a quality policy by ID."""
        
        return self.policies.get(policy_id)
    
    async def list_policies(self) -> List[QualityPolicy]:
        """List all quality policies."""
        
        return list(self.policies.values())
    
    async def create_rule_from_template(self, template_name: str, 
                                      rule_id: str, **kwargs) -> Optional[QualityRule]:
        """Create a rule from a built-in template."""
        
        template = self.rule_templates.get(template_name)
        if not template:
            logger.error(f"Rule template not found: {template_name}")
            return None
        
        try:
            # Create rule from template
            rule_data = template.copy()
            rule_data['rule_id'] = rule_id
            rule_data.update(kwargs)
            
            return QualityRule(**rule_data)
            
        except Exception as e:
            logger.error(f"Failed to create rule from template {template_name}: {str(e)}")
            return None
    
    async def get_violations(self, repository: str = None, 
                           status: str = None, 
                           severity: str = None) -> List[PolicyViolation]:
        """Get policy violations with optional filtering."""
        
        violations = list(self.violations.values())
        
        # Apply filters
        if repository:
            violations = [v for v in violations if v.repository == repository]
        
        if status:
            violations = [v for v in violations if v.status == status]
        
        if severity:
            violations = [v for v in violations if v.severity == severity]
        
        return violations
    
    # Private methods
    
    async def _load_default_policies(self):
        """Load default quality policies."""
        
        # This would load from configuration file
        logger.debug("Loading default quality policies")
    
    async def _initialize_security_policies(self):
        """Initialize built-in security policies."""
        
        # Create default security policy
        security_policy = QualityPolicy(
            policy_id="default_security",
            name="Default Security Policy",
            description="Standard security quality gates for all projects",
            level=PolicyLevel.GLOBAL,
            rules=[
                QualityRule(
                    rule_id="no_critical_vulnerabilities",
                    name="No Critical Vulnerabilities",
                    description="Block deployment if critical vulnerabilities are found",
                    metric="critical_findings",
                    operator=RuleOperator.EQUAL,
                    threshold=0,
                    severity=RuleSeverity.BLOCKER,
                    category="security"
                ),
                QualityRule(
                    rule_id="max_high_vulnerabilities",
                    name="Maximum High Vulnerabilities",
                    description="Limit high severity vulnerabilities",
                    metric="high_findings",
                    operator=RuleOperator.LESS_THAN_EQUAL,
                    threshold=5,
                    severity=RuleSeverity.CRITICAL,
                    category="security"
                ),
                QualityRule(
                    rule_id="minimum_security_score",
                    name="Minimum Security Score",
                    description="Require minimum security score",
                    metric="security_score",
                    operator=RuleOperator.GREATER_THAN_EQUAL,
                    threshold=70.0,
                    severity=RuleSeverity.MAJOR,
                    category="security"
                )
            ]
        )
        
        await self.add_policy(security_policy)
    
    async def _get_applicable_policies(self, repository: str, branch: str, 
                                     environment: str) -> List[QualityPolicy]:
        """Get policies applicable to the given context."""
        
        applicable_policies = []
        
        for policy in self.policies.values():
            if not policy.enabled:
                continue
            
            # Check repository applicability
            if (policy.applies_to_repositories and 
                repository not in policy.applies_to_repositories):
                continue
            
            # Check branch applicability
            if (policy.applies_to_branches and 
                branch not in policy.applies_to_branches):
                continue
            
            # Check environment applicability
            if (policy.applies_to_environments and 
                environment not in policy.applies_to_environments):
                continue
            
            applicable_policies.append(policy)
        
        return applicable_policies
    
    async def _filter_applicable_rules(self, rules: List[QualityRule], 
                                     repository: str, branch: str, 
                                     environment: str) -> List[QualityRule]:
        """Filter rules by applicability."""
        
        applicable_rules = []
        
        for rule in rules:
            if not rule.enabled:
                continue
            
            # Check branch applicability
            if rule.applies_to_branches and branch not in rule.applies_to_branches:
                continue
            
            # Check environment applicability
            if rule.applies_to_environments and environment not in rule.applies_to_environments:
                continue
            
            applicable_rules.append(rule)
        
        return applicable_rules
    
    async def _evaluate_rule(self, rule: QualityRule, scan_data: Dict[str, Any], 
                           repository: str, branch: str, environment: str) -> RuleEvaluation:
        """Evaluate a single quality rule."""
        
        logger.debug(f"Evaluating rule: {rule.rule_id}")
        
        try:
            # Get actual value from scan data
            actual_value = self._extract_metric_value(rule.metric, scan_data)
            
            # Perform comparison
            passed = self._compare_values(actual_value, rule.operator, rule.threshold)
            
            # Generate message
            message = self._generate_rule_message(rule, actual_value, passed)
            
            # Create evaluation
            evaluation = RuleEvaluation(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                passed=passed,
                actual_value=actual_value,
                threshold_value=rule.threshold,
                metric=rule.metric,
                operator=rule.operator.value,
                severity=rule.severity.value,
                message=message,
                context={
                    'repository': repository,
                    'branch': branch,
                    'environment': environment
                }
            )
            
            # Check for auto-waiver conditions
            if not passed and rule.auto_waiver_conditions:
                waived = await self._check_auto_waiver(rule, scan_data, evaluation)
                if waived:
                    evaluation.waived = True
                    evaluation.waiver_reason = "Auto-waiver conditions met"
            
            self.stats['rules_evaluated'] += 1
            
            return evaluation
            
        except Exception as e:
            logger.error(f"Error evaluating rule {rule.rule_id}: {str(e)}")
            
            # Return failed evaluation
            return RuleEvaluation(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                passed=False,
                actual_value=None,
                threshold_value=rule.threshold,
                metric=rule.metric,
                operator=rule.operator.value,
                severity=rule.severity.value,
                message=f"Rule evaluation error: {str(e)}"
            )
    
    def _extract_metric_value(self, metric: str, scan_data: Dict[str, Any]) -> Any:
        """Extract metric value from scan data."""
        
        # Handle nested metrics with dot notation
        keys = metric.split('.')
        value = scan_data
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        
        return value
    
    def _compare_values(self, actual: Any, operator: RuleOperator, threshold: Any) -> bool:
        """Compare actual value with threshold using operator."""
        
        try:
            if operator == RuleOperator.GREATER_THAN:
                return actual > threshold
            elif operator == RuleOperator.GREATER_THAN_EQUAL:
                return actual >= threshold
            elif operator == RuleOperator.LESS_THAN:
                return actual < threshold
            elif operator == RuleOperator.LESS_THAN_EQUAL:
                return actual <= threshold
            elif operator == RuleOperator.EQUAL:
                return actual == threshold
            elif operator == RuleOperator.NOT_EQUAL:
                return actual != threshold
            elif operator == RuleOperator.CONTAINS:
                return threshold in actual if actual else False
            elif operator == RuleOperator.NOT_CONTAINS:
                return threshold not in actual if actual else True
            elif operator == RuleOperator.IN:
                return actual in threshold if threshold else False
            elif operator == RuleOperator.NOT_IN:
                return actual not in threshold if threshold else True
            else:
                logger.warning(f"Unknown operator: {operator}")
                return False
                
        except Exception as e:
            logger.error(f"Error comparing values: {str(e)}")
            return False
    
    def _generate_rule_message(self, rule: QualityRule, actual_value: Any, passed: bool) -> str:
        """Generate human-readable message for rule evaluation."""
        
        if passed:
            return f"✅ {rule.name}: {actual_value} meets threshold {rule.operator.value} {rule.threshold}"
        else:
            return f"❌ {rule.name}: {actual_value} does not meet threshold {rule.operator.value} {rule.threshold}"
    
    async def _determine_gate_status(self, result: QualityGateResult, 
                                   policies: List[QualityPolicy]) -> QualityGateResult:
        """Determine overall quality gate status."""
        
        # Check for blocker failures
        if result.blocker_failures > 0:
            result.status = GateStatus.FAILED
            result.passed = False
            return result
        
        # Check for critical failures
        if result.critical_failures > 0:
            result.status = GateStatus.FAILED
            result.passed = False
            return result
        
        # Check strict mode policies
        for policy in policies:
            if policy.strict_mode and result.failed_rules > 0:
                result.status = GateStatus.FAILED
                result.passed = False
                return result
        
        # Check for major failures (warning status)
        if result.major_failures > 0:
            result.status = GateStatus.WARNING
            result.passed = True  # Allow with warnings
            return result
        
        # All checks passed
        result.status = GateStatus.PASSED
        result.passed = True
        
        return result
    
    async def _calculate_quality_score(self, result: QualityGateResult) -> float:
        """Calculate overall quality score (0-100)."""
        
        if result.total_rules == 0:
            return 100.0
        
        # Base score from passed rules
        base_score = (result.passed_rules / result.total_rules) * 100
        
        # Apply penalties for failures by severity
        penalty = 0
        penalty += result.blocker_failures * 25  # Heavy penalty for blockers
        penalty += result.critical_failures * 15  # Heavy penalty for critical
        penalty += result.major_failures * 5     # Medium penalty for major
        penalty += result.minor_failures * 1     # Light penalty for minor
        
        # Calculate final score
        final_score = max(0, base_score - penalty)
        
        return round(final_score, 1)
    
    def _initialize_rule_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize built-in rule templates."""
        
        return {
            'no_critical_vulns': {
                'name': 'No Critical Vulnerabilities',
                'description': 'Block if critical vulnerabilities found',
                'metric': 'critical_findings',
                'operator': RuleOperator.EQUAL,
                'threshold': 0,
                'severity': RuleSeverity.BLOCKER,
                'category': 'security'
            },
            'max_high_vulns': {
                'name': 'Maximum High Vulnerabilities',
                'description': 'Limit high severity vulnerabilities',
                'metric': 'high_findings',
                'operator': RuleOperator.LESS_THAN_EQUAL,
                'threshold': 10,
                'severity': RuleSeverity.CRITICAL,
                'category': 'security'
            },
            'min_security_score': {
                'name': 'Minimum Security Score',
                'description': 'Require minimum security score',
                'metric': 'security_score',
                'operator': RuleOperator.GREATER_THAN_EQUAL,
                'threshold': 70.0,
                'severity': RuleSeverity.MAJOR,
                'category': 'security'
            }
        }
    
    def _generate_cache_key(self, scan_data: Dict[str, Any], repository: str, 
                          branch: str, commit_sha: str) -> str:
        """Generate cache key for evaluation."""
        
        import hashlib
        
        key_data = {
            'repository': repository,
            'branch': branch,
            'commit_sha': commit_sha,
            'scan_data_hash': hashlib.md5(
                json.dumps(scan_data, sort_keys=True, default=str).encode()
            ).hexdigest(),
            'policies_hash': self._get_policies_hash()
        }
        
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _get_policies_hash(self) -> str:
        """Get hash of current policies for cache invalidation."""
        
        import hashlib
        
        policy_data = {
            policy_id: {
                'version': policy.version,
                'updated_at': policy.updated_at,
                'rules_count': len(policy.rules)
            }
            for policy_id, policy in self.policies.items()
        }
        
        return hashlib.md5(
            json.dumps(policy_data, sort_keys=True).encode()
        ).hexdigest()
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cache entry is still valid."""
        
        if cache_key not in self.cache_timestamps:
            return False
        
        age = time.time() - self.cache_timestamps[cache_key]
        return age < self.engine_config['cache_duration']
    
    def _clear_cache(self):
        """Clear evaluation cache."""
        
        self.evaluation_cache.clear()
        self.cache_timestamps.clear()
    
    def _result_to_dict(self, result: QualityGateResult) -> Dict[str, Any]:
        """Convert result to dictionary."""
        
        return {
            'gate_id': result.gate_id,
            'repository': result.repository,
            'branch': result.branch,
            'commit_sha': result.commit_sha,
            'status': result.status.value,
            'passed': result.passed,
            'score': result.score,
            'summary': {
                'total_rules': result.total_rules,
                'passed_rules': result.passed_rules,
                'failed_rules': result.failed_rules,
                'waived_rules': result.waived_rules,
                'blocker_failures': result.blocker_failures,
                'critical_failures': result.critical_failures,
                'major_failures': result.major_failures,
                'minor_failures': result.minor_failures
            },
            'rule_evaluations': [
                {
                    'rule_id': e.rule_id,
                    'rule_name': e.rule_name,
                    'passed': e.passed,
                    'actual_value': e.actual_value,
                    'threshold_value': e.threshold_value,
                    'severity': e.severity,
                    'message': e.message,
                    'waived': e.waived,
                    'waiver_reason': e.waiver_reason
                }
                for e in result.rule_evaluations
            ],
            'evaluation_time': result.evaluation_time,
            'evaluation_duration': result.evaluation_duration,
            'environment': result.environment
        }
    
    async def _track_violation(self, evaluation: RuleEvaluation, repository: str, 
                             branch: str, commit_sha: str):
        """Track policy violation."""
        
        violation_id = f"{evaluation.rule_id}_{repository}_{branch}"
        
        if violation_id in self.violations:
            # Update existing violation
            violation = self.violations[violation_id]
            violation.last_seen = time.time()
            violation.occurrence_count += 1
            violation.commit_sha = commit_sha  # Update to latest
        else:
            # Create new violation
            violation = PolicyViolation(
                violation_id=violation_id,
                rule_id=evaluation.rule_id,
                rule_name=evaluation.rule_name,
                repository=repository,
                branch=branch,
                commit_sha=commit_sha,
                severity=evaluation.severity,
                actual_value=evaluation.actual_value,
                threshold_value=evaluation.threshold_value,
                message=evaluation.message
            )
            
            self.violations[violation_id] = violation
            self.stats['violations_detected'] += 1
    
    async def _check_auto_waiver(self, rule: QualityRule, scan_data: Dict[str, Any], 
                                evaluation: RuleEvaluation) -> bool:
        """Check if auto-waiver conditions are met."""
        
        # This would implement auto-waiver logic
        return False
    
    async def _validate_policy(self, policy: QualityPolicy) -> bool:
        """Validate policy configuration."""
        
        if not policy.policy_id or not policy.name:
            return False
        
        # Validate rules
        for rule in policy.rules:
            if not rule.rule_id or not rule.name or not rule.metric:
                return False
        
        return True
    
    def _update_statistics(self, result: QualityGateResult):
        """Update engine statistics."""
        
        self.stats['total_evaluations'] += 1
        
        if result.passed:
            self.stats['passed_gates'] += 1
        else:
            self.stats['failed_gates'] += 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get quality gate engine statistics."""
        
        stats = dict(self.stats)
        stats['total_policies'] = len(self.policies)
        stats['total_violations'] = len(self.violations)
        stats['cache_size'] = len(self.evaluation_cache)
        
        return stats
    
    async def shutdown(self):
        """Shutdown quality gate engine."""
        
        logger.info("Shutting down Quality Gate Engine")
        
        # Save violations and history if needed
        # This would persist data to storage
        
        logger.info("Quality Gate Engine shutdown completed")
