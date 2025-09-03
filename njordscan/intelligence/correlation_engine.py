"""
Vulnerability Correlation Engine

Identifies relationships and patterns between vulnerabilities to provide deeper insights.
"""

import time
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)

class CorrelationType(Enum):
    """Types of vulnerability correlations."""
    ATTACK_CHAIN = "attack_chain"
    COMPOUND_VULNERABILITY = "compound_vulnerability"
    SIMILAR_ROOT_CAUSE = "similar_root_cause"
    SAME_COMPONENT = "same_component"
    EXPLOITATION_AMPLIFIER = "exploitation_amplifier"
    DEFENSE_BYPASS = "defense_bypass"
    PRIVILEGE_ESCALATION_PATH = "privilege_escalation_path"

@dataclass
class VulnerabilityCorrelation:
    """Represents a correlation between vulnerabilities."""
    correlation_id: str
    correlation_type: CorrelationType
    primary_vulnerability: str  # vulnerability ID
    related_vulnerabilities: List[str]
    
    # Correlation strength and confidence
    correlation_strength: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    
    # Description and impact
    description: str
    impact_amplification: float = 1.0  # Multiplier for combined impact
    exploitability_increase: float = 1.0  # Multiplier for exploitability
    
    # Context information
    affected_components: List[str] = field(default_factory=list)
    attack_scenarios: List[str] = field(default_factory=list)
    mitigation_priority: str = "medium"  # low, medium, high, critical
    
    # Metadata
    discovered_at: float = field(default_factory=time.time)
    evidence: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

@dataclass
class AttackPath:
    """Represents a potential attack path through multiple vulnerabilities."""
    path_id: str
    vulnerabilities: List[str]  # Ordered list of vulnerability IDs
    path_type: str  # e.g., "privilege_escalation", "data_exfiltration"
    complexity: str  # low, medium, high
    impact_level: str  # low, medium, high, critical
    description: str
    steps: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)

class CorrelationEngine:
    """Engine for discovering and analyzing vulnerability correlations."""
    
    def __init__(self):
        self.correlations: Dict[str, VulnerabilityCorrelation] = {}
        self.attack_paths: Dict[str, AttackPath] = {}
        
        # Correlation rules and patterns
        self.correlation_rules = self._build_correlation_rules()
        
        # Component and location tracking
        self.vulnerability_components: Dict[str, Set[str]] = defaultdict(set)
        self.component_vulnerabilities: Dict[str, Set[str]] = defaultdict(set)
        
        # Statistics
        self.correlation_stats = {
            'total_correlations': 0,
            'correlation_types': defaultdict(int),
            'attack_paths_discovered': 0,
            'high_impact_correlations': 0
        }
    
    def _build_correlation_rules(self) -> Dict[CorrelationType, Dict[str, Any]]:
        """Build rules for different types of correlations."""
        return {
            CorrelationType.ATTACK_CHAIN: {
                'patterns': [
                    # Information disclosure -> Privilege escalation
                    {
                        'sequence': ['information_disclosure', 'privilege_escalation'],
                        'strength': 0.8,
                        'description': 'Information disclosure enables privilege escalation'
                    },
                    # Authentication bypass -> Data access
                    {
                        'sequence': ['authentication_bypass', 'data_access'],
                        'strength': 0.9,
                        'description': 'Authentication bypass leads to unauthorized data access'
                    },
                    # XSS -> Session hijacking
                    {
                        'sequence': ['xss', 'session_hijacking'],
                        'strength': 0.7,
                        'description': 'XSS vulnerability enables session hijacking'
                    }
                ],
                'indicators': ['sequential_exploitation', 'escalating_privileges']
            },
            
            CorrelationType.COMPOUND_VULNERABILITY: {
                'patterns': [
                    # CSRF + XSS = Severe impact
                    {
                        'combination': ['csrf', 'xss'],
                        'strength': 0.8,
                        'amplification': 1.5,
                        'description': 'CSRF and XSS combination creates severe attack potential'
                    },
                    # SQL Injection + File Upload = System compromise
                    {
                        'combination': ['sql_injection', 'file_upload'],
                        'strength': 0.9,
                        'amplification': 2.0,
                        'description': 'SQL injection with file upload enables system compromise'
                    }
                ],
                'indicators': ['same_user_context', 'combined_exploitation']
            },
            
            CorrelationType.SIMILAR_ROOT_CAUSE: {
                'patterns': [
                    {
                        'root_causes': ['input_validation', 'output_encoding'],
                        'strength': 0.6,
                        'description': 'Vulnerabilities sharing common root cause patterns'
                    }
                ],
                'indicators': ['same_code_pattern', 'same_developer', 'same_timeframe']
            },
            
            CorrelationType.SAME_COMPONENT: {
                'patterns': [
                    {
                        'component_types': ['authentication', 'authorization', 'data_processing'],
                        'strength': 0.7,
                        'description': 'Multiple vulnerabilities in the same component'
                    }
                ],
                'indicators': ['same_file', 'same_module', 'same_function']
            },
            
            CorrelationType.DEFENSE_BYPASS: {
                'patterns': [
                    {
                        'bypass_combinations': [
                            ['input_validation_bypass', 'output_encoding_bypass'],
                            ['authentication_bypass', 'authorization_bypass']
                        ],
                        'strength': 0.8,
                        'amplification': 1.8,
                        'description': 'Multiple defense mechanisms bypassed'
                    }
                ],
                'indicators': ['security_control_failure', 'defense_in_depth_failure']
            }
        }
    
    def analyze_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[VulnerabilityCorrelation]:
        """Analyze a set of vulnerabilities for correlations."""
        
        logger.info(f"Analyzing {len(vulnerabilities)} vulnerabilities for correlations")
        
        # Clear previous analysis
        self.correlations.clear()
        self.attack_paths.clear()
        self._reset_component_tracking()
        
        # Index vulnerabilities by components and characteristics
        self._index_vulnerabilities(vulnerabilities)
        
        # Discover different types of correlations
        self._discover_attack_chains(vulnerabilities)
        self._discover_compound_vulnerabilities(vulnerabilities)
        self._discover_similar_root_causes(vulnerabilities)
        self._discover_component_correlations(vulnerabilities)
        self._discover_defense_bypasses(vulnerabilities)
        
        # Generate attack paths
        self._generate_attack_paths(vulnerabilities)
        
        # Calculate correlation impacts
        self._calculate_correlation_impacts()
        
        # Update statistics
        self._update_correlation_stats()
        
        logger.info(f"Discovered {len(self.correlations)} correlations and {len(self.attack_paths)} attack paths")
        
        return list(self.correlations.values())
    
    def _index_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]):
        """Index vulnerabilities by various characteristics."""
        
        for vuln in vulnerabilities:
            vuln_id = vuln.get('id', str(hash(str(vuln))))
            
            # Index by file/component
            file_path = vuln.get('file_path', '')
            if file_path:
                component = self._extract_component_name(file_path)
                self.vulnerability_components[vuln_id].add(component)
                self.component_vulnerabilities[component].add(vuln_id)
            
            # Index by module
            module = vuln.get('module', '')
            if module:
                self.vulnerability_components[vuln_id].add(f"module:{module}")
                self.component_vulnerabilities[f"module:{module}"].add(vuln_id)
            
            # Index by vulnerability type
            vuln_type = vuln.get('vuln_type', vuln.get('type', ''))
            if vuln_type:
                self.vulnerability_components[vuln_id].add(f"type:{vuln_type}")
                self.component_vulnerabilities[f"type:{vuln_type}"].add(vuln_id)
    
    def _discover_attack_chains(self, vulnerabilities: List[Dict[str, Any]]):
        """Discover attack chain correlations."""
        
        # Group vulnerabilities by severity and type for chain analysis
        vuln_by_type = defaultdict(list)
        for vuln in vulnerabilities:
            vuln_type = self._normalize_vulnerability_type(vuln.get('vuln_type', ''))
            vuln_by_type[vuln_type].append(vuln)
        
        # Look for attack chain patterns
        chain_patterns = self.correlation_rules[CorrelationType.ATTACK_CHAIN]['patterns']
        
        for pattern in chain_patterns:
            sequence = pattern['sequence']
            if len(sequence) < 2:
                continue
            
            # Find vulnerabilities that match the sequence
            for i in range(len(sequence) - 1):
                current_type = sequence[i]
                next_type = sequence[i + 1]
                
                current_vulns = vuln_by_type.get(current_type, [])
                next_vulns = vuln_by_type.get(next_type, [])
                
                # Check for potential chains
                for current_vuln in current_vulns:
                    for next_vuln in next_vulns:
                        if self._can_form_attack_chain(current_vuln, next_vuln):
                            correlation = self._create_attack_chain_correlation(
                                current_vuln, next_vuln, pattern
                            )
                            self.correlations[correlation.correlation_id] = correlation
    
    def _discover_compound_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]):
        """Discover compound vulnerability correlations."""
        
        compound_patterns = self.correlation_rules[CorrelationType.COMPOUND_VULNERABILITY]['patterns']
        
        for pattern in compound_patterns:
            combination = pattern['combination']
            
            # Find vulnerabilities matching the combination
            matching_vulns = []
            for combo_type in combination:
                type_vulns = [v for v in vulnerabilities 
                            if self._normalize_vulnerability_type(v.get('vuln_type', '')) == combo_type]
                matching_vulns.append(type_vulns)
            
            # Create correlations for all combinations
            if all(matching_vulns):
                for i, vulns1 in enumerate(matching_vulns[:-1]):
                    for vulns2 in matching_vulns[i+1:]:
                        for vuln1 in vulns1:
                            for vuln2 in vulns2:
                                if self._can_form_compound_vulnerability(vuln1, vuln2):
                                    correlation = self._create_compound_vulnerability_correlation(
                                        vuln1, vuln2, pattern
                                    )
                                    self.correlations[correlation.correlation_id] = correlation
    
    def _discover_similar_root_causes(self, vulnerabilities: List[Dict[str, Any]]):
        """Discover vulnerabilities with similar root causes."""
        
        # Group vulnerabilities by potential root causes
        root_cause_groups = defaultdict(list)
        
        for vuln in vulnerabilities:
            root_causes = self._identify_root_causes(vuln)
            for root_cause in root_causes:
                root_cause_groups[root_cause].append(vuln)
        
        # Create correlations for vulnerabilities with same root causes
        for root_cause, vulns in root_cause_groups.items():
            if len(vulns) > 1:
                # Create correlation for each pair
                for i in range(len(vulns)):
                    for j in range(i + 1, len(vulns)):
                        correlation = self._create_root_cause_correlation(
                            vulns[i], vulns[j], root_cause
                        )
                        self.correlations[correlation.correlation_id] = correlation
    
    def _discover_component_correlations(self, vulnerabilities: List[Dict[str, Any]]):
        """Discover vulnerabilities in the same components."""
        
        # Find components with multiple vulnerabilities
        for component, vuln_ids in self.component_vulnerabilities.items():
            if len(vuln_ids) > 1:
                vuln_list = [v for v in vulnerabilities if v.get('id', str(hash(str(v)))) in vuln_ids]
                
                # Create correlations between vulnerabilities in same component
                for i in range(len(vuln_list)):
                    for j in range(i + 1, len(vuln_list)):
                        correlation = self._create_component_correlation(
                            vuln_list[i], vuln_list[j], component
                        )
                        self.correlations[correlation.correlation_id] = correlation
    
    def _discover_defense_bypasses(self, vulnerabilities: List[Dict[str, Any]]):
        """Discover defense bypass correlations."""
        
        # Look for combinations that bypass multiple defense layers
        defense_categories = {
            'input_validation': ['xss', 'sql_injection', 'command_injection'],
            'authentication': ['authentication_bypass', 'session_hijacking'],
            'authorization': ['privilege_escalation', 'access_control'],
            'output_encoding': ['xss', 'template_injection']
        }
        
        # Find vulnerabilities that bypass different defense categories
        defense_bypasses = defaultdict(list)
        
        for vuln in vulnerabilities:
            vuln_type = self._normalize_vulnerability_type(vuln.get('vuln_type', ''))
            for defense, vuln_types in defense_categories.items():
                if vuln_type in vuln_types:
                    defense_bypasses[defense].append(vuln)
        
        # Create correlations for multiple defense bypasses
        defense_list = list(defense_bypasses.keys())
        for i in range(len(defense_list)):
            for j in range(i + 1, len(defense_list)):
                defense1, defense2 = defense_list[i], defense_list[j]
                vulns1, vulns2 = defense_bypasses[defense1], defense_bypasses[defense2]
                
                for vuln1 in vulns1:
                    for vuln2 in vulns2:
                        correlation = self._create_defense_bypass_correlation(
                            vuln1, vuln2, [defense1, defense2]
                        )
                        self.correlations[correlation.correlation_id] = correlation
    
    def _generate_attack_paths(self, vulnerabilities: List[Dict[str, Any]]):
        """Generate potential attack paths through vulnerabilities."""
        
        # Create attack paths based on correlations
        attack_chain_correlations = [c for c in self.correlations.values() 
                                   if c.correlation_type == CorrelationType.ATTACK_CHAIN]
        
        for correlation in attack_chain_correlations:
            attack_path = self._create_attack_path_from_correlation(correlation, vulnerabilities)
            if attack_path:
                self.attack_paths[attack_path.path_id] = attack_path
        
        # Generate complex multi-step attack paths
        self._generate_complex_attack_paths(vulnerabilities)
    
    def _can_form_attack_chain(self, vuln1: Dict[str, Any], vuln2: Dict[str, Any]) -> bool:
        """Check if two vulnerabilities can form an attack chain."""
        
        # Check if vulnerabilities are in related components
        file1 = vuln1.get('file_path', '')
        file2 = vuln2.get('file_path', '')
        
        # Same application/component
        if self._extract_component_name(file1) == self._extract_component_name(file2):
            return True
        
        # Check for logical connection (API -> Frontend, Auth -> Data)
        if self._have_logical_connection(vuln1, vuln2):
            return True
        
        return False
    
    def _can_form_compound_vulnerability(self, vuln1: Dict[str, Any], vuln2: Dict[str, Any]) -> bool:
        """Check if two vulnerabilities can form a compound vulnerability."""
        
        # Must be exploitable in the same user context
        if not self._same_user_context(vuln1, vuln2):
            return False
        
        # Should be in related components or same application flow
        return self._have_logical_connection(vuln1, vuln2)
    
    def _create_attack_chain_correlation(self, vuln1: Dict[str, Any], vuln2: Dict[str, Any], 
                                       pattern: Dict[str, Any]) -> VulnerabilityCorrelation:
        """Create an attack chain correlation."""
        
        vuln1_id = vuln1.get('id', str(hash(str(vuln1))))
        vuln2_id = vuln2.get('id', str(hash(str(vuln2))))
        
        correlation_id = f"attack_chain_{vuln1_id}_{vuln2_id}"
        
        return VulnerabilityCorrelation(
            correlation_id=correlation_id,
            correlation_type=CorrelationType.ATTACK_CHAIN,
            primary_vulnerability=vuln1_id,
            related_vulnerabilities=[vuln2_id],
            correlation_strength=pattern['strength'],
            confidence=0.8,
            description=pattern['description'],
            impact_amplification=1.3,
            exploitability_increase=1.2,
            affected_components=self._get_affected_components([vuln1, vuln2]),
            attack_scenarios=[f"Exploit {vuln1.get('title', 'vulnerability')} to enable {vuln2.get('title', 'secondary exploit')}"],
            mitigation_priority="high",
            evidence=[f"Sequential exploitation possible: {vuln1.get('title')} -> {vuln2.get('title')}"]
        )
    
    def _create_compound_vulnerability_correlation(self, vuln1: Dict[str, Any], vuln2: Dict[str, Any],
                                                 pattern: Dict[str, Any]) -> VulnerabilityCorrelation:
        """Create a compound vulnerability correlation."""
        
        vuln1_id = vuln1.get('id', str(hash(str(vuln1))))
        vuln2_id = vuln2.get('id', str(hash(str(vuln2))))
        
        correlation_id = f"compound_{vuln1_id}_{vuln2_id}"
        
        return VulnerabilityCorrelation(
            correlation_id=correlation_id,
            correlation_type=CorrelationType.COMPOUND_VULNERABILITY,
            primary_vulnerability=vuln1_id,
            related_vulnerabilities=[vuln2_id],
            correlation_strength=pattern['strength'],
            confidence=0.9,
            description=pattern['description'],
            impact_amplification=pattern.get('amplification', 1.5),
            exploitability_increase=1.4,
            affected_components=self._get_affected_components([vuln1, vuln2]),
            attack_scenarios=[f"Combined exploitation of {vuln1.get('title')} and {vuln2.get('title')}"],
            mitigation_priority="critical",
            evidence=[f"Compound vulnerability: {pattern['combination']}"]
        )
    
    def _create_root_cause_correlation(self, vuln1: Dict[str, Any], vuln2: Dict[str, Any],
                                     root_cause: str) -> VulnerabilityCorrelation:
        """Create a root cause correlation."""
        
        vuln1_id = vuln1.get('id', str(hash(str(vuln1))))
        vuln2_id = vuln2.get('id', str(hash(str(vuln2))))
        
        correlation_id = f"root_cause_{root_cause}_{vuln1_id}_{vuln2_id}"
        
        return VulnerabilityCorrelation(
            correlation_id=correlation_id,
            correlation_type=CorrelationType.SIMILAR_ROOT_CAUSE,
            primary_vulnerability=vuln1_id,
            related_vulnerabilities=[vuln2_id],
            correlation_strength=0.6,
            confidence=0.7,
            description=f"Vulnerabilities sharing root cause: {root_cause}",
            impact_amplification=1.1,
            exploitability_increase=1.0,
            affected_components=self._get_affected_components([vuln1, vuln2]),
            attack_scenarios=[f"Similar exploitation techniques for {root_cause} vulnerabilities"],
            mitigation_priority="medium",
            evidence=[f"Common root cause: {root_cause}"]
        )
    
    def _create_component_correlation(self, vuln1: Dict[str, Any], vuln2: Dict[str, Any],
                                    component: str) -> VulnerabilityCorrelation:
        """Create a component-based correlation."""
        
        vuln1_id = vuln1.get('id', str(hash(str(vuln1))))
        vuln2_id = vuln2.get('id', str(hash(str(vuln2))))
        
        correlation_id = f"component_{component}_{vuln1_id}_{vuln2_id}"
        
        return VulnerabilityCorrelation(
            correlation_id=correlation_id,
            correlation_type=CorrelationType.SAME_COMPONENT,
            primary_vulnerability=vuln1_id,
            related_vulnerabilities=[vuln2_id],
            correlation_strength=0.7,
            confidence=0.8,
            description=f"Multiple vulnerabilities in component: {component}",
            impact_amplification=1.2,
            exploitability_increase=1.1,
            affected_components=[component],
            attack_scenarios=[f"Component compromise through multiple vulnerabilities in {component}"],
            mitigation_priority="high",
            evidence=[f"Same component affected: {component}"]
        )
    
    def _create_defense_bypass_correlation(self, vuln1: Dict[str, Any], vuln2: Dict[str, Any],
                                         defenses: List[str]) -> VulnerabilityCorrelation:
        """Create a defense bypass correlation."""
        
        vuln1_id = vuln1.get('id', str(hash(str(vuln1))))
        vuln2_id = vuln2.get('id', str(hash(str(vuln2))))
        
        correlation_id = f"defense_bypass_{vuln1_id}_{vuln2_id}"
        
        return VulnerabilityCorrelation(
            correlation_id=correlation_id,
            correlation_type=CorrelationType.DEFENSE_BYPASS,
            primary_vulnerability=vuln1_id,
            related_vulnerabilities=[vuln2_id],
            correlation_strength=0.8,
            confidence=0.8,
            description=f"Multiple defense layers bypassed: {', '.join(defenses)}",
            impact_amplification=1.8,
            exploitability_increase=1.5,
            affected_components=self._get_affected_components([vuln1, vuln2]),
            attack_scenarios=[f"Defense-in-depth bypass through {', '.join(defenses)}"],
            mitigation_priority="critical",
            evidence=[f"Defense layers bypassed: {defenses}"]
        )
    
    def _create_attack_path_from_correlation(self, correlation: VulnerabilityCorrelation,
                                           vulnerabilities: List[Dict[str, Any]]) -> Optional[AttackPath]:
        """Create an attack path from a correlation."""
        
        if correlation.correlation_type != CorrelationType.ATTACK_CHAIN:
            return None
        
        # Find vulnerability details
        primary_vuln = next((v for v in vulnerabilities 
                           if v.get('id', str(hash(str(v)))) == correlation.primary_vulnerability), None)
        related_vulns = [v for v in vulnerabilities 
                        if v.get('id', str(hash(str(v)))) in correlation.related_vulnerabilities]
        
        if not primary_vuln or not related_vulns:
            return None
        
        path_id = f"path_{correlation.correlation_id}"
        
        return AttackPath(
            path_id=path_id,
            vulnerabilities=[correlation.primary_vulnerability] + correlation.related_vulnerabilities,
            path_type="privilege_escalation",
            complexity="medium",
            impact_level="high",
            description=f"Attack path: {primary_vuln.get('title')} -> {related_vulns[0].get('title')}",
            steps=[
                f"1. Exploit {primary_vuln.get('title')}",
                f"2. Use gained access to exploit {related_vulns[0].get('title')}"
            ],
            prerequisites=["Network access", "Basic knowledge of application"],
            mitigations=[
                f"Fix {primary_vuln.get('title')}",
                f"Implement proper access controls",
                f"Add monitoring for exploitation attempts"
            ]
        )
    
    def _generate_complex_attack_paths(self, vulnerabilities: List[Dict[str, Any]]):
        """Generate complex multi-step attack paths."""
        
        # Look for chains of 3+ vulnerabilities
        high_severity_vulns = [v for v in vulnerabilities 
                             if v.get('severity', '').lower() in ['high', 'critical']]
        
        if len(high_severity_vulns) >= 3:
            # Create a complex attack path
            path_id = f"complex_path_{int(time.time())}"
            
            attack_path = AttackPath(
                path_id=path_id,
                vulnerabilities=[v.get('id', str(hash(str(v)))) for v in high_severity_vulns[:3]],
                path_type="system_compromise",
                complexity="high",
                impact_level="critical",
                description="Complex multi-step attack leading to system compromise",
                steps=[
                    f"1. Initial access via {high_severity_vulns[0].get('title')}",
                    f"2. Privilege escalation using {high_severity_vulns[1].get('title')}",
                    f"3. Data exfiltration through {high_severity_vulns[2].get('title')}"
                ],
                prerequisites=["External network access", "Advanced attack skills"],
                mitigations=[
                    "Implement comprehensive security monitoring",
                    "Deploy defense-in-depth strategies",
                    "Regular security assessments and penetration testing"
                ]
            )
            
            self.attack_paths[path_id] = attack_path
    
    def _calculate_correlation_impacts(self):
        """Calculate the impact of correlations on overall risk."""
        
        for correlation in self.correlations.values():
            # Adjust impact based on correlation type
            if correlation.correlation_type == CorrelationType.COMPOUND_VULNERABILITY:
                correlation.impact_amplification *= 1.2
            elif correlation.correlation_type == CorrelationType.ATTACK_CHAIN:
                correlation.exploitability_increase *= 1.1
            elif correlation.correlation_type == CorrelationType.DEFENSE_BYPASS:
                correlation.impact_amplification *= 1.5
                correlation.mitigation_priority = "critical"
    
    def _normalize_vulnerability_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type for consistent matching."""
        
        type_mapping = {
            'xss': ['xss', 'cross_site_scripting', 'reflected_xss', 'stored_xss'],
            'sql_injection': ['sql_injection', 'sqli', 'sql_inject'],
            'command_injection': ['command_injection', 'cmd_injection', 'code_injection'],
            'csrf': ['csrf', 'cross_site_request_forgery'],
            'authentication_bypass': ['auth_bypass', 'authentication_bypass'],
            'privilege_escalation': ['privilege_escalation', 'privesc'],
            'information_disclosure': ['info_disclosure', 'information_disclosure', 'data_leak'],
            'file_upload': ['file_upload', 'upload_vulnerability'],
            'path_traversal': ['path_traversal', 'directory_traversal'],
            'session_hijacking': ['session_hijack', 'session_fixation']
        }
        
        vuln_type_lower = vuln_type.lower()
        
        for normalized, variants in type_mapping.items():
            if vuln_type_lower in variants or any(variant in vuln_type_lower for variant in variants):
                return normalized
        
        return vuln_type_lower
    
    def _identify_root_causes(self, vuln: Dict[str, Any]) -> List[str]:
        """Identify potential root causes of a vulnerability."""
        
        root_causes = []
        description = (vuln.get('description', '') + ' ' + vuln.get('title', '')).lower()
        
        root_cause_patterns = {
            'input_validation': ['input', 'validation', 'sanitize', 'filter'],
            'output_encoding': ['output', 'encoding', 'escape', 'html'],
            'authentication': ['auth', 'login', 'session', 'credential'],
            'authorization': ['authz', 'permission', 'access', 'role'],
            'configuration': ['config', 'setting', 'misconfiguration'],
            'crypto': ['crypto', 'encryption', 'hash', 'random'],
            'error_handling': ['error', 'exception', 'handling', 'catch']
        }
        
        for root_cause, keywords in root_cause_patterns.items():
            if any(keyword in description for keyword in keywords):
                root_causes.append(root_cause)
        
        return root_causes or ['unknown']
    
    def _extract_component_name(self, file_path: str) -> str:
        """Extract component name from file path."""
        
        if not file_path:
            return 'unknown'
        
        # Extract meaningful component names
        path_parts = file_path.split('/')
        
        # Look for common component indicators
        for part in path_parts:
            if part in ['api', 'components', 'pages', 'middleware', 'lib', 'utils', 'services']:
                try:
                    next_part = path_parts[path_parts.index(part) + 1]
                    return f"{part}/{next_part}"
                except (IndexError, ValueError):
                    return part
        
        # Return filename without extension as component
        filename = path_parts[-1] if path_parts else 'unknown'
        return filename.split('.')[0] if '.' in filename else filename
    
    def _have_logical_connection(self, vuln1: Dict[str, Any], vuln2: Dict[str, Any]) -> bool:
        """Check if vulnerabilities have a logical connection."""
        
        # Check for common application flows
        flow_connections = [
            (['auth', 'login'], ['data', 'profile', 'user']),
            (['api', 'endpoint'], ['frontend', 'client']),
            (['upload', 'file'], ['process', 'handle']),
            (['input', 'form'], ['output', 'display'])
        ]
        
        file1 = vuln1.get('file_path', '').lower()
        file2 = vuln2.get('file_path', '').lower()
        
        for source_keywords, target_keywords in flow_connections:
            if (any(keyword in file1 for keyword in source_keywords) and
                any(keyword in file2 for keyword in target_keywords)):
                return True
            
            if (any(keyword in file2 for keyword in source_keywords) and
                any(keyword in file1 for keyword in target_keywords)):
                return True
        
        return False
    
    def _same_user_context(self, vuln1: Dict[str, Any], vuln2: Dict[str, Any]) -> bool:
        """Check if vulnerabilities can be exploited in the same user context."""
        
        # Check if both are client-side or both are server-side
        client_side_indicators = ['xss', 'csrf', 'dom', 'client', 'browser']
        server_side_indicators = ['sql', 'command', 'server', 'api', 'backend']
        
        vuln1_desc = (vuln1.get('description', '') + ' ' + vuln1.get('title', '')).lower()
        vuln2_desc = (vuln2.get('description', '') + ' ' + vuln2.get('title', '')).lower()
        
        vuln1_client = any(indicator in vuln1_desc for indicator in client_side_indicators)
        vuln1_server = any(indicator in vuln1_desc for indicator in server_side_indicators)
        
        vuln2_client = any(indicator in vuln2_desc for indicator in client_side_indicators)
        vuln2_server = any(indicator in vuln2_desc for indicator in server_side_indicators)
        
        # Both client-side or both server-side
        return (vuln1_client and vuln2_client) or (vuln1_server and vuln2_server)
    
    def _get_affected_components(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Get list of affected components from vulnerabilities."""
        
        components = set()
        for vuln in vulnerabilities:
            file_path = vuln.get('file_path', '')
            if file_path:
                component = self._extract_component_name(file_path)
                components.add(component)
        
        return list(components)
    
    def _reset_component_tracking(self):
        """Reset component tracking dictionaries."""
        self.vulnerability_components.clear()
        self.component_vulnerabilities.clear()
    
    def _update_correlation_stats(self):
        """Update correlation statistics."""
        self.correlation_stats['total_correlations'] = len(self.correlations)
        self.correlation_stats['attack_paths_discovered'] = len(self.attack_paths)
        
        # Reset type counters
        for correlation_type in CorrelationType:
            self.correlation_stats['correlation_types'][correlation_type.value] = 0
        
        # Count correlation types
        for correlation in self.correlations.values():
            self.correlation_stats['correlation_types'][correlation.correlation_type.value] += 1
        
        # Count high impact correlations
        self.correlation_stats['high_impact_correlations'] = sum(
            1 for c in self.correlations.values() 
            if c.impact_amplification > 1.5 or c.mitigation_priority == "critical"
        )
    
    def get_attack_paths(self) -> List[AttackPath]:
        """Get discovered attack paths."""
        return list(self.attack_paths.values())
    
    def get_correlation_statistics(self) -> Dict[str, Any]:
        """Get correlation analysis statistics."""
        return dict(self.correlation_stats)
    
    def get_high_priority_correlations(self) -> List[VulnerabilityCorrelation]:
        """Get high priority correlations requiring immediate attention."""
        return [c for c in self.correlations.values() 
                if c.mitigation_priority in ["high", "critical"] and c.confidence > 0.7]
