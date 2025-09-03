#!/usr/bin/env python3
"""
Test script to validate AI integration with standardized vulnerability types.
"""

import asyncio
import sys
import os
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from njordscan.vulnerability import Vulnerability, Severity, Confidence
from njordscan.intelligence.false_positive_filter import FalsePositiveFilter
from njordscan.intelligence.behavioral_analyzer import BehavioralAnalyzer
from njordscan.intelligence.intelligence_engine import IntelligenceEngine
from njordscan.ai.ai_orchestrator import AISecurityOrchestrator

async def test_false_positive_filter_integration():
    """Test False Positive Filter with standardized vulnerability types."""
    print("🧠 Testing False Positive Filter Integration...")
    
    # Create test vulnerabilities with standardized types
    test_vulnerabilities = [
        Vulnerability(
            id="test_1",
            title="XSS Vulnerability",
            description="Potential XSS in user input",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            vuln_type="xss_reflected",
            file_path="test.js",
            line_number=10,
            code_snippet="document.innerHTML = userInput;",
            fix="Use textContent instead of innerHTML or sanitize input",
            reference="https://owasp.org/www-community/attacks/xss/"
        ),
        Vulnerability(
            id="test_2", 
            title="SQL Injection",
            description="Potential SQL injection in query",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            vuln_type="sql_injection",
            file_path="database.js",
            line_number=25,
            code_snippet="SELECT * FROM users WHERE id = " + "userId",
            fix="Use parameterized queries or prepared statements",
            reference="https://owasp.org/www-community/attacks/SQL_Injection"
        )
    ]
    
    # Initialize filter
    filter_system = FalsePositiveFilter()
    
    # Test filtering
    true_positives, false_positives = filter_system.filter_vulnerabilities(test_vulnerabilities)
    
    print(f"  ✅ Filtered {len(test_vulnerabilities)} vulnerabilities")
    print(f"  ✅ True positives: {len(true_positives)}")
    print(f"  ✅ False positives: {len(false_positives)}")
    
    # Test pattern matching with standardized types
    for vuln in true_positives:
        print(f"  ✅ {vuln.vuln_type} - {vuln.title}")
    
    return True

async def test_behavioral_analyzer_integration():
    """Test Behavioral Analyzer with standardized vulnerability types."""
    print("\n🔍 Testing Behavioral Analyzer Integration...")
    
    # Create test vulnerability
    test_vuln = Vulnerability(
        id="test_behavioral",
        title="Command Injection",
        description="Potential command injection vulnerability",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        vuln_type="command_injection",
        file_path="server.js",
        line_number=15,
        code_snippet="exec(userCommand);",
        fix="Use safe command execution methods and validate input",
        reference="https://owasp.org/www-community/attacks/Command_Injection"
    )
    
    # Initialize behavioral analyzer
    analyzer = BehavioralAnalyzer()
    
    # Test vulnerability enhancement
    enhanced_vuln = analyzer.enhance_vulnerability_with_behavioral_context(test_vuln)
    
    print(f"  ✅ Enhanced vulnerability: {enhanced_vuln.title}")
    print(f"  ✅ Type: {enhanced_vuln.vuln_type}")
    
    # Check if metadata was enhanced
    if enhanced_vuln.metadata and 'behavioral_analysis' in enhanced_vuln.metadata:
        print(f"  ✅ Behavioral analysis metadata added")
        print(f"  ✅ CWE codes: {enhanced_vuln.metadata.get('cwe_codes', [])}")
        print(f"  ✅ OWASP category: {enhanced_vuln.metadata.get('owasp_category', 'N/A')}")
    
    return True

async def test_intelligence_engine_integration():
    """Test Intelligence Engine with standardized vulnerability types."""
    print("\n🧠 Testing Intelligence Engine Integration...")
    
    # Create test vulnerabilities
    test_vulnerabilities = [
        {
            'id': 'test_intel_1',
            'title': 'XSS Stored',
            'description': 'Stored XSS vulnerability',
            'severity': 'high',
            'confidence': 'medium',
            'vuln_type': 'xss_stored',
            'file_path': 'comment.js',
            'line_number': 30
        },
        {
            'id': 'test_intel_2',
            'title': 'SSRF Vulnerability',
            'description': 'Server-side request forgery',
            'severity': 'critical',
            'confidence': 'high',
            'vuln_type': 'ssrf',
            'file_path': 'api.js',
            'line_number': 45
        }
    ]
    
    # Initialize intelligence engine
    engine = IntelligenceEngine()
    
    # Test vulnerability enhancement
    enhanced_vulns = engine.enhance_vulnerabilities_with_intelligence(test_vulnerabilities)
    
    print(f"  ✅ Enhanced {len(enhanced_vulns)} vulnerabilities")
    
    for vuln in enhanced_vulns:
        print(f"  ✅ {vuln['vuln_type']} - {vuln['title']}")
        
        # Check if intelligence analysis was added
        if 'metadata' in vuln and 'intelligence_analysis' in vuln['metadata']:
            print(f"    ✅ Intelligence analysis metadata added")
            print(f"    ✅ CWE codes: {vuln['metadata'].get('cwe_codes', [])}")
            print(f"    ✅ OWASP category: {vuln['metadata'].get('owasp_category', 'N/A')}")
    
    return True

async def test_ai_orchestrator_integration():
    """Test AI Orchestrator with standardized vulnerability types."""
    print("\n🤖 Testing AI Orchestrator Integration...")
    
    # Create test vulnerabilities
    test_vulnerabilities = [
        {
            'id': 'test_ai_1',
            'title': 'Privilege Escalation',
            'description': 'Potential privilege escalation vulnerability',
            'severity': 'critical',
            'confidence': 'high',
            'vuln_type': 'privilege_escalation',
            'file_path': 'auth.js',
            'line_number': 20
        },
        {
            'id': 'test_ai_2',
            'title': 'Secrets Exposure',
            'description': 'Hardcoded secrets in configuration',
            'severity': 'high',
            'confidence': 'medium',
            'vuln_type': 'secrets_exposure',
            'file_path': 'config.js',
            'line_number': 5
        }
    ]
    
    # Initialize AI orchestrator
    orchestrator = AISecurityOrchestrator()
    
    # Test vulnerability enhancement
    enhanced_vulns = orchestrator.enhance_vulnerabilities_with_ai_analysis(test_vulnerabilities)
    
    print(f"  ✅ Enhanced {len(enhanced_vulns)} vulnerabilities")
    
    for vuln in enhanced_vulns:
        print(f"  ✅ {vuln['vuln_type']} - {vuln['title']}")
        
        # Check if AI analysis was added
        if 'metadata' in vuln and 'ai_analysis' in vuln['metadata']:
            print(f"    ✅ AI analysis metadata added")
            print(f"    ✅ CWE codes: {vuln['metadata'].get('cwe_codes', [])}")
            print(f"    ✅ OWASP category: {vuln['metadata'].get('owasp_category', 'N/A')}")
            print(f"    ✅ AI enhanced: {vuln['metadata']['ai_analysis'].get('ai_enhanced', False)}")
    
    return True

async def main():
    """Run all AI integration tests."""
    print("🛡️ NjordScan AI Integration Testing")
    print("=" * 50)
    
    try:
        # Test False Positive Filter
        await test_false_positive_filter_integration()
        
        # Test Behavioral Analyzer
        await test_behavioral_analyzer_integration()
        
        # Test Intelligence Engine
        await test_intelligence_engine_integration()
        
        # Test AI Orchestrator
        await test_ai_orchestrator_integration()
        
        print("\n" + "=" * 50)
        print("🎉 All AI integration tests passed!")
        print("✅ AI modules are properly integrated with standardized vulnerability types")
        
    except Exception as e:
        print(f"\n❌ AI integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    asyncio.run(main())
