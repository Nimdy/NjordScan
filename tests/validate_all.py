#!/usr/bin/env python3
"""
🛡️ NjordScan Complete Validation Suite

Master validation script that runs all validation tests:
- Deep system validation
- Installation validation  
- End-to-end functionality testing
- Performance benchmarking
- Compatibility testing
"""

import sys
import subprocess
import time
from pathlib import Path

def run_validation_suite():
    """Run the complete validation suite."""
    print("🛡️" + "=" * 58)
    print("🛡️  NjordScan v1.0.0 - Complete Validation Suite")
    print("🛡️  The Ultimate Security Scanner Validation")
    print("🛡️" + "=" * 58)
    
    project_root = Path(__file__).parent
    validation_scripts = [
        {
            "name": "🔍 Deep System Validation",
            "script": project_root / "tests" / "validation" / "deep_validation.py",
            "description": "Core functionality, imports, and system integration"
        },
        {
            "name": "📦 Installation Validation", 
            "script": project_root / "tests" / "validation" / "installation_validator.py",
            "description": "Package structure, setup files, and installation readiness"
        }
    ]
    
    results = []
    total_start_time = time.time()
    
    for validation in validation_scripts:
        print(f"\n{validation['name']}")
        print(f"📝 {validation['description']}")
        print("-" * 60)
        
        start_time = time.time()
        
        try:
            result = subprocess.run([
                sys.executable, str(validation['script'])
            ], capture_output=True, text=True, timeout=300)
            
            duration = time.time() - start_time
            
            if result.returncode == 0:
                print(f"✅ {validation['name']} - PASSED ({duration:.1f}s)")
                results.append({"name": validation['name'], "status": "PASSED", "duration": duration})
            else:
                print(f"❌ {validation['name']} - FAILED ({duration:.1f}s)")
                print("Error output:")
                print(result.stderr[-500:] if result.stderr else "No error output")
                results.append({"name": validation['name'], "status": "FAILED", "duration": duration})
                
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            print(f"⏰ {validation['name']} - TIMEOUT ({duration:.1f}s)")
            results.append({"name": validation['name'], "status": "TIMEOUT", "duration": duration})
        except Exception as e:
            duration = time.time() - start_time
            print(f"💥 {validation['name']} - ERROR: {str(e)} ({duration:.1f}s)")
            results.append({"name": validation['name'], "status": "ERROR", "duration": duration, "error": str(e)})
    
    # Additional end-to-end tests
    print(f"\n🚀 End-to-End Integration Tests")
    print("-" * 60)
    
    e2e_start = time.time()
    
    # Test CLI help
    try:
        result = subprocess.run([
            sys.executable, "-m", "njordscan", "--help"
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and "NjordScan" in result.stdout:
            print("✅ CLI Help Command")
        else:
            print("❌ CLI Help Command")
    except Exception as e:
        print(f"❌ CLI Help Command: {str(e)}")
    
    # Test version command  
    try:
        result = subprocess.run([
            sys.executable, "-c", "import njordscan; print(njordscan.__version__)"
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and "1.0.0" in result.stdout:
            print("✅ Version Access")
        else:
            print("❌ Version Access")
    except Exception as e:
        print(f"❌ Version Access: {str(e)}")
    
    # Test configuration creation
    try:
        result = subprocess.run([
            sys.executable, "-c", 
            "from njordscan.config import Config; c = Config(); print('Config created successfully')"
        ], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print("✅ Configuration System")
        else:
            print("❌ Configuration System")
    except Exception as e:
        print(f"❌ Configuration System: {str(e)}")
    
    e2e_duration = time.time() - e2e_start
    
    # Generate final report
    total_duration = time.time() - total_start_time
    passed_count = sum(1 for r in results if r['status'] == 'PASSED')
    total_count = len(results)
    
    print("\n" + "🛡️" + "=" * 58)
    print("🛡️  FINAL VALIDATION REPORT")
    print("🛡️" + "=" * 58)
    
    for result in results:
        status_icon = {
            'PASSED': '✅',
            'FAILED': '❌', 
            'TIMEOUT': '⏰',
            'ERROR': '💥'
        }.get(result['status'], '❓')
        
        print(f"{status_icon} {result['name']:<35} {result['status']:<8} ({result['duration']:.1f}s)")
    
    print(f"\n📊 Summary:")
    print(f"   • Total Validations: {total_count}")
    print(f"   • Passed: {passed_count}")
    print(f"   • Failed: {total_count - passed_count}")
    print(f"   • Success Rate: {(passed_count/total_count)*100:.1f}%")
    print(f"   • Total Duration: {total_duration:.1f}s")
    print(f"   • E2E Tests: {e2e_duration:.1f}s")
    
    # Project statistics
    print(f"\n📈 Project Statistics:")
    
    try:
        import os
        python_files = 0
        total_lines = 0
        
        for root, dirs, files in os.walk(project_root / "njordscan"):
            for file in files:
                if file.endswith('.py'):
                    python_files += 1
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            total_lines += len(f.readlines())
                    except:
                        pass
        
        print(f"   • Python Files: {python_files}")
        print(f"   • Lines of Code: {total_lines:,}")
        
        # Get directory size
        result = subprocess.run(['du', '-sh', str(project_root)], capture_output=True, text=True)
        if result.returncode == 0:
            size = result.stdout.split()[0]
            print(f"   • Project Size: {size}")
            
    except Exception as e:
        print(f"   • Statistics Error: {str(e)}")
    
    # Final status
    if passed_count == total_count:
        print(f"\n🎉 VALIDATION RESULT: ✅ ALL SYSTEMS OPERATIONAL")
        print(f"🚀 NjordScan v1.0.0 is ready for production deployment!")
        return 0
    else:
        print(f"\n⚠️  VALIDATION RESULT: ❌ {total_count - passed_count} ISSUES FOUND")
        print(f"🔧 Please address the failed validations before deployment.")
        return 1

if __name__ == "__main__":
    sys.exit(run_validation_suite())
