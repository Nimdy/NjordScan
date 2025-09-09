#!/usr/bin/env python3
"""
Test Runner and Status Reporter for NjordScan

This script runs the test suite and generates a detailed status report.
"""

import subprocess
import sys
import re
from pathlib import Path

def run_tests():
    """Run the test suite and return results."""
    print("🧪 Running NjordScan Test Suite...")
    print("=" * 50)
    
    try:
        # Run pytest with detailed output
        result = subprocess.run([
            sys.executable, '-m', 'pytest', 'tests/', 
            '-v', '--tb=short'
        ], capture_output=True, text=True, cwd=Path(__file__).parent)
        
        return result.returncode, result.stdout, result.stderr
        
    except Exception as e:
        print(f"❌ Error running tests: {e}")
        return 1, "", str(e)

def parse_test_results(stdout):
    """Parse pytest output to extract test statistics."""
    # Try multiple patterns for different pytest output formats
    patterns = [
        r'(\d+) failed, (\d+) passed, (\d+) skipped',
        r'(\d+) passed, (\d+) failed, (\d+) skipped',
        r'(\d+) passed, (\d+) skipped, (\d+) failed',
        r'(\d+) failed, (\d+) passed',
        r'(\d+) passed, (\d+) failed',
        r'=========== (\d+) failed, (\d+) passed, (\d+) skipped.*?===========',
        r'=========== (\d+) passed, (\d+) failed, (\d+) skipped.*?==========='
    ]
    
    for pattern in patterns:
        summary_match = re.search(pattern, stdout)
        if summary_match:
            groups = summary_match.groups()
            
            # Handle different group orders
            if 'failed' in pattern and 'passed' in pattern and 'skipped' in pattern:
                if pattern.startswith(r'(\d+) failed'):
                    failed, passed, skipped = map(int, groups)
                else:
                    passed, failed, skipped = map(int, groups)
            elif 'failed' in pattern and 'passed' in pattern:
                if pattern.startswith(r'(\d+) failed'):
                    failed, passed = map(int, groups)
                    skipped = 0
                else:
                    passed, failed = map(int, groups)
                    skipped = 0
            else:
                continue
            
            total = failed + passed + skipped
            pass_rate = (passed / (total - skipped)) * 100 if (total - skipped) > 0 else 0
            
            return {
                'total': total,
                'passed': passed,
                'failed': failed,
                'skipped': skipped,
                'pass_rate': pass_rate
            }
    
    # Fallback: try to extract from any line with numbers
    lines = stdout.split('\n')
    for line in lines:
        if 'failed' in line and 'passed' in line:
            numbers = re.findall(r'\d+', line)
            if len(numbers) >= 2:
                try:
                    failed = int(numbers[0])
                    passed = int(numbers[1])
                    skipped = int(numbers[2]) if len(numbers) > 2 else 0
                    total = failed + passed + skipped
                    pass_rate = (passed / (total - skipped)) * 100 if (total - skipped) > 0 else 0
                    
                    return {
                        'total': total,
                        'passed': passed,
                        'failed': failed,
                        'skipped': skipped,
                        'pass_rate': pass_rate
                    }
                except (ValueError, IndexError):
                    continue
    
    return None

def generate_status_report(stats):
    """Generate a detailed status report."""
    if not stats:
        return "❌ Could not parse test results"
    
    report = []
    report.append("📊 NjordScan Test Status Report")
    report.append("=" * 40)
    report.append(f"Total Tests: {stats['total']}")
    report.append(f"✅ Passed: {stats['passed']}")
    report.append(f"❌ Failed: {stats['failed']}")
    report.append(f"⏭️ Skipped: {stats['skipped']}")
    report.append(f"📈 Pass Rate: {stats['pass_rate']:.1f}%")
    report.append("")
    
    # Status assessment
    if stats['pass_rate'] >= 90:
        status = "🟢 Excellent"
        color = "green"
    elif stats['pass_rate'] >= 80:
        status = "🟡 Good"
        color = "yellow"
    elif stats['pass_rate'] >= 70:
        status = "🟠 Needs Improvement"
        color = "orange"
    else:
        status = "🔴 Critical Issues"
        color = "red"
    
    report.append(f"Overall Status: {status}")
    report.append("")
    
    # Recommendations
    if stats['failed'] > 0:
        report.append("🔧 Recommendations:")
        report.append("- Fix failing tests to improve reliability")
        report.append("- Focus on core functionality first")
        report.append("- Consider async test setup improvements")
    
    if stats['skipped'] > 0:
        report.append("- Address skipped tests for better coverage")
    
    return "\n".join(report)

def main():
    """Main test runner function."""
    print("🛡️ NjordScan Test Runner")
    print("=" * 30)
    
    # Run tests
    returncode, stdout, stderr = run_tests()
    
    # Parse results (pytest often outputs to stderr)
    stats = parse_test_results(stdout + stderr)
    
    # Debug output
    if '--debug' in sys.argv:
        print(f"Debug - Return code: {returncode}")
        print(f"Debug - STDOUT length: {len(stdout)}")
        print(f"Debug - STDERR length: {len(stderr)}")
        print(f"Debug - Last 200 chars of stdout: {stdout[-200:]}")
        print(f"Debug - Last 200 chars of stderr: {stderr[-200:]}")
        print(f"Debug - Combined output: {stdout + stderr}")
    
    # Generate report
    report = generate_status_report(stats)
    print(report)
    
    # Print raw output if requested
    if '--verbose' in sys.argv:
        print("\n" + "=" * 50)
        print("Raw Test Output:")
        print(stdout)
        if stderr:
            print("Errors:")
            print(stderr)
    
    # Update README badge if requested
    if '--update-badge' in sys.argv and stats:
        update_readme_badge(stats['pass_rate'])
    
    return returncode

def update_readme_badge(pass_rate):
    """Update the test badge in README.md."""
    readme_path = Path(__file__).parent / "README.md"
    
    if not readme_path.exists():
        print("❌ README.md not found")
        return
    
    # Read current README
    with open(readme_path, 'r') as f:
        content = f.read()
    
    # Determine badge color and text
    if pass_rate >= 90:
        color = "brightgreen"
        text = f"{pass_rate:.0f}%25%20Passing"
    elif pass_rate >= 80:
        color = "yellow"
        text = f"{pass_rate:.0f}%25%20Passing"
    elif pass_rate >= 70:
        color = "orange"
        text = f"{pass_rate:.0f}%25%20Passing"
    else:
        color = "red"
        text = f"{pass_rate:.0f}%25%20Passing"
    
    # Update badge
    badge_pattern = r'\[!\[Tests\].*?\]\(#\)'
    new_badge = f'[![Tests](https://img.shields.io/badge/Tests-{text}-{color}.svg)](#)'
    
    updated_content = re.sub(badge_pattern, new_badge, content)
    
    # Write back
    with open(readme_path, 'w') as f:
        f.write(updated_content)
    
    print(f"✅ Updated README badge to {pass_rate:.1f}%")

if __name__ == "__main__":
    sys.exit(main())