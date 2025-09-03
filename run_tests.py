#!/usr/bin/env python3
"""
Test runner for NjordScan.
"""

import sys
import os
import subprocess
import argparse
from pathlib import Path

def run_tests(test_type="all", verbose=False, coverage=False, parallel=False):
    """Run tests with specified options."""
    
    # Base pytest command
    cmd = ["python", "-m", "pytest"]
    
    # Add test paths
    if test_type == "all":
        cmd.append("tests/")
    elif test_type == "unit":
        cmd.extend(["tests/test_core_functionality.py", "-m", "unit"])
    elif test_type == "integration":
        cmd.extend(["tests/", "-m", "integration"])
    elif test_type == "cli":
        cmd.append("tests/test_cli.py")
    elif test_type == "ai":
        cmd.extend(["tests/test_ai_intelligence.py", "-m", "ai"])
    else:
        cmd.append(f"tests/test_{test_type}.py")
    
    # Add options
    if verbose:
        cmd.append("-v")
    
    if coverage:
        cmd.extend(["--cov=njordscan", "--cov-report=html", "--cov-report=term"])
    
    if parallel:
        cmd.extend(["-n", "auto"])
    
    # Add markers to exclude slow tests by default
    cmd.extend(["-m", "not slow"])
    
    print(f"Running command: {' '.join(cmd)}")
    
    # Run tests
    try:
        result = subprocess.run(cmd, cwd=Path(__file__).parent)
        return result.returncode
    except KeyboardInterrupt:
        print("\nTests interrupted by user")
        return 1
    except Exception as e:
        print(f"Error running tests: {e}")
        return 1

def main():
    """Main test runner function."""
    parser = argparse.ArgumentParser(description="Run NjordScan tests")
    parser.add_argument(
        "--type", 
        choices=["all", "unit", "integration", "cli", "ai", "core"],
        default="all",
        help="Type of tests to run"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--coverage", "-c",
        action="store_true",
        help="Run with coverage reporting"
    )
    parser.add_argument(
        "--parallel", "-p",
        action="store_true",
        help="Run tests in parallel"
    )
    parser.add_argument(
        "--slow",
        action="store_true",
        help="Include slow tests"
    )
    
    args = parser.parse_args()
    
    # Check if pytest is available
    try:
        import pytest
    except ImportError:
        print("Error: pytest is not installed. Please install test dependencies:")
        print("pip install -r requirements-test.txt")
        return 1
    
    # Run tests
    exit_code = run_tests(
        test_type=args.type,
        verbose=args.verbose,
        coverage=args.coverage,
        parallel=args.parallel
    )
    
    if exit_code == 0:
        print("\n✅ All tests passed!")
    else:
        print("\n❌ Some tests failed!")
    
    return exit_code

if __name__ == "__main__":
    sys.exit(main())
