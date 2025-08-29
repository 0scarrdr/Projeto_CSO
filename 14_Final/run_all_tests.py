#!/usr/bin/env python3
"""
Automated Test Execution Script
Runs complete SOAR test suite and generates reports
"""

import subprocess
import sys
import os
from pathlib import Path
import json
from datetime import datetime

def main():
    """Execute complete test suite"""
    project_root = Path(__file__).parent
    tests_dir = project_root / "tests"

    print("🚀 SOAR Automated Test Suite")
    print("=" * 50)
    print(f"Project Root: {project_root}")
    print(f"Tests Directory: {tests_dir}")
    print()

    # Check if we're in the right directory
    if not tests_dir.exists():
        print("❌ Tests directory not found!")
        print(f"Expected: {tests_dir}")
        sys.exit(1)

    # Check if run_tests.py exists
    run_tests_script = tests_dir / "run_tests.py"
    if not run_tests_script.exists():
        print("❌ Test runner script not found!")
        print(f"Expected: {run_tests_script}")
        sys.exit(1)

    # Execute the test suite
    print("📋 Executing complete test suite...")
    print()

    try:
        result = subprocess.run([
            sys.executable,
            str(run_tests_script)
        ], cwd=project_root, capture_output=False)

        # Check results
        if result.returncode == 0:
            print("\n✅ All tests passed successfully!")
            print_test_summary(project_root)
        else:
            print(f"\n❌ Tests failed with return code: {result.returncode}")
            print_test_summary(project_root)

        sys.exit(result.returncode)

    except KeyboardInterrupt:
        print("\n⚠️  Test execution interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n💥 Error executing tests: {e}")
        sys.exit(1)

def print_test_summary(project_root):
    """Print test results summary"""
    results_file = project_root / "test_results.json"

    if results_file.exists():
        try:
            with open(results_file, 'r') as f:
                results = json.load(f)

            print("\n📊 Test Summary:")
            print("-" * 30)
            print(f"Timestamp: {results['timestamp']}")
            print(f"Duration: {results['duration_seconds']:.2f}s")
            print(f"Test Suites: {results['total_suites']}")
            print(f"Passed: {results['passed_suites']}")
            print(f"Failed: {results['failed_suites']}")
            print(".1f")

            if results['success_rate'] >= 90:
                print("🎉 Excellent test coverage!")
            elif results['success_rate'] >= 75:
                print("👍 Good test coverage")
            else:
                print("⚠️  Test coverage needs improvement")

        except Exception as e:
            print(f"Could not read test results: {e}")
    else:
        print("No test results file found")

if __name__ == "__main__":
    main()
