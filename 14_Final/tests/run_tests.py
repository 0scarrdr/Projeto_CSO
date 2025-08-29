"""
Test Runner Script
Executes all SOAR system tests with comprehensive reporting
"""

import subprocess
import sys
import os
from pathlib import Path
import time
import json
from datetime import datetime
import argparse

class SOARTestRunner:
    """Comprehensive test runner for SOAR system"""

    def __init__(self, test_dir=None, verbose=True):
        self.test_dir = test_dir or Path(__file__).parent
        self.verbose = verbose
        self.results = {}
        self.start_time = None

    def run_unit_tests(self):
        """Run unit tests for all components"""
        print("🧪 Running Unit Tests...")
        print("=" * 50)

        test_files = [
            "test_core.py",
            "test_detection.py",
            "test_analysis.py",
            "test_response.py",
            "test_prediction.py"
        ]

        results = {}
        for test_file in test_files:
            print(f"\n📋 Running {test_file}...")
            result = self._run_pytest(test_file, ["-v"])
            results[test_file] = result

        return results

    def run_integration_tests(self):
        """Run integration tests"""
        print("\n🔗 Running Integration Tests...")
        print("=" * 50)

        result = self._run_pytest("test_integration.py", ["-v", "--tb=short"])
        return {"integration": result}

    def run_api_tests(self):
        """Run API tests"""
        print("\n🌐 Running API Tests...")
        print("=" * 50)

        result = self._run_pytest("test_api.py", ["-v", "--tb=short"])
        return {"api": result}

    def run_performance_tests(self):
        """Run performance tests"""
        print("\n⚡ Running Performance Tests...")
        print("=" * 50)

        result = self._run_pytest("test_integration.py::TestPerformanceBenchmarks", ["-v"])
        return {"performance": result}

    def run_all_tests(self):
        """Run all test suites"""
        print("🚀 Starting Complete SOAR Test Suite")
        print("=" * 60)

        self.start_time = time.time()

        # Run all test suites
        results = {}

        results.update(self.run_unit_tests())
        results.update(self.run_integration_tests())
        results.update(self.run_api_tests())
        results.update(self.run_performance_tests())

        # Generate comprehensive report
        self.generate_report(results)

        return results

    def _run_pytest(self, test_path, extra_args=None):
        """Run pytest with given arguments"""
        cmd = [sys.executable, "-m", "pytest", str(self.test_dir / test_path)]

        if extra_args:
            cmd.extend(extra_args)

        if not self.verbose:
            cmd.extend(["--tb=no", "-q"])

        try:
            result = subprocess.run(
                cmd,
                capture_output=not self.verbose,
                text=True,
                cwd=self.test_dir.parent
            )

            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "success": result.returncode == 0
            }

        except Exception as e:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "success": False
            }

    def generate_report(self, results):
        """Generate comprehensive test report"""
        end_time = time.time()
        duration = end_time - self.start_time

        print("\n" + "=" * 60)
        print("📊 SOAR TEST SUITE RESULTS")
        print("=" * 60)

        total_tests = 0
        passed_tests = 0
        failed_tests = 0

        for test_suite, result in results.items():
            print(f"\n🔍 {test_suite.upper()} TESTS:")
            print("-" * 30)

            if result["success"]:
                print("✅ PASSED")
                passed_tests += 1
            else:
                print("❌ FAILED")
                failed_tests += 1

                if result["stderr"]:
                    print(f"Error: {result['stderr']}")

            total_tests += 1

        print(f"\n📈 SUMMARY:")
        print(f"Total Test Suites: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(".2f")
        print(".1f")

        # Save detailed report
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": duration,
            "total_suites": total_tests,
            "passed_suites": passed_tests,
            "failed_suites": failed_tests,
            "success_rate": (passed_tests / total_tests) * 100 if total_tests > 0 else 0,
            "results": results
        }

        report_file = self.test_dir.parent / "test_results.json"
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        print(f"\n📄 Detailed report saved to: {report_file}")

        return report_data

    def run_smoke_tests(self):
        """Run quick smoke tests to verify basic functionality"""
        print("💨 Running Smoke Tests...")
        print("=" * 50)

        # Quick import tests
        smoke_tests = [
            "test_core.py::TestIncidentHandler::test_initialization",
            "test_detection.py::TestThreatDetector::test_initialization",
            "test_analysis.py::TestIncidentAnalyzer::test_initialization",
            "test_response.py::TestAutomatedResponder::test_initialization",
            "test_prediction.py::TestThreatPredictor::test_initialization"
        ]

        results = []
        for test in smoke_tests:
            print(f"🧪 Testing {test}...")
            result = self._run_pytest(test, ["-v"])
            results.append(result["success"])

        success_count = sum(results)
        total_count = len(results)

        print(f"\n💨 Smoke Test Results: {success_count}/{total_count} passed")

        return success_count == total_count


def main():
    parser = argparse.ArgumentParser(description="SOAR Test Runner")
    parser.add_argument("--test-dir", help="Test directory path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--smoke", action="store_true", help="Run only smoke tests")
    parser.add_argument("--unit", action="store_true", help="Run only unit tests")
    parser.add_argument("--integration", action="store_true", help="Run only integration tests")
    parser.add_argument("--api", action="store_true", help="Run only API tests")
    parser.add_argument("--performance", action="store_true", help="Run only performance tests")

    args = parser.parse_args()

    test_dir = Path(args.test_dir) if args.test_dir else None
    runner = SOARTestRunner(test_dir, args.verbose)

    if args.smoke:
        success = runner.run_smoke_tests()
        sys.exit(0 if success else 1)

    elif args.unit:
        results = runner.run_unit_tests()
        success = all(result["success"] for result in results.values())
        sys.exit(0 if success else 1)

    elif args.integration:
        results = runner.run_integration_tests()
        success = all(result["success"] for result in results.values())
        sys.exit(0 if success else 1)

    elif args.api:
        results = runner.run_api_tests()
        success = all(result["success"] for result in results.values())
        sys.exit(0 if success else 1)

    elif args.performance:
        results = runner.run_performance_tests()
        success = all(result["success"] for result in results.values())
        sys.exit(0 if success else 1)

    else:
        # Run all tests
        results = runner.run_all_tests()
        success = all(result["success"] for result in results.values())
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
