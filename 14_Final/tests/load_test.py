"""
Load Testing Script for SOAR System
Tests system performance under various load conditions
"""

import asyncio
import aiohttp
import time
import statistics
import json
from datetime import datetime
from pathlib import Path
import sys
import argparse
from typing import List, Dict, Any

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class LoadTester:
    """Load testing utility for SOAR API"""

    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url.rstrip("/")
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def generate_test_event(self, event_id: int) -> Dict[str, Any]:
        """Generate a test security event"""
        return {
            "id": f"load-test-event-{event_id}",
            "timestamp": datetime.now().isoformat(),
            "source": "load_tester",
            "event_type": "malware_detected",
            "severity": "high",
            "data": {
                "message": f"Load test malware detection {event_id}",
                "src_ip": f"192.168.1.{event_id % 255}",
                "host_id": f"LOAD_HOST_{event_id % 10}",
                "file_hash": f"load_test_hash_{event_id}",
                "description": f"Simulated malware for load testing {event_id}"
            }
        }

    async def send_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Send a single event to the API"""
        if not self.session:
            raise RuntimeError("LoadTester must be used as async context manager")

        start_time = time.time()

        try:
            async with self.session.post(
                f"{self.base_url}/incidents",
                json=event,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                end_time = time.time()
                response_time = end_time - start_time

                result = await response.json()

                return {
                    "success": response.status == 200,
                    "status_code": response.status,
                    "response_time": response_time,
                    "data": result if response.status == 200 else None,
                    "error": result.get("detail") if response.status != 200 else None
                }

        except Exception as e:
            end_time = time.time()
            response_time = end_time - start_time

            return {
                "success": False,
                "status_code": None,
                "response_time": response_time,
                "data": None,
                "error": str(e)
            }

    async def run_load_test(self, num_requests: int, concurrency: int = 10) -> Dict[str, Any]:
        """Run load test with specified parameters"""
        print(f"🚀 Starting Load Test: {num_requests} requests, {concurrency} concurrent")
        print("=" * 60)

        start_time = time.time()
        results = []

        # Create semaphore to limit concurrency
        semaphore = asyncio.Semaphore(concurrency)

        async def send_with_semaphore(event_id: int):
            async with semaphore:
                event = self.generate_test_event(event_id)
                result = await self.send_event(event)
                return result

        # Create and run tasks
        tasks = [send_with_semaphore(i) for i in range(num_requests)]
        completed_results = []

        # Process results as they complete
        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed_results.append(result)

            # Print progress
            completed = len(completed_results)
            if completed % 50 == 0 or completed == num_requests:
                success_count = sum(1 for r in completed_results if r["success"])
                print(f"📊 Progress: {completed}/{num_requests} "
                      f"({success_count} successful, "
                      f"{completed - success_count} failed)")

        end_time = time.time()
        total_time = end_time - start_time

        # Analyze results
        successful_requests = [r for r in completed_results if r["success"]]
        failed_requests = [r for r in completed_results if not r["success"]]

        response_times = [r["response_time"] for r in completed_results]

        analysis = {
            "total_requests": num_requests,
            "successful_requests": len(successful_requests),
            "failed_requests": len(failed_requests),
            "success_rate": (len(successful_requests) / num_requests) * 100,
            "total_time_seconds": total_time,
            "requests_per_second": num_requests / total_time,
            "response_time_stats": {
                "mean": statistics.mean(response_times),
                "median": statistics.median(response_times),
                "min": min(response_times),
                "max": max(response_times),
                "95th_percentile": statistics.quantiles(response_times, n=20)[18],  # 95th percentile
                "99th_percentile": statistics.quantiles(response_times, n=100)[98]  # 99th percentile
            },
            "error_summary": self._analyze_errors(failed_requests)
        }

        return analysis

    def _analyze_errors(self, failed_requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze failed requests to categorize errors"""
        error_counts = {}
        status_codes = {}

        for request in failed_requests:
            error = request.get("error", "Unknown error")
            status = request.get("status_code")

            # Categorize errors
            if status:
                status_codes[status] = status_codes.get(status, 0) + 1

            if "timeout" in error.lower():
                error_type = "timeout"
            elif "connection" in error.lower():
                error_type = "connection_error"
            elif status == 422:
                error_type = "validation_error"
            elif status == 500:
                error_type = "server_error"
            else:
                error_type = "other"

            error_counts[error_type] = error_counts.get(error_type, 0) + 1

        return {
            "error_types": error_counts,
            "status_codes": status_codes,
            "sample_errors": [r.get("error") for r in failed_requests[:5]]
        }

    def print_report(self, analysis: Dict[str, Any]):
        """Print detailed load test report"""
        print("\n" + "=" * 60)
        print("📊 LOAD TEST RESULTS")
        print("=" * 60)

        print("
📈 OVERVIEW:"        print(f"Total Requests: {analysis['total_requests']}")
        print(f"Successful: {analysis['successful_requests']}")
        print(f"Failed: {analysis['failed_requests']}")
        print(".1f")
        print(".2f")
        print(".2f")

        print("
⏱️  RESPONSE TIME STATISTICS:"        rt_stats = analysis["response_time_stats"]
        print(".3f")
        print(".3f")
        print(".3f")
        print(".3f")
        print(".3f")
        print(".3f")

        print("
❌ ERROR ANALYSIS:"        errors = analysis["error_summary"]
        if errors["error_types"]:
            print("Error Types:")
            for error_type, count in errors["error_types"].items():
                print(f"  {error_type}: {count}")

        if errors["status_codes"]:
            print("HTTP Status Codes:")
            for status, count in errors["status_codes"].items():
                print(f"  {status}: {count}")

        if errors["sample_errors"]:
            print("Sample Errors:")
            for error in errors["sample_errors"]:
                print(f"  • {error}")

    async def run_performance_targets_test(self):
        """Test against SOAR performance targets"""
        print("🎯 Testing SOAR Performance Targets")
        print("=" * 50)

        targets = {
            "detection_time": {"target": 60, "description": "Detection < 1 minute"},
            "response_time": {"target": 300, "description": "Response < 5 minutes"},
            "success_rate": {"target": 95, "description": "Success rate > 95%"}
        }

        # Run a smaller test to check performance
        analysis = await self.run_load_test(num_requests=20, concurrency=5)

        print("
🎯 TARGET COMPLIANCE:"        for metric, config in targets.items():
            if metric == "success_rate":
                actual = analysis["success_rate"]
                target = config["target"]
                compliant = actual >= target
            elif metric in ["detection_time", "response_time"]:
                actual = analysis["response_time_stats"]["95th_percentile"] * 1000  # Convert to ms
                target = config["target"] * 1000  # Convert to ms
                compliant = actual <= target
            else:
                continue

            status = "✅ COMPLIANT" if compliant else "❌ NON-COMPLIANT"
            print(f"{config['description']}: {actual:.2f} vs {target:.2f} - {status}")

        return analysis


async def main():
    parser = argparse.ArgumentParser(description="SOAR Load Tester")
    parser.add_argument("--url", default="http://localhost:8000", help="SOAR API base URL")
    parser.add_argument("--requests", type=int, default=100, help="Number of requests to send")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrent requests")
    parser.add_argument("--targets", action="store_true", help="Test against performance targets")
    parser.add_argument("--output", help="Output file for results")

    args = parser.parse_args()

    async with LoadTester(args.url) as tester:
        if args.targets:
            analysis = await tester.run_performance_targets_test()
        else:
            analysis = await tester.run_load_test(args.requests, args.concurrency)

        tester.print_report(analysis)

        # Save results if requested
        if args.output:
            output_file = Path(args.output)
            with open(output_file, 'w') as f:
                json.dump({
                    "timestamp": datetime.now().isoformat(),
                    "test_config": {
                        "url": args.url,
                        "requests": args.requests,
                        "concurrency": args.concurrency,
                        "targets_test": args.targets
                    },
                    "results": analysis
                }, f, indent=2)

            print(f"\n💾 Results saved to: {output_file}")


if __name__ == "__main__":
    asyncio.run(main())
