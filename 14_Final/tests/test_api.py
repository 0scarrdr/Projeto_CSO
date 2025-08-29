"""
API Tests for SOAR REST API
Tests all API endpoints and integration
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime
import sys
from pathlib import Path
import json
from fastapi.testclient import TestClient
from fastapi import FastAPI

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from soar.api.app import app
from soar.core.incident_handler import IncidentHandler
from soar.models.incident import Incident, IncidentType, IncidentSeverity


@pytest.fixture
def client():
    """Test client for FastAPI application"""
    return TestClient(app)


@pytest.fixture
def sample_event_data():
    """Sample event data for API testing"""
    return {
        "id": "api-test-event-001",
        "timestamp": datetime.now(),
        "source": "api_test",
        "event_type": "malware_detected",
        "severity": "high",
        "data": {
            "message": "API test malware detection",
            "src_ip": "192.168.1.100",
            "host_id": "TEST_HOST",
            "file_hash": "api_test_hash",
            "description": "Test malware event"
        }
    }


@pytest.fixture
def mock_incident_handler():
    """Mock incident handler for API testing"""
    handler = AsyncMock(spec=IncidentHandler)

    # Setup mock responses
    mock_incident = Mock(spec=Incident)
    mock_incident.id = "api-test-incident-001"
    mock_incident.incident_type = IncidentType.MALWARE
    mock_incident.severity = IncidentSeverity.HIGH

    handler.handle_incident.return_value = {
        "success": True,
        "incident_id": "api-test-incident-001",
        "processing_time": 2.5,
        "response": {"success": True, "actions_taken": 3},
        "analysis": {"success": True, "risk_score": 0.8},
        "predictions": {"success": True, "predicted_threats": []}
    }

    handler.health_check.return_value = {
        "operational": True,
        "components": {
            "detector": {"operational": True},
            "analyzer": {"operational": True},
            "responder": {"operational": True},
            "predictor": {"operational": True}
        }
    }

    handler.get_system_status.return_value = {
        "health": {"operational": True},
        "metrics": {"total_incidents": 42},
        "active_incidents": 2
    }

    return handler


class TestRootEndpoints:
    """Test root and basic API endpoints"""

    def test_root_endpoint(self, client):
        """Test root endpoint returns correct information"""
        response = client.get("/")

        assert response.status_code == 200
        data = response.json()

        assert "system" in data
        assert "SOAR" in data["system"]
        assert "version" in data
        assert "status" in data
        assert "endpoints" in data

    def test_health_endpoint(self, client, mock_incident_handler):
        """Test health check endpoint"""
        with patch('soar.api.app.incident_handler', mock_incident_handler):
            response = client.get("/health")

            assert response.status_code == 200
            data = response.json()

            assert "operational" in data
            assert "components" in data
            assert data["operational"] is True

    def test_status_endpoint(self, client, mock_incident_handler):
        """Test system status endpoint"""
        with patch('soar.api.app.incident_handler', mock_incident_handler):
            response = client.get("/status")

            assert response.status_code == 200
            data = response.json()

            assert "health" in data
            assert "metrics" in data
            assert "active_incidents" in data


class TestIncidentProcessing:
    """Test incident processing endpoints"""

    def test_process_incident_success(self, client, sample_event_data, mock_incident_handler):
        """Test successful incident processing"""
        with patch('soar.api.app.incident_handler', mock_incident_handler):
            response = client.post("/incidents", json=sample_event_data)

            assert response.status_code == 200
            data = response.json()

            assert data["success"] is True
            assert "incident_id" in data
            assert "processing_time" in data
            assert "response" in data
            assert "analysis" in data
            assert "predictions" in data

    def test_process_incident_invalid_data(self, client):
        """Test incident processing with invalid data"""
        invalid_event = {
            "id": "invalid-event",
            # Missing required fields
        }

        response = client.post("/incidents", json=invalid_event)

        # Should return validation error
        assert response.status_code == 422

    def test_process_incident_missing_fields(self, client):
        """Test incident processing with missing required fields"""
        incomplete_event = {
            "id": "incomplete-event",
            "timestamp": datetime.now().isoformat(),
            # Missing source, event_type, severity, data
        }

        response = client.post("/incidents", json=incomplete_event)

        assert response.status_code == 422
        error_data = response.json()
        assert "detail" in error_data

    def test_process_incident_with_timestamp(self, client, sample_event_data, mock_incident_handler):
        """Test incident processing with explicit timestamp"""
        event_with_timestamp = sample_event_data.copy()
        event_with_timestamp["timestamp"] = datetime.now().isoformat()

        with patch('soar.api.app.incident_handler', mock_incident_handler):
            response = client.post("/incidents", json=event_with_timestamp)

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True

    @pytest.mark.asyncio
    async def test_concurrent_incident_processing(self, client, mock_incident_handler):
        """Test concurrent incident processing"""
        # Create multiple events
        events = [
            {
                "id": f"concurrent-event-{i}",
                "timestamp": datetime.now().isoformat(),
                "source": "api_test",
                "event_type": "malware",
                "severity": "high",
                "data": {"message": f"Concurrent test {i}"}
            }
            for i in range(5)
        ]

        with patch('soar.api.app.incident_handler', mock_incident_handler):
            # Process concurrently using asyncio
            import aiohttp
            import asyncio

            async def post_event(session, event):
                async with session.post(
                    "http://testserver/incidents",
                    json=event
                ) as response:
                    return await response.json()

            async with aiohttp.ClientSession() as session:
                tasks = [post_event(session, event) for event in events]
                results = await asyncio.gather(*tasks)

            # Verify all requests succeeded
            assert all(result["success"] for result in results)
            assert len(results) == 5


class TestMetricsEndpoints:
    """Test metrics and monitoring endpoints"""

    def test_metrics_endpoint(self, client):
        """Test Prometheus metrics endpoint"""
        response = client.get("/metrics")

        assert response.status_code == 200
        # Should return Prometheus format metrics
        content = response.text
        assert "soar_" in content or "# HELP" in content

    def test_metrics_json_endpoint(self, client, mock_incident_handler):
        """Test JSON metrics endpoint"""
        with patch('soar.api.app.incident_handler', mock_incident_handler):
            response = client.get("/metrics/json")

            assert response.status_code == 200
            data = response.json()

            # Should contain metrics data
            assert isinstance(data, dict)

    def test_kpis_endpoint(self, client):
        """Test KPIs endpoint"""
        response = client.get("/kpis")

        assert response.status_code == 200
        data = response.json()

        # Should contain KPI data
        assert isinstance(data, dict)

    def test_system_status_detailed(self, client, mock_incident_handler):
        """Test detailed system status"""
        with patch('soar.api.app.incident_handler', mock_incident_handler):
            response = client.get("/status")

            assert response.status_code == 200
            data = response.json()

            assert "health" in data
            assert "metrics" in data
            assert "active_incidents" in data
            assert data["health"]["operational"] is True


class TestErrorHandling:
    """Test API error handling"""

    def test_incident_processing_failure(self, client):
        """Test incident processing when handler fails"""
        failing_handler = AsyncMock(spec=IncidentHandler)
        failing_handler.handle_incident.side_effect = Exception("Processing failed")

        event = {
            "id": "failure-test",
            "source": "test",
            "event_type": "malware",
            "severity": "high",
            "data": {"message": "Test failure"}
        }

        with patch('soar.api.app.incident_handler', failing_handler):
            response = client.post("/incidents", json=event)

            assert response.status_code == 500
            data = response.json()
            assert "detail" in data

    def test_health_check_failure(self, client):
        """Test health check when system is down"""
        failing_handler = AsyncMock(spec=IncidentHandler)
        failing_handler.health_check.side_effect = Exception("Health check failed")

        with patch('soar.api.app.incident_handler', failing_handler):
            response = client.get("/health")

            assert response.status_code == 503
            data = response.json()
            assert "detail" in data

    def test_invalid_json_payload(self, client):
        """Test handling of invalid JSON payload"""
        response = client.post(
            "/incidents",
            data="invalid json {",
            headers={"Content-Type": "application/json"}
        )

        assert response.status_code == 400

    def test_unsupported_content_type(self, client):
        """Test handling of unsupported content type"""
        response = client.post(
            "/incidents",
            data="some data",
            headers={"Content-Type": "text/plain"}
        )

        assert response.status_code == 415


class TestCORSHeaders:
    """Test CORS headers for API"""

    def test_cors_headers(self, client):
        """Test CORS headers are present"""
        response = client.options("/incidents")

        assert "access-control-allow-origin" in response.headers
        assert "access-control-allow-methods" in response.headers
        assert "access-control-allow-headers" in response.headers

    def test_cors_preflight(self, client):
        """Test CORS preflight request"""
        response = client.options(
            "/incidents",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type"
            }
        )

        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == "*"


class TestRequestValidation:
    """Test request validation"""

    def test_event_data_validation(self, client):
        """Test event data validation"""
        # Test with valid data
        valid_event = {
            "id": "valid-event",
            "source": "test",
            "event_type": "malware",
            "severity": "high",
            "data": {"message": "test"}
        }

        response = client.post("/incidents", json=valid_event)
        assert response.status_code == 200

    def test_severity_validation(self, client):
        """Test severity field validation"""
        invalid_severity_event = {
            "id": "invalid-severity",
            "source": "test",
            "event_type": "malware",
            "severity": "invalid_severity",  # Invalid severity
            "data": {"message": "test"}
        }

        response = client.post("/incidents", json=invalid_severity_event)
        assert response.status_code == 422

    def test_required_fields_validation(self, client):
        """Test required fields validation"""
        missing_source = {
            "id": "missing-source",
            "event_type": "malware",
            "severity": "high",
            "data": {"message": "test"}
            # Missing source field
        }

        response = client.post("/incidents", json=missing_source)
        assert response.status_code == 422

    def test_data_field_validation(self, client):
        """Test data field validation"""
        empty_data_event = {
            "id": "empty-data",
            "source": "test",
            "event_type": "malware",
            "severity": "high",
            "data": {}  # Empty data
        }

        response = client.post("/incidents", json=empty_data_event)
        assert response.status_code == 200  # Should still work with empty data


class TestPerformanceUnderLoad:
    """Test API performance under load"""

    @pytest.mark.asyncio
    async def test_high_concurrency_load(self, client, mock_incident_handler):
        """Test API under high concurrency"""
        # Create many concurrent requests
        import asyncio
        import aiohttp

        event_template = {
            "id": "load-test-{i}",
            "source": "load_test",
            "event_type": "malware",
            "severity": "high",
            "data": {"message": "Load test event {i}"}
        }

        async def make_request(session, i):
            event = event_template.copy()
            event["id"] = f"load-test-{i}"
            event["data"]["message"] = f"Load test event {i}"

            async with session.post(
                "http://testserver/incidents",
                json=event
            ) as response:
                return response.status

        with patch('soar.api.app.incident_handler', mock_incident_handler):
            async with aiohttp.ClientSession() as session:
                # Make 50 concurrent requests
                tasks = [make_request(session, i) for i in range(50)]
                start_time = datetime.now()
                results = await asyncio.gather(*tasks)
                end_time = datetime.now()

                # Verify all requests succeeded
                assert all(status == 200 for status in results)

                # Verify reasonable response time
                total_time = (end_time - start_time).total_seconds()
                avg_time = total_time / 50
                assert avg_time < 1.0  # Less than 1 second per request

    def test_memory_usage_under_load(self, client, mock_incident_handler):
        """Test memory usage under sustained load"""
        # This would typically use memory profiling tools
        # For now, just ensure the system can handle multiple requests

        with patch('soar.api.app.incident_handler', mock_incident_handler):
            for i in range(100):
                event = {
                    "id": f"memory-test-{i}",
                    "source": "memory_test",
                    "event_type": "malware",
                    "severity": "high",
                    "data": {"message": f"Memory test {i}"}
                }

                response = client.post("/incidents", json=event)
                assert response.status_code == 200

    def test_response_time_distribution(self, client, mock_incident_handler):
        """Test response time distribution"""
        import time

        response_times = []

        with patch('soar.api.app.incident_handler', mock_incident_handler):
            for i in range(20):
                event = {
                    "id": f"timing-test-{i}",
                    "source": "timing_test",
                    "event_type": "malware",
                    "severity": "high",
                    "data": {"message": f"Timing test {i}"}
                }

                start_time = time.time()
                response = client.post("/incidents", json=event)
                end_time = time.time()

                assert response.status_code == 200
                response_times.append(end_time - start_time)

            # Calculate statistics
            avg_time = sum(response_times) / len(response_times)
            max_time = max(response_times)
            min_time = min(response_times)

            # Verify reasonable performance
            assert avg_time < 0.5  # Average under 0.5 seconds
            assert max_time < 2.0  # Max under 2 seconds
            assert min_time > 0.0   # Min greater than 0


class TestAPIDocumentation:
    """Test API documentation endpoints"""

    def test_openapi_schema(self, client):
        """Test OpenAPI schema generation"""
        response = client.get("/openapi.json")

        assert response.status_code == 200
        schema = response.json()

        assert "openapi" in schema
        assert "info" in schema
        assert "paths" in schema
        assert "/incidents" in schema["paths"]
        assert "/health" in schema["paths"]

    def test_docs_endpoint(self, client):
        """Test Swagger UI documentation"""
        response = client.get("/docs")

        assert response.status_code == 200
        # Should return HTML content
        assert "swagger" in response.text.lower()

    def test_redoc_endpoint(self, client):
        """Test ReDoc documentation"""
        response = client.get("/redoc")

        assert response.status_code == 200
        # Should return HTML content
        assert "redoc" in response.text.lower()
