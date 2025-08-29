"""
Unit Tests for Core SOAR Components
Tests the main incident handling logic and core components
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from soar.core.incident_handler import IncidentHandler
from soar.models.incident import Incident, IncidentType, IncidentSeverity, IncidentStatus
from soar.detection.threat_detector import ThreatDetector
from soar.analysis.incident_analyzer import IncidentAnalyzer
from soar.response.automated_responder import AutomatedResponder
from soar.prediction.threat_predictor import ThreatPredictor


@pytest.fixture
def sample_event():
    """Sample security event for testing"""
    return {
        "id": "test-event-001",
        "timestamp": datetime.now(),
        "source": "log",
        "event_type": "malware",
        "severity": "high",
        "data": {
            "message": "Malware detected on host srv-01",
            "src_ip": "192.168.1.100",
            "host_id": "srv-01",
            "file_hash": "abc123",
            "description": "Suspicious file detected"
        }
    }


@pytest.fixture
def mock_incident():
    """Mock incident object for testing"""
    incident = Mock(spec=Incident)
    incident.id = "test-incident-001"
    incident.incident_type = IncidentType.MALWARE
    incident.severity = IncidentSeverity.HIGH
    incident.status = IncidentStatus.DETECTED
    incident.processing_metrics = {}
    incident.source_ip = "192.168.1.100"
    incident.host_id = "srv-01"
    incident.file_hash = "abc123"
    incident.description = "Malware detected"
    incident.title = "Malware Alert"
    incident.attributes = {
        "source_ip": "192.168.1.100",
        "host_id": "srv-01",
        "file_hash": "abc123"
    }
    return incident


class TestIncidentHandler:
    """Test IncidentHandler core functionality"""

    @pytest.fixture
    def incident_handler(self):
        """Create IncidentHandler instance with mocked components"""
        handler = IncidentHandler()

        # Mock all components
        handler.detector = AsyncMock(spec=ThreatDetector)
        handler.analyzer = AsyncMock(spec=IncidentAnalyzer)
        handler.responder = AsyncMock(spec=AutomatedResponder)
        handler.predictor = AsyncMock(spec=ThreatPredictor)
        handler.metrics = Mock()

        return handler

    @pytest.mark.asyncio
    async def test_initialization(self, incident_handler):
        """Test IncidentHandler initialization"""
        assert incident_handler.detector is not None
        assert incident_handler.analyzer is not None
        assert incident_handler.responder is not None
        assert incident_handler.predictor is not None
        assert incident_handler.metrics is not None
        assert not incident_handler.is_initialized

    @pytest.mark.asyncio
    async def test_handle_incident_success(self, incident_handler, sample_event, mock_incident):
        """Test successful incident handling"""
        # Setup mocks
        incident_handler.detector.classify.return_value = mock_incident
        incident_handler.responder.execute_playbook.return_value = {
            "success": True,
            "actions_taken": 3,
            "message": "Response executed successfully"
        }
        incident_handler.analyzer.deep_analysis.return_value = {
            "success": True,
            "threats": [{"type": "malware", "severity": "high"}],
            "risk_score": 0.8
        }
        incident_handler.predictor.forecast_related_threats.return_value = {
            "success": True,
            "predicted_threats": [{"type": "ransomware", "probability": 0.3}]
        }
        incident_handler.metrics.record_detection_start.return_value = 1.0
        incident_handler.metrics.record_detection_end.return_value = 2.5
        incident_handler.metrics.record_response_start.return_value = 1.0
        incident_handler.metrics.record_response_end.return_value = 15.0

        # Execute test
        result = await incident_handler.handle_incident(sample_event)

        # Verify results
        assert result["success"] is True
        assert result["incident_id"] == mock_incident.id
        assert "processing_time" in result
        assert "performance_metrics" in result
        assert result["response"]["success"] is True
        assert result["analysis"]["success"] is True
        assert result["predictions"]["success"] is True

        # Verify method calls
        incident_handler.detector.classify.assert_called_once_with(sample_event)
        incident_handler.responder.execute_playbook.assert_called_once()
        incident_handler.analyzer.deep_analysis.assert_called_once()
        incident_handler.predictor.forecast_related_threats.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_incident_failure(self, incident_handler, sample_event):
        """Test incident handling with component failures"""
        # Setup mocks to raise exceptions
        incident_handler.detector.classify.side_effect = Exception("Detection failed")

        # Execute test
        result = await incident_handler.handle_incident(sample_event)

        # Verify error handling
        assert result["success"] is False
        assert "error" in result
        assert result["response"]["status"] == "failed"
        assert result["analysis"]["status"] == "failed"
        assert result["predictions"]["status"] == "failed"

    @pytest.mark.asyncio
    async def test_compile_results(self, incident_handler):
        """Test results compilation"""
        response_result = {"success": True, "actions_taken": 2}
        analysis_result = {"success": True, "threats": ["malware"]}
        prediction_result = {"success": True, "predictions": ["ransomware"]}

        result = incident_handler.compile_results(
            response_result, analysis_result, prediction_result
        )

        assert result["response"] == response_result
        assert result["analysis"] == analysis_result
        assert result["predictions"] == prediction_result
        assert "compiled_at" in result
        assert "processing_summary" in result

    @pytest.mark.asyncio
    async def test_health_check_all_healthy(self, incident_handler):
        """Test health check when all components are healthy"""
        # Setup healthy mocks
        incident_handler.detector.health_check = AsyncMock(return_value={"operational": True})
        incident_handler.analyzer.health_check = AsyncMock(return_value={"operational": True})
        incident_handler.responder.health_check = AsyncMock(return_value={"operational": True})
        incident_handler.predictor.health_check = AsyncMock(return_value={"operational": True})

        result = await incident_handler.health_check()

        assert result["operational"] is True
        assert len(result["components"]) == 4
        assert all(comp["operational"] for comp in result["components"].values())

    @pytest.mark.asyncio
    async def test_health_check_partial_failure(self, incident_handler):
        """Test health check with some component failures"""
        # Setup mixed health status
        incident_handler.detector.health_check = AsyncMock(return_value={"operational": True})
        incident_handler.analyzer.health_check = AsyncMock(return_value={"operational": False})
        incident_handler.responder.health_check = AsyncMock(return_value={"operational": True})
        incident_handler.predictor.health_check = AsyncMock(return_value={"operational": False})

        result = await incident_handler.health_check()

        assert result["operational"] is False
        assert result["components"]["analyzer"]["operational"] is False
        assert result["components"]["predictor"]["operational"] is False


class TestPerformanceMetrics:
    """Test performance metrics tracking"""

    @pytest.mark.asyncio
    async def test_detection_time_tracking(self, incident_handler, sample_event, mock_incident):
        """Test detection time measurement"""
        incident_handler.detector.classify.return_value = mock_incident
        incident_handler.responder.execute_playbook.return_value = {"success": True}
        incident_handler.analyzer.deep_analysis.return_value = {"success": True}
        incident_handler.predictor.forecast_related_threats.return_value = {"success": True}

        # Mock metrics timing
        incident_handler.metrics.record_detection_start.return_value = 1.0
        incident_handler.metrics.record_detection_end.return_value = 2.5
        incident_handler.metrics.record_response_start.return_value = 1.0
        incident_handler.metrics.record_response_end.return_value = 15.0

        result = await incident_handler.handle_incident(sample_event)

        # Verify performance metrics are included
        assert "performance_metrics" in result
        perf_metrics = result["performance_metrics"]
        assert "detection_time" in perf_metrics
        assert "response_time" in perf_metrics
        assert "total_time" in perf_metrics
        assert "targets_met" in perf_metrics

        # Verify target compliance
        targets = perf_metrics["targets_met"]
        assert "detection_under_1min" in targets
        assert "response_under_5min" in targets
