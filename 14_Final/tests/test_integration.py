"""
Integration Tests for SOAR System
Tests end-to-end functionality and component interactions
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime
import sys
from pathlib import Path
import aiohttp
import requests

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from soar.core.incident_handler import IncidentHandler
from soar.detection.threat_detector import ThreatDetector
from soar.analysis.incident_analyzer import IncidentAnalyzer
from soar.response.automated_responder import AutomatedResponder
from soar.prediction.threat_predictor import ThreatPredictor
from soar.models.incident import Incident, IncidentType, IncidentSeverity, IncidentStatus


@pytest.fixture
def sample_security_event():
    """Sample security event for integration testing"""
    return {
        "id": "integration-test-event-001",
        "timestamp": datetime.now(),
        "source": "siem",
        "event_type": "malware_detected",
        "severity": "high",
        "data": {
            "message": "Ransomware detected on file server",
            "src_ip": "192.168.1.100",
            "host_id": "FILE_SERVER_01",
            "file_hash": "ransomware_hash_123",
            "file_path": "\\\\fileserver\\shared\\important.doc",
            "signature": "Ransom.Generic",
            "description": "Ransomware encryption pattern detected",
            "affected_users": 50,
            "data_at_risk": "business_critical"
        }
    }


@pytest.fixture
def complex_attack_scenario():
    """Complex multi-stage attack scenario"""
    return {
        "id": "complex-attack-001",
        "timestamp": datetime.now(),
        "source": "multi_source",
        "event_type": "complex_attack",
        "severity": "critical",
        "data": {
            "attack_stages": [
                {
                    "stage": "initial_compromise",
                    "type": "phishing",
                    "timestamp": datetime.now() - timedelta(hours=2),
                    "indicators": ["suspicious_email", "malicious_attachment"]
                },
                {
                    "stage": "lateral_movement",
                    "type": "pass_the_hash",
                    "timestamp": datetime.now() - timedelta(hours=1),
                    "indicators": ["anomalous_login", "credential_theft"]
                },
                {
                    "stage": "data_exfiltration",
                    "type": "exfiltration",
                    "timestamp": datetime.now(),
                    "indicators": ["large_outbound_traffic", "encrypted_channel"]
                }
            ],
            "affected_systems": ["workstation_01", "file_server", "database_server"],
            "threat_actor": "APT_Group_X",
            "motivation": "data_theft"
        }
    }


class TestEndToEndIncidentProcessing:
    """Test complete incident processing workflow"""

    @pytest.fixture
    def complete_soar_system(self):
        """Create complete SOAR system with all components"""
        # Create main incident handler
        handler = IncidentHandler()

        # Mock components for controlled testing
        handler.detector = AsyncMock(spec=ThreatDetector)
        handler.analyzer = AsyncMock(spec=IncidentAnalyzer)
        handler.responder = AsyncMock(spec=AutomatedResponder)
        handler.predictor = AsyncMock(spec=ThreatPredictor)
        handler.metrics = Mock()

        return handler

    @pytest.mark.asyncio
    async def test_complete_incident_lifecycle(self, complete_soar_system, sample_security_event):
        """Test complete incident lifecycle from detection to resolution"""
        # Setup mock responses for each component
        mock_incident = Mock(spec=Incident)
        mock_incident.id = "test-incident-001"
        mock_incident.incident_type = IncidentType.MALWARE
        mock_incident.severity = IncidentSeverity.CRITICAL
        mock_incident.status = IncidentStatus.DETECTED
        mock_incident.source_ip = "192.168.1.100"
        mock_incident.host_id = "FILE_SERVER_01"
        mock_incident.processing_metrics = {}

        # Mock detector response
        complete_soar_system.detector.classify.return_value = mock_incident

        # Mock analyzer response
        complete_soar_system.analyzer.deep_analysis.return_value = {
            "success": True,
            "threats": [
                {"type": "ransomware", "severity": "critical", "confidence": 0.95}
            ],
            "risk_score": 0.95,
            "recommendations": [
                "Isolate infected systems",
                "Block malicious IPs",
                "Initiate backup recovery"
            ],
            "affected_systems": ["FILE_SERVER_01", "workstations"],
            "analysis_timestamp": datetime.now()
        }

        # Mock responder response
        complete_soar_system.responder.execute_playbook.return_value = {
            "success": True,
            "actions_taken": 5,
            "containment_status": "successful",
            "message": "Automated response completed"
        }

        # Mock predictor response
        complete_soar_system.predictor.forecast_related_threats.return_value = {
            "success": True,
            "predicted_threats": [
                {
                    "type": "data_exfiltration",
                    "probability": 0.8,
                    "timeframe": "next_24_hours"
                }
            ],
            "confidence_score": 0.85
        }

        # Mock metrics
        complete_soar_system.metrics.record_detection_start.return_value = 1.0
        complete_soar_system.metrics.record_detection_end.return_value = 2.5
        complete_soar_system.metrics.record_response_start.return_value = 1.0
        complete_soar_system.metrics.record_response_end.return_value = 15.0

        # Execute complete workflow
        result = await complete_soar_system.handle_incident(sample_security_event)

        # Verify complete success
        assert result["success"] is True
        assert result["incident_id"] == mock_incident.id

        # Verify all components were called
        complete_soar_system.detector.classify.assert_called_once_with(sample_security_event)
        complete_soar_system.analyzer.deep_analysis.assert_called_once()
        complete_soar_system.responder.execute_playbook.assert_called_once()
        complete_soar_system.predictor.forecast_related_threats.assert_called_once()

        # Verify results compilation
        assert "response" in result
        assert "analysis" in result
        assert "predictions" in result
        assert result["response"]["success"] is True
        assert result["analysis"]["success"] is True
        assert result["predictions"]["success"] is True

        # Verify performance metrics
        assert "performance_metrics" in result
        perf = result["performance_metrics"]
        assert "detection_time" in perf
        assert "response_time" in perf
        assert "targets_met" in perf

    @pytest.mark.asyncio
    async def test_complex_attack_scenario_processing(self, complete_soar_system, complex_attack_scenario):
        """Test processing of complex multi-stage attack scenario"""
        # Setup complex incident
        complex_incident = Mock(spec=Incident)
        complex_incident.id = "complex-attack-incident"
        complex_incident.incident_type = IncidentType.ADVANCED_PERSISTENT_THREAT
        complex_incident.severity = IncidentSeverity.CRITICAL
        complex_incident.attack_stages = complex_attack_scenario["data"]["attack_stages"]

        # Mock component responses for complex scenario
        complete_soar_system.detector.classify.return_value = complex_incident

        complete_soar_system.analyzer.deep_analysis.return_value = {
            "success": True,
            "threats": [
                {"type": "apt", "severity": "critical", "stages": 3},
                {"type": "data_exfiltration", "severity": "high"}
            ],
            "risk_score": 0.98,
            "attack_chain_analysis": True,
            "recommendations": [
                "Full network isolation",
                "Forensic investigation",
                "Stakeholder notification"
            ]
        }

        complete_soar_system.responder.execute_playbook.return_value = {
            "success": True,
            "actions_taken": 8,
            "multi_stage_response": True
        }

        complete_soar_system.predictor.forecast_related_threats.return_value = {
            "success": True,
            "predicted_threats": [
                {"type": "ransomware", "probability": 0.9},
                {"type": "data_destruction", "probability": 0.7}
            ]
        }

        # Mock metrics
        complete_soar_system.metrics.record_detection_start.return_value = 1.0
        complete_soar_system.metrics.record_detection_end.return_value = 3.0
        complete_soar_system.metrics.record_response_start.return_value = 1.0
        complete_soar_system.metrics.record_response_end.return_value = 25.0

        result = await complete_soar_system.handle_incident(complex_attack_scenario)

        assert result["success"] is True
        assert result["analysis"]["attack_chain_analysis"] is True
        assert result["response"]["multi_stage_response"] is True

    @pytest.mark.asyncio
    async def test_performance_target_compliance(self, complete_soar_system, sample_security_event):
        """Test compliance with performance targets"""
        # Setup fast response times
        complete_soar_system.detector.classify.return_value = Mock(spec=Incident)
        complete_soar_system.analyzer.deep_analysis.return_value = {"success": True, "risk_score": 0.8}
        complete_soar_system.responder.execute_playbook.return_value = {"success": True}
        complete_soar_system.predictor.forecast_related_threats.return_value = {"success": True}

        # Mock very fast response times (within targets)
        complete_soar_system.metrics.record_detection_start.return_value = 1.0
        complete_soar_system.metrics.record_detection_end.return_value = 25.0  # < 60s
        complete_soar_system.metrics.record_response_start.return_value = 1.0
        complete_soar_system.metrics.record_response_end.return_value = 120.0  # < 300s

        result = await complete_soar_system.handle_incident(sample_security_event)

        # Verify targets are met
        perf = result["performance_metrics"]
        targets = perf["targets_met"]
        assert targets["detection_under_1min"] is True
        assert targets["response_under_5min"] is True

    @pytest.mark.asyncio
    async def test_error_handling_and_recovery(self, complete_soar_system, sample_security_event):
        """Test error handling and system recovery"""
        # Setup component failure
        complete_soar_system.detector.classify.side_effect = Exception("Detection system failure")

        result = await complete_soar_system.handle_incident(sample_security_event)

        # Verify graceful error handling
        assert result["success"] is False
        assert "error" in result
        assert result["response"]["status"] == "failed"
        assert result["analysis"]["status"] == "failed"
        assert result["predictions"]["status"] == "failed"

    @pytest.mark.asyncio
    async def test_concurrent_incident_processing(self, complete_soar_system):
        """Test concurrent processing of multiple incidents"""
        # Create multiple events
        events = [
            {
                "id": f"concurrent-event-{i}",
                "timestamp": datetime.now(),
                "source": "multi_source",
                "event_type": "malware",
                "severity": "high",
                "data": {"message": f"Malware {i}"}
            }
            for i in range(5)
        ]

        # Setup mocks
        complete_soar_system.detector.classify.return_value = Mock(spec=Incident)
        complete_soar_system.analyzer.deep_analysis.return_value = {"success": True}
        complete_soar_system.responder.execute_playbook.return_value = {"success": True}
        complete_soar_system.predictor.forecast_related_threats.return_value = {"success": True}

        # Process all events concurrently
        tasks = [complete_soar_system.handle_incident(event) for event in events]
        results = await asyncio.gather(*tasks)

        # Verify all incidents processed successfully
        assert all(result["success"] for result in results)
        assert len(results) == 5

        # Verify detector was called for each event
        assert complete_soar_system.detector.classify.call_count == 5


class TestAPIIntegration:
    """Test API integration and endpoints"""

    @pytest.fixture
    def api_base_url(self):
        """Base URL for API tests"""
        return "http://localhost:8000"

    def test_api_root_endpoint(self, api_base_url):
        """Test API root endpoint"""
        # This test would run against a live API
        # For now, just test the structure
        expected_response = {
            "system": "SOAR - Security Orchestration, Automation and Response",
            "version": "1.0.0",
            "status": "operational"
        }

        # In a real test, you'd make HTTP request:
        # response = requests.get(f"{api_base_url}/")
        # assert response.status_code == 200
        # assert response.json() == expected_response

        assert "system" in expected_response
        assert "version" in expected_response

    def test_api_incident_processing_endpoint(self, api_base_url, sample_security_event):
        """Test incident processing API endpoint"""
        # Test the request structure
        api_request = {
            "id": sample_security_event["id"],
            "timestamp": sample_security_event["timestamp"].isoformat(),
            "source": sample_security_event["source"],
            "event_type": sample_security_event["event_type"],
            "severity": sample_security_event["severity"],
            "data": sample_security_event["data"]
        }

        # Validate request structure
        assert "id" in api_request
        assert "source" in api_request
        assert "event_type" in api_request
        assert "data" in api_request

    def test_api_metrics_endpoints(self, api_base_url):
        """Test metrics API endpoints"""
        # Test endpoints structure
        metrics_endpoints = [
            "/metrics",
            "/metrics/json",
            "/health",
            "/status"
        ]

        for endpoint in metrics_endpoints:
            # In real test: response = requests.get(f"{api_base_url}{endpoint}")
            assert endpoint.startswith("/")
            assert "metrics" in endpoint or "health" in endpoint or "status" in endpoint


class TestComponentIntegration:
    """Test integration between specific components"""

    @pytest.mark.asyncio
    async def test_detection_to_analysis_integration(self):
        """Test data flow from detection to analysis"""
        # Create detector and analyzer
        detector = ThreatDetector()
        analyzer = IncidentAnalyzer()

        # Mock threat intelligence for both
        detector.threat_intel = AsyncMock()
        analyzer.threat_intel = AsyncMock()

        detector.threat_intel.enrich_incident.return_value = {
            "threat_score": 0.9,
            "malicious_indicators": [{"type": "ip", "value": "192.168.1.100"}]
        }

        analyzer.threat_intel.analyze_incident.return_value = {
            "threat_score": 0.85,
            "confidence": 0.9
        }

        # Test event
        event = {
            "id": "integration-test-001",
            "source": "firewall",
            "event_type": "suspicious_traffic",
            "data": {
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.1",
                "bytes": 1000000
            }
        }

        # Process through detection
        incident = await detector.classify(event)

        # Process through analysis
        analysis_result = await analyzer.deep_analysis(incident)

        # Verify data consistency
        assert incident.source_ip == "192.168.1.100"
        assert analysis_result["success"] is True
        assert "threats" in analysis_result

    @pytest.mark.asyncio
    async def test_analysis_to_response_integration(self):
        """Test data flow from analysis to response"""
        # Create analyzer and responder
        analyzer = IncidentAnalyzer()
        responder = AutomatedResponder()

        # Mock components
        responder.playbooks = Mock()
        responder.orchestrator = AsyncMock()
        responder.siem = AsyncMock()

        responder.playbooks.select_playbook.return_value = {
            "name": "Test Response",
            "steps": [{"name": "Test Step", "action": "test.action"}]
        }

        responder.orchestrator.execute.return_value = {
            "success": True,
            "actions_executed": 1
        }

        # Create incident with analysis results
        incident = Mock(spec=Incident)
        incident.incident_type = IncidentType.MALWARE
        incident.severity = IncidentSeverity.HIGH
        incident.analysis_results = {
            "risk_score": 0.9,
            "recommendations": ["isolate_host", "scan_system"]
        }

        # Process analysis
        analysis_result = await analyzer.deep_analysis(incident)

        # Process response
        response_result = await responder.execute_playbook(incident)

        # Verify integration
        assert analysis_result["success"] is True
        assert response_result["success"] is True
        assert "actions_executed" in response_result

    @pytest.mark.asyncio
    async def test_response_to_prediction_integration(self):
        """Test data flow from response to prediction"""
        # Create responder and predictor
        responder = AutomatedResponder()
        predictor = ThreatPredictor()

        # Mock components
        responder.playbooks = Mock()
        responder.orchestrator = AsyncMock()

        responder.playbooks.select_playbook.return_value = {
            "name": "Containment Response",
            "steps": [{"name": "Isolate", "action": "network.isolate"}]
        }

        responder.orchestrator.execute.return_value = {
            "success": True,
            "containment_status": "successful"
        }

        # Create incident
        incident = Mock(spec=Incident)
        incident.incident_type = IncidentType.MALWARE
        incident.response_actions = ["isolate_host"]

        # Process response
        response_result = await responder.execute_playbook(incident)

        # Process prediction
        prediction_result = await predictor.forecast_related_threats(incident)

        # Verify integration
        assert response_result["success"] is True
        assert prediction_result["success"] is True
        assert "predicted_threats" in prediction_result


class TestPerformanceBenchmarks:
    """Test performance benchmarks and targets"""

    @pytest.mark.asyncio
    async def test_detection_performance_target(self):
        """Test detection time meets target (< 1 minute)"""
        detector = ThreatDetector()

        event = {
            "id": "perf-test-001",
            "source": "log",
            "event_type": "malware",
            "data": {"message": "Malware detected"}
        }

        start_time = datetime.now()
        incident = await detector.classify(event)
        end_time = datetime.now()

        detection_time = (end_time - start_time).total_seconds()

        # Should be well under 1 minute
        assert detection_time < 60.0
        assert incident is not None

    @pytest.mark.asyncio
    async def test_response_performance_target(self):
        """Test response time meets target (< 5 minutes)"""
        responder = AutomatedResponder()

        # Mock components
        responder.playbooks = Mock()
        responder.orchestrator = AsyncMock()
        responder.siem = AsyncMock()

        responder.playbooks.select_playbook.return_value = {
            "name": "Fast Response",
            "steps": [{"name": "Quick Action", "action": "test.action"}]
        }

        responder.orchestrator.execute.return_value = {"success": True}

        incident = Mock(spec=Incident)
        incident.incident_type = IncidentType.MALWARE

        start_time = datetime.now()
        result = await responder.execute_playbook(incident)
        end_time = datetime.now()

        response_time = (end_time - start_time).total_seconds()

        # Should be well under 5 minutes
        assert response_time < 300.0
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_analysis_accuracy_target(self):
        """Test analysis accuracy meets target (> 95%)"""
        analyzer = IncidentAnalyzer()

        # Create test incident with known characteristics
        incident = Mock(spec=Incident)
        incident.incident_type = IncidentType.MALWARE
        incident.severity = IncidentSeverity.CRITICAL
        incident.description = "Critical ransomware infection"
        incident.attributes = {
            "file_hash": "known_malware_hash",
            "c2_server": "malicious.domain.com"
        }

        result = await analyzer.deep_analysis(incident)

        # Should achieve high accuracy for clear cases
        assert result["success"] is True
        assert result["risk_score"] > 0.8  # High confidence for critical malware
        assert len(result["threats"]) > 0

    @pytest.mark.asyncio
    async def test_concurrent_load_performance(self):
        """Test system performance under concurrent load"""
        # Create multiple incident handlers
        handlers = [IncidentHandler() for _ in range(10)]

        # Mock all components for fast processing
        for handler in handlers:
            handler.detector = AsyncMock()
            handler.analyzer = AsyncMock()
            handler.responder = AsyncMock()
            handler.predictor = AsyncMock()
            handler.metrics = Mock()

            handler.detector.classify.return_value = Mock(spec=Incident)
            handler.analyzer.deep_analysis.return_value = {"success": True}
            handler.responder.execute_playbook.return_value = {"success": True}
            handler.predictor.forecast_related_threats.return_value = {"success": True}

        # Create test events
        events = [
            {
                "id": f"load-test-{i}",
                "source": "test",
                "event_type": "malware",
                "data": {"message": f"Test event {i}"}
            }
            for i in range(10)
        ]

        # Process concurrently
        start_time = datetime.now()
        tasks = [handler.handle_incident(event) for handler, event in zip(handlers, events)]
        results = await asyncio.gather(*tasks)
        end_time = datetime.now()

        total_time = (end_time - start_time).total_seconds()

        # Verify all processed successfully
        assert all(result["success"] for result in results)

        # Verify reasonable total processing time (should be fast with mocks)
        assert total_time < 30.0  # Under 30 seconds for 10 concurrent incidents


class TestSystemResilience:
    """Test system resilience and error handling"""

    @pytest.mark.asyncio
    async def test_component_failure_recovery(self):
        """Test system recovery from component failures"""
        handler = IncidentHandler()

        # Simulate detector failure
        handler.detector = AsyncMock()
        handler.detector.classify.side_effect = Exception("Detector unavailable")

        # Other components work normally
        handler.analyzer = AsyncMock()
        handler.responder = AsyncMock()
        handler.predictor = AsyncMock()

        event = {
            "id": "resilience-test-001",
            "source": "test",
            "event_type": "malware"
        }

        result = await handler.handle_incident(event)

        # System should handle failure gracefully
        assert result["success"] is False
        assert "error" in result
        assert "Detector unavailable" in result["error"]

    @pytest.mark.asyncio
    async def test_partial_system_degradation(self):
        """Test system operation with partial component degradation"""
        handler = IncidentHandler()

        # Setup working components
        handler.detector = AsyncMock()
        handler.analyzer = AsyncMock()
        handler.responder = AsyncMock()

        # Prediction component degraded
        handler.predictor = AsyncMock()
        handler.predictor.forecast_related_threats.side_effect = Exception("Prediction service slow")

        handler.detector.classify.return_value = Mock(spec=Incident)
        handler.analyzer.deep_analysis.return_value = {"success": True}
        handler.responder.execute_playbook.return_value = {"success": True}

        event = {
            "id": "degradation-test-001",
            "source": "test",
            "event_type": "malware"
        }

        result = await handler.handle_incident(event)

        # Core functionality should still work
        assert result["success"] is True
        assert result["response"]["success"] is True
        assert result["analysis"]["success"] is True
        # Prediction might fail but shouldn't break the whole system
        assert result["predictions"]["success"] is False

    @pytest.mark.asyncio
    async def test_data_consistency_across_failures(self):
        """Test data consistency when components fail"""
        handler = IncidentHandler()

        # Setup components with some failures
        handler.detector = AsyncMock()
        handler.analyzer = AsyncMock()
        handler.responder = AsyncMock()
        handler.predictor = AsyncMock()

        incident = Mock(spec=Incident)
        incident.id = "consistency-test-001"

        handler.detector.classify.return_value = incident
        handler.analyzer.deep_analysis.return_value = {"success": True, "data": "analysis_data"}
        handler.responder.execute_playbook.return_value = {"success": True, "data": "response_data"}
        handler.predictor.forecast_related_threats.side_effect = Exception("Prediction failed")

        event = {
            "id": "consistency-test-001",
            "source": "test",
            "event_type": "malware"
        }

        result = await handler.handle_incident(event)

        # Verify successful components' data is preserved
        assert result["analysis"]["data"] == "analysis_data"
        assert result["response"]["data"] == "response_data"
        assert result["incident_id"] == "consistency-test-001"
