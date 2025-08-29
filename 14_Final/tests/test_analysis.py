"""
Unit Tests for Analysis Components
Tests incident analysis, risk assessment, and behavioral analysis
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from soar.analysis.incident_analyzer import IncidentAnalyzer, AnalysisResult
from soar.models.incident import Incident, IncidentType, IncidentSeverity, IncidentStatus
from soar.integrations.threat_intel_client import ThreatIntelligenceClient


@pytest.fixture
def sample_incident():
    """Sample incident for analysis testing"""
    incident = Mock(spec=Incident)
    incident.id = "test-incident-001"
    incident.incident_type = IncidentType.MALWARE
    incident.severity = IncidentSeverity.HIGH
    incident.status = IncidentStatus.DETECTED
    incident.source_ip = "192.168.1.100"
    incident.host_id = "WS-001"
    incident.file_hash = "abc123def456"
    incident.description = "Malware detected on workstation"
    incident.title = "Malware Alert"
    incident.attributes = {
        "source_ip": "192.168.1.100",
        "host_id": "WS-001",
        "file_hash": "abc123def456",
        "file_path": "C:\\malware.exe"
    }
    incident.threat_intel_data = {
        "threat_score": 0.9,
        "malicious_indicators": [
            {"type": "hash", "value": "abc123def456", "confidence": 0.95}
        ]
    }
    return incident


@pytest.fixture
def network_incident():
    """Sample network incident for analysis"""
    incident = Mock(spec=Incident)
    incident.id = "network-incident-001"
    incident.incident_type = IncidentType.NETWORK_ATTACK
    incident.severity = IncidentSeverity.MEDIUM
    incident.source_ip = "203.0.113.1"
    incident.destination_ip = "192.168.1.10"
    incident.destination_port = 22
    incident.protocol = "tcp"
    incident.description = "Port scan detected"
    incident.attributes = {
        "source_ip": "203.0.113.1",
        "destination_ip": "192.168.1.10",
        "destination_port": 22,
        "protocol": "tcp",
        "scan_type": "syn_scan"
    }
    return incident


class TestIncidentAnalyzer:
    """Test IncidentAnalyzer functionality"""

    @pytest.fixture
    def incident_analyzer(self):
        """Create IncidentAnalyzer instance"""
        analyzer = IncidentAnalyzer()
        return analyzer

    @pytest.mark.asyncio
    async def test_initialization(self, incident_analyzer):
        """Test IncidentAnalyzer initialization"""
        assert incident_analyzer.threat_patterns is not None
        assert "malware" in incident_analyzer.threat_patterns
        assert "network" in incident_analyzer.threat_patterns
        assert "data" in incident_analyzer.threat_patterns
        assert incident_analyzer.threat_intel is not None

    @pytest.mark.asyncio
    async def test_deep_analysis_malware(self, incident_analyzer, sample_incident):
        """Test deep analysis of malware incident"""
        result = await incident_analyzer.deep_analysis(sample_incident)

        assert result["success"] is True
        assert "threats" in result
        assert "risk_score" in result
        assert "recommendations" in result
        assert "affected_systems" in result
        assert "analysis_timestamp" in result

        # Verify malware-specific analysis
        threats = result["threats"]
        assert len(threats) > 0
        malware_threats = [t for t in threats if t.get("type") == "malware"]
        assert len(malware_threats) > 0

        # Verify risk score is reasonable
        assert 0.0 <= result["risk_score"] <= 1.0
        assert result["risk_score"] > 0.5  # Should be high for malware

    @pytest.mark.asyncio
    async def test_deep_analysis_network_attack(self, incident_analyzer, network_incident):
        """Test deep analysis of network attack incident"""
        result = await incident_analyzer.deep_analysis(network_incident)

        assert result["success"] is True
        assert "threats" in result
        assert "risk_score" in result

        # Verify network-specific analysis
        threats = result["threats"]
        network_threats = [t for t in threats if t.get("category") == "network"]
        assert len(network_threats) > 0

        # Verify affected systems include destination
        affected_systems = result["affected_systems"]
        assert "192.168.1.10" in affected_systems

    @pytest.mark.asyncio
    async def test_risk_assessment_calculation(self, incident_analyzer, sample_incident):
        """Test risk assessment calculation"""
        result = await incident_analyzer.deep_analysis(sample_incident)

        risk_score = result["risk_score"]

        # Risk should be influenced by:
        # - Incident severity
        # - Threat intelligence data
        # - System criticality
        # - Attack vector

        assert 0.0 <= risk_score <= 1.0

        # High severity malware should have high risk
        if sample_incident.severity == IncidentSeverity.HIGH:
            assert risk_score > 0.6

    @pytest.mark.asyncio
    async def test_threat_intelligence_integration(self, incident_analyzer, sample_incident):
        """Test threat intelligence integration in analysis"""
        # Mock threat intelligence client
        incident_analyzer.threat_intel = AsyncMock(spec=ThreatIntelligenceClient)
        incident_analyzer.threat_intel.analyze_incident.return_value = {
            "threat_score": 0.95,
            "confidence": 0.9,
            "related_threats": ["trojan", "backdoor"],
            "attack_vector": "phishing_email",
            "mitigation_steps": ["isolate_host", "remove_malware", "patch_system"]
        }

        result = await incident_analyzer.deep_analysis(sample_incident)

        # Verify threat intelligence was called
        incident_analyzer.threat_intel.analyze_incident.assert_called_once()

        # Verify threat intel data is incorporated
        assert result["risk_score"] >= 0.8  # Should be high due to threat intel

    @pytest.mark.asyncio
    async def test_behavioral_analysis(self, incident_analyzer):
        """Test behavioral analysis patterns"""
        # Create incident with behavioral data
        behavioral_incident = Mock(spec=Incident)
        behavioral_incident.id = "behavior-incident-001"
        behavioral_incident.incident_type = IncidentType.SUSPICIOUS_BEHAVIOR
        behavioral_incident.severity = IncidentSeverity.MEDIUM
        behavioral_incident.description = "Anomalous process behavior"
        behavioral_incident.attributes = {
            "host_id": "SRV-001",
            "process_name": "svchost.exe",
            "anomalous_patterns": ["memory_usage_spike", "network_connections"],
            "baseline_deviation": 0.8
        }

        result = await incident_analyzer.deep_analysis(behavioral_incident)

        assert result["success"] is True
        # Behavioral analysis should identify unusual patterns
        assert len(result["threats"]) > 0
        assert result["risk_score"] > 0.3  # Moderate risk for behavioral anomaly

    @pytest.mark.asyncio
    async def test_pattern_recognition(self, incident_analyzer):
        """Test pattern recognition across incidents"""
        # Create multiple related incidents
        incidents = []
        for i in range(3):
            incident = Mock(spec=Incident)
            incident.id = f"pattern-incident-{i}"
            incident.incident_type = IncidentType.BRUTE_FORCE
            incident.source_ip = "192.168.1.100"
            incident.severity = IncidentSeverity.HIGH
            incident.description = f"Failed login attempt {i}"
            incident.attributes = {
                "username": "admin",
                "source_ip": "192.168.1.100",
                "failed_attempts": 10 + i
            }
            incidents.append(incident)

        # Analyze each incident
        results = []
        for incident in incidents:
            result = await incident_analyzer.deep_analysis(incident)
            results.append(result)

        # Pattern recognition should identify the brute force campaign
        pattern_detected = any(
            "brute_force" in str(result.get("threats", []))
            for result in results
        )
        assert pattern_detected

    @pytest.mark.asyncio
    async def test_impact_assessment(self, incident_analyzer):
        """Test impact assessment for different scenarios"""
        # High impact scenario
        critical_incident = Mock(spec=Incident)
        critical_incident.id = "critical-incident-001"
        critical_incident.incident_type = IncidentType.MALWARE
        critical_incident.severity = IncidentSeverity.CRITICAL
        critical_incident.host_id = "DOMAIN_CONTROLLER"
        critical_incident.description = "Ransomware on domain controller"
        critical_incident.attributes = {
            "host_id": "DOMAIN_CONTROLLER",
            "affected_users": 1000,
            "data_at_risk": "critical_business_data"
        }

        result = await incident_analyzer.deep_analysis(critical_incident)

        # Should have high impact assessment
        assert result["risk_score"] > 0.9
        assert "DOMAIN_CONTROLLER" in str(result["affected_systems"])

        # Recommendations should include critical response actions
        recommendations = result["recommendations"]
        critical_actions = ["isolate", "backup", "notify_executive"]
        assert any(action in str(recommendations).lower() for action in critical_actions)

    @pytest.mark.asyncio
    async def test_recovery_optimization(self, incident_analyzer):
        """Test recovery optimization recommendations"""
        # Incident with recovery considerations
        recovery_incident = Mock(spec=Incident)
        recovery_incident.id = "recovery-incident-001"
        recovery_incident.incident_type = IncidentType.DATA_BREACH
        recovery_incident.severity = IncidentSeverity.HIGH
        recovery_incident.description = "Customer data breach"
        recovery_incident.attributes = {
            "breach_type": "sql_injection",
            "records_affected": 50000,
            "data_types": ["personal_info", "financial_data"],
            "time_to_detection": 7200  # 2 hours
        }

        result = await incident_analyzer.deep_analysis(recovery_incident)

        # Should include recovery optimization
        recommendations = result["recommendations"]
        recovery_terms = ["recovery", "restore", "backup", "notification"]
        assert any(term in str(recommendations).lower() for term in recovery_terms)

    @pytest.mark.asyncio
    async def test_machine_learning_model_integration(self, incident_analyzer, sample_incident):
        """Test machine learning model integration"""
        # Mock ML model predictions
        with patch('soar.analysis.incident_analyzer.MLModel') as mock_ml:
            mock_ml_instance = Mock()
            mock_ml_instance.predict_risk.return_value = 0.85
            mock_ml_instance.predict_impact.return_value = "high"
            mock_ml_instance.predict_duration.return_value = 3600
            mock_ml.return_value = mock_ml_instance

            result = await incident_analyzer.deep_analysis(sample_incident)

            # Verify ML model was used
            mock_ml_instance.predict_risk.assert_called_once()
            mock_ml_instance.predict_impact.assert_called_once()

            # Verify ML predictions are incorporated
            assert result["risk_score"] >= 0.8

    @pytest.mark.asyncio
    async def test_evidence_correlation(self, incident_analyzer):
        """Test evidence correlation across multiple sources"""
        # Incident with multiple evidence sources
        correlated_incident = Mock(spec=Incident)
        correlated_incident.id = "correlation-incident-001"
        correlated_incident.incident_type = IncidentType.MULTI_VECTOR_ATTACK
        correlated_incident.severity = IncidentSeverity.CRITICAL
        correlated_incident.description = "Coordinated attack campaign"
        correlated_incident.attributes = {
            "attack_vectors": ["phishing", "malware", "lateral_movement"],
            "evidence_sources": ["email_logs", "edr_alerts", "network_traffic"],
            "timeline": [
                {"time": "2024-01-01T10:00:00Z", "event": "phishing_email"},
                {"time": "2024-01-01T10:30:00Z", "event": "malware_execution"},
                {"time": "2024-01-01T11:00:00Z", "event": "lateral_movement"}
            ]
        }

        result = await incident_analyzer.deep_analysis(correlated_incident)

        # Should identify attack campaign pattern
        assert len(result["threats"]) > 1
        assert result["risk_score"] > 0.8

        # Should include correlation analysis
        assert "attack_campaign" in str(result.get("analysis_type", ""))

    @pytest.mark.asyncio
    async def test_compliance_impact_analysis(self, incident_analyzer):
        """Test compliance impact analysis"""
        # Incident affecting compliance
        compliance_incident = Mock(spec=Incident)
        compliance_incident.id = "compliance-incident-001"
        compliance_incident.incident_type = IncidentType.DATA_BREACH
        compliance_incident.severity = IncidentSeverity.HIGH
        compliance_incident.description = "PII data breach"
        compliance_incident.attributes = {
            "data_types": ["personal_identifiable_information", "health_data"],
            "affected_records": 100000,
            "regulations": ["GDPR", "HIPAA"],
            "jurisdictions": ["EU", "US"]
        }

        result = await incident_analyzer.deep_analysis(compliance_incident)

        # Should include compliance considerations
        recommendations = result["recommendations"]
        compliance_terms = ["gdpr", "hipaa", "notification", "breach_disclosure"]
        assert any(term in str(recommendations).lower() for term in compliance_terms)

    @pytest.mark.asyncio
    async def test_analysis_result_format(self, incident_analyzer, sample_incident):
        """Test analysis result format and completeness"""
        result = await incident_analyzer.deep_analysis(sample_incident)

        # Required fields
        required_fields = [
            "success", "threats", "risk_score", "recommendations",
            "affected_systems", "analysis_timestamp", "confidence_level"
        ]

        for field in required_fields:
            assert field in result

        # Validate data types
        assert isinstance(result["success"], bool)
        assert isinstance(result["threats"], list)
        assert isinstance(result["risk_score"], (int, float))
        assert isinstance(result["recommendations"], list)
        assert isinstance(result["affected_systems"], list)

        # Validate ranges
        assert 0.0 <= result["risk_score"] <= 1.0
        assert 0.0 <= result["confidence_level"] <= 1.0
