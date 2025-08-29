"""
Unit Tests for Detection Components
Tests threat detection, classification, and anomaly detection
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from soar.detection.threat_detector import ThreatDetector
from soar.models.incident import Incident, IncidentType, IncidentSeverity, IncidentStatus
from soar.integrations.threat_intel_client import ThreatIntelligenceClient


@pytest.fixture
def sample_malware_event():
    """Sample malware detection event"""
    return {
        "id": "malware-event-001",
        "timestamp": datetime.now(),
        "source": "edr",
        "event_type": "malware_alert",
        "severity": "high",
        "data": {
            "message": "Trojan detected on workstation WS-001",
            "src_ip": "192.168.1.100",
            "host_id": "WS-001",
            "file_hash": "abc123def456",
            "file_path": "C:\\Users\\user\\Downloads\\malware.exe",
            "signature": "Trojan.Generic",
            "description": "Generic trojan signature detected"
        }
    }


@pytest.fixture
def sample_network_event():
    """Sample network attack event"""
    return {
        "id": "network-event-001",
        "timestamp": datetime.now(),
        "source": "firewall",
        "event_type": "network_attack",
        "severity": "medium",
        "data": {
            "message": "Port scan detected from external IP",
            "src_ip": "203.0.113.1",
            "dst_ip": "192.168.1.10",
            "dst_port": 22,
            "protocol": "tcp",
            "description": "TCP SYN scan pattern detected"
        }
    }


@pytest.fixture
def sample_brute_force_event():
    """Sample brute force attack event"""
    return {
        "id": "brute-force-event-001",
        "timestamp": datetime.now(),
        "source": "auth_log",
        "event_type": "brute_force",
        "severity": "high",
        "data": {
            "message": "Multiple failed login attempts",
            "src_ip": "192.168.1.50",
            "username": "admin",
            "failed_attempts": 25,
            "time_window": 300,
            "description": "Brute force attack pattern detected"
        }
    }


class TestThreatDetector:
    """Test ThreatDetector functionality"""

    @pytest.fixture
    def threat_detector(self):
        """Create ThreatDetector instance"""
        detector = ThreatDetector()
        return detector

    @pytest.mark.asyncio
    async def test_initialization(self, threat_detector):
        """Test ThreatDetector initialization"""
        assert threat_detector.detection_rules is not None
        assert IncidentType.MALWARE in threat_detector.detection_rules
        assert IncidentType.NETWORK_ATTACK in threat_detector.detection_rules
        assert threat_detector.threat_intel is not None

    @pytest.mark.asyncio
    async def test_classify_malware_event(self, threat_detector, sample_malware_event):
        """Test malware event classification"""
        incident = await threat_detector.classify(sample_malware_event)

        assert incident is not None
        assert incident.incident_type == IncidentType.MALWARE
        assert incident.severity in [IncidentSeverity.HIGH, IncidentSeverity.CRITICAL]
        assert incident.source_ip == "192.168.1.100"
        assert incident.host_id == "WS-001"
        assert incident.file_hash == "abc123def456"

    @pytest.mark.asyncio
    async def test_classify_network_event(self, threat_detector, sample_network_event):
        """Test network attack event classification"""
        incident = await threat_detector.classify(sample_network_event)

        assert incident is not None
        assert incident.incident_type == IncidentType.NETWORK_ATTACK
        assert incident.severity == IncidentSeverity.MEDIUM
        assert incident.source_ip == "203.0.113.1"
        assert incident.destination_ip == "192.168.1.10"

    @pytest.mark.asyncio
    async def test_classify_brute_force_event(self, threat_detector, sample_brute_force_event):
        """Test brute force event classification"""
        incident = await threat_detector.classify(sample_brute_force_event)

        assert incident is not None
        assert incident.incident_type == IncidentType.BRUTE_FORCE
        assert incident.severity == IncidentSeverity.HIGH
        assert incident.source_ip == "192.168.1.50"
        assert hasattr(incident, 'failed_attempts')

    @pytest.mark.asyncio
    async def test_threat_intelligence_enrichment(self, threat_detector, sample_malware_event):
        """Test threat intelligence enrichment"""
        # Mock threat intelligence client
        threat_detector.threat_intel = AsyncMock(spec=ThreatIntelligenceClient)
        threat_detector.threat_intel.enrich_incident.return_value = {
            "threat_score": 0.9,
            "malicious_indicators": [
                {"type": "ip", "value": "192.168.1.100", "confidence": 0.95}
            ],
            "threat_categories": ["malware", "trojan"],
            "external_lookups_performed": 3
        }

        incident = await threat_detector.classify(sample_malware_event)

        # Verify threat intelligence was called
        threat_detector.threat_intel.enrich_incident.assert_called_once()
        call_args = threat_detector.threat_intel.enrich_incident.call_args[0][0]

        assert call_args["source_ip"] == "192.168.1.100"
        assert call_args["file_hash"] == "abc123def456"
        assert call_args["description"] == "Trojan detected on workstation WS-001"

    @pytest.mark.asyncio
    async def test_anomaly_detection(self, threat_detector):
        """Test anomaly detection patterns"""
        # Test with anomalous network traffic
        anomaly_event = {
            "id": "anomaly-event-001",
            "timestamp": datetime.now(),
            "source": "network_monitor",
            "event_type": "network_anomaly",
            "severity": "medium",
            "data": {
                "message": "Unusual outbound traffic detected",
                "src_ip": "192.168.1.20",
                "bytes_sent": 50000000,  # 50MB in short time
                "time_window": 60,  # 1 minute
                "description": "Data exfiltration pattern detected"
            }
        }

        incident = await threat_detector.classify(anomaly_event)

        assert incident is not None
        assert incident.incident_type == IncidentType.DATA_EXFILTRATION
        assert incident.severity >= IncidentSeverity.MEDIUM

    @pytest.mark.asyncio
    async def test_custom_detection_rules(self, threat_detector):
        """Test custom detection rules application"""
        # Create custom rule event
        custom_event = {
            "id": "custom-event-001",
            "timestamp": datetime.now(),
            "source": "custom_sensor",
            "event_type": "custom_alert",
            "severity": "high",
            "data": {
                "message": "Custom detection rule triggered",
                "rule_id": "CUSTOM-001",
                "matched_pattern": "suspicious_behavior",
                "description": "Custom security rule violation"
            }
        }

        incident = await threat_detector.classify(custom_event)

        # Should still create an incident even for unknown event types
        assert incident is not None
        assert incident.incident_type == IncidentType.UNKNOWN
        assert incident.severity == IncidentSeverity.HIGH

    @pytest.mark.asyncio
    async def test_log_aggregation_patterns(self, threat_detector):
        """Test log aggregation and pattern recognition"""
        # Multiple related events
        events = [
            {
                "id": "log-001",
                "timestamp": datetime.now(),
                "source": "auth_log",
                "event_type": "failed_login",
                "data": {"username": "admin", "src_ip": "192.168.1.100"}
            },
            {
                "id": "log-002",
                "timestamp": datetime.now(),
                "source": "auth_log",
                "event_type": "failed_login",
                "data": {"username": "admin", "src_ip": "192.168.1.100"}
            },
            {
                "id": "log-003",
                "timestamp": datetime.now(),
                "source": "auth_log",
                "event_type": "failed_login",
                "data": {"username": "admin", "src_ip": "192.168.1.100"}
            }
        ]

        # Process each event
        incidents = []
        for event in events:
            incident = await threat_detector.classify(event)
            incidents.append(incident)

        # Should detect brute force pattern
        brute_force_incidents = [i for i in incidents if i.incident_type == IncidentType.BRUTE_FORCE]
        assert len(brute_force_incidents) > 0

    @pytest.mark.asyncio
    async def test_system_behavior_monitoring(self, threat_detector):
        """Test system behavior monitoring"""
        behavior_event = {
            "id": "behavior-event-001",
            "timestamp": datetime.now(),
            "source": "behavior_monitor",
            "event_type": "suspicious_behavior",
            "severity": "medium",
            "data": {
                "message": "Suspicious process behavior detected",
                "host_id": "SRV-001",
                "process_name": "svchost.exe",
                "anomalous_patterns": ["memory_usage_spike", "network_connections"],
                "description": "System process showing anomalous behavior"
            }
        }

        incident = await threat_detector.classify(behavior_event)

        assert incident is not None
        assert incident.incident_type == IncidentType.SUSPICIOUS_BEHAVIOR
        assert incident.host_id == "SRV-001"

    @pytest.mark.asyncio
    async def test_zero_day_detection(self, threat_detector):
        """Test zero-day attack detection"""
        zero_day_event = {
            "id": "zero-day-event-001",
            "timestamp": datetime.now(),
            "source": "anomaly_detector",
            "event_type": "zero_day",
            "severity": "critical",
            "data": {
                "message": "Unknown attack pattern detected",
                "anomaly_score": 0.95,
                "unusual_patterns": ["never_seen_before", "evasion_techniques"],
                "description": "Potential zero-day exploit detected"
            }
        }

        incident = await threat_detector.classify(zero_day_event)

        assert incident is not None
        assert incident.incident_type == IncidentType.ZERO_DAY
        assert incident.severity == IncidentSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_incident_severity_calculation(self, threat_detector):
        """Test incident severity calculation based on multiple factors"""
        # High severity malware with threat intel
        high_severity_event = {
            "id": "severity-test-001",
            "timestamp": datetime.now(),
            "source": "edr",
            "event_type": "malware_alert",
            "severity": "high",
            "data": {
                "message": "Critical system file modified",
                "src_ip": "192.168.1.100",
                "host_id": "DOMAIN_CONTROLLER",
                "file_path": "C:\\Windows\\System32\\lsass.exe",
                "description": "Critical system file modification"
            }
        }

        incident = await threat_detector.classify(high_severity_event)

        # Should be critical due to system criticality
        assert incident.severity == IncidentSeverity.CRITICAL
        assert "DOMAIN_CONTROLLER" in incident.description.upper()

    @pytest.mark.asyncio
    async def test_evidence_collection(self, threat_detector, sample_malware_event):
        """Test evidence collection during classification"""
        incident = await threat_detector.classify(sample_malware_event)

        # Verify evidence is collected
        assert hasattr(incident, 'evidence')
        assert 'original_event' in incident.evidence
        assert 'classification_timestamp' in incident.evidence
        assert 'detection_rules_applied' in incident.evidence

        # Verify original event is preserved
        original_event = incident.evidence['original_event']
        assert original_event['id'] == sample_malware_event['id']
        assert original_event['source'] == sample_malware_event['source']
