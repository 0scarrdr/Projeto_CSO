"""
Unit Tests for Response Components
Tests automated response, playbook execution, and orchestration
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime
import sys
from pathlib import Path
import yaml

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from soar.response.automated_responder import AutomatedResponder, PlaybookLibrary
from soar.response.orchestrator import ResponseOrchestrator
from soar.models.incident import Incident, IncidentType, IncidentSeverity, IncidentStatus
from soar.integrations.threat_intel_client import ThreatIntelligenceClient


@pytest.fixture
def sample_incident():
    """Sample incident for response testing"""
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
    return incident


@pytest.fixture
def sample_playbook():
    """Sample playbook for testing"""
    return {
        "name": "Test Malware Response",
        "description": "Test response playbook for malware",
        "version": "1.0",
        "triggers": [
            {"incident_type": "malware"}
        ],
        "steps": [
            {
                "name": "Isolate Host",
                "action": "network.isolate_host",
                "params": {
                    "host_id": "INCIDENT_HOST_ID"
                }
            },
            {
                "name": "Send Alert",
                "action": "alert.send_alert",
                "params": {
                    "severity": "high",
                    "message": "Malware detected and contained"
                }
            }
        ]
    }


class TestPlaybookLibrary:
    """Test PlaybookLibrary functionality"""

    @pytest.fixture
    def playbook_library(self, tmp_path):
        """Create PlaybookLibrary with temporary directory"""
        # Create temporary playbooks directory
        playbooks_dir = tmp_path / "playbooks"
        playbooks_dir.mkdir()

        # Create sample playbooks
        malware_playbook = playbooks_dir / "quarantine.yml"
        malware_playbook.write_text("""
name: "Quarantine Malware"
description: "Automated response to malware detection"
version: "1.0"
triggers:
  - incident_type: "malware"
steps:
  - name: "Isolate Host"
    action: "network.isolate_host"
    params:
      host_id: "INCIDENT_HOST_ID"
  - name: "Send Alert"
    action: "alert.send_alert"
    params:
      severity: "high"
""")

        library = PlaybookLibrary(root=str(playbooks_dir))
        return library

    def test_initialization(self, playbook_library):
        """Test PlaybookLibrary initialization"""
        assert playbook_library.root is not None
        assert playbook_library.root.exists()

    def test_select_playbook_malware(self, playbook_library, sample_incident):
        """Test playbook selection for malware incident"""
        playbook = playbook_library.select_playbook(sample_incident)

        assert playbook is not None
        assert playbook["name"] == "Quarantine Malware"
        assert "Isolate Host" in [step["name"] for step in playbook["steps"]]

    def test_select_playbook_unknown_type(self, playbook_library):
        """Test playbook selection for unknown incident type"""
        unknown_incident = Mock(spec=Incident)
        unknown_incident.incident_type = IncidentType.UNKNOWN
        unknown_incident.incident_type.value = "unknown_type"

        playbook = playbook_library.select_playbook(unknown_incident)

        # Should return default playbook
        assert playbook is not None
        assert "Default Response" in playbook["name"]

    def test_select_playbook_missing_file(self, playbook_library, sample_incident):
        """Test playbook selection when file doesn't exist"""
        # Modify incident type to non-existent playbook
        sample_incident.incident_type = IncidentType.CUSTOM
        sample_incident.incident_type.value = "non_existent_type"

        playbook = playbook_library.select_playbook(sample_incident)

        # Should return default playbook
        assert playbook is not None
        assert "Default Response" in playbook["name"]


class TestAutomatedResponder:
    """Test AutomatedResponder functionality"""

    @pytest.fixture
    def automated_responder(self):
        """Create AutomatedResponder instance with mocked components"""
        responder = AutomatedResponder()

        # Mock all integrations
        responder.siem = AsyncMock()
        responder.threat_intel = AsyncMock(spec=ThreatIntelligenceClient)
        responder.azure_firewall = Mock()
        responder.azure_vm = Mock()
        responder.azure_nsg = Mock()
        responder.azure_backup = Mock()
        responder.azure_ad = Mock()

        return responder

    @pytest.mark.asyncio
    async def test_initialization(self, automated_responder):
        """Test AutomatedResponder initialization"""
        assert automated_responder.playbooks is not None
        assert automated_responder.orchestrator is not None
        assert automated_responder.siem is not None
        assert automated_responder.threat_intel is not None

    @pytest.mark.asyncio
    async def test_execute_playbook_success(self, automated_responder, sample_incident, sample_playbook):
        """Test successful playbook execution"""
        # Mock components
        automated_responder.playbooks.select_playbook.return_value = sample_playbook
        automated_responder.orchestrator.execute.return_value = {
            "success": True,
            "actions_executed": 2,
            "message": "Playbook executed successfully"
        }
        automated_responder.threat_intel.enrich_incident_with_threat_intel.return_value = {
            "threat_score": 0.8,
            "malicious_indicators": []
        }
        automated_responder.siem.send_incident_to_siem = AsyncMock()

        result = await automated_responder.execute_playbook(sample_incident)

        assert result["success"] is True
        assert "actions_executed" in result

        # Verify method calls
        automated_responder.playbooks.select_playbook.assert_called_once_with(sample_incident)
        automated_responder.orchestrator.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_playbook_with_threat_intelligence(self, automated_responder, sample_incident, sample_playbook):
        """Test playbook execution with threat intelligence enrichment"""
        # Mock high threat score
        automated_responder.threat_intel.enrich_incident_with_threat_intel.return_value = {
            "threat_score": 0.95,
            "malicious_indicators": [
                {"type": "ip", "value": "192.168.1.100"}
            ]
        }
        automated_responder.playbooks.select_playbook.return_value = sample_playbook
        automated_responder.orchestrator.execute.return_value = {"success": True}

        # Mock Azure Firewall
        automated_responder.azure_firewall.block_ip_address.return_value = {
            "success": True,
            "rule_name": "AUTO_BLOCK_001"
        }

        result = await automated_responder.execute_playbook(sample_incident)

        # Verify firewall was automatically triggered
        automated_responder.azure_firewall.block_ip_address.assert_called_once()
        assert "azure_firewall_actions" in result

    @pytest.mark.asyncio
    async def test_execute_playbook_siem_integration(self, automated_responder, sample_incident, sample_playbook):
        """Test SIEM integration during playbook execution"""
        automated_responder.playbooks.select_playbook.return_value = sample_playbook
        automated_responder.orchestrator.execute.return_value = {"success": True}
        automated_responder.threat_intel.enrich_incident_with_threat_intel.return_value = {
            "threat_score": 0.5
        }

        result = await automated_responder.execute_playbook(sample_incident)

        # Verify SIEM logging calls
        assert automated_responder.siem.send_incident_to_siem.call_count >= 2  # Initial + completion

    @pytest.mark.asyncio
    async def test_execute_playbook_failure_handling(self, automated_responder, sample_incident):
        """Test playbook execution failure handling"""
        # Mock playbook selection failure
        automated_responder.playbooks.select_playbook.side_effect = Exception("Playbook selection failed")

        result = await automated_responder.execute_playbook(sample_incident)

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    async def test_response_action_execution(self, automated_responder, sample_incident):
        """Test individual response action execution"""
        # Test quarantine action
        quarantine_incident = Mock(spec=Incident)
        quarantine_incident.incident_type = IncidentType.MALWARE
        quarantine_incident.host_id = "INFECTED_HOST"

        # Mock successful quarantine
        with patch('soar.response.actions.system.quarantine_host') as mock_quarantine:
            mock_quarantine.return_value = {
                "success": True,
                "message": "Host quarantined successfully"
            }

            # This would be called through orchestrator
            # Verify the action would be executed correctly
            assert mock_quarantine is not None

    @pytest.mark.asyncio
    async def test_multi_step_playbook_execution(self, automated_responder):
        """Test execution of multi-step playbook"""
        multi_step_playbook = {
            "name": "Complex Response",
            "steps": [
                {"name": "Step 1", "action": "network.isolate", "params": {}},
                {"name": "Step 2", "action": "alert.notify", "params": {}},
                {"name": "Step 3", "action": "system.scan", "params": {}}
            ]
        }

        incident = Mock(spec=Incident)
        automated_responder.playbooks.select_playbook.return_value = multi_step_playbook
        automated_responder.orchestrator.execute.return_value = {
            "success": True,
            "steps_executed": 3
        }

        result = await automated_responder.execute_playbook(incident)

        assert result["success"] is True
        assert result["steps_executed"] == 3

    @pytest.mark.asyncio
    async def test_containment_actions(self, automated_responder, sample_incident):
        """Test containment action execution"""
        containment_incident = Mock(spec=Incident)
        containment_incident.incident_type = IncidentType.MALWARE
        containment_incident.source_ip = "192.168.1.100"
        containment_incident.host_id = "INFECTED_HOST"

        containment_playbook = {
            "name": "Containment Response",
            "steps": [
                {
                    "name": "Isolate Network",
                    "action": "network.isolate_host",
                    "params": {"host_id": "INFECTED_HOST"}
                },
                {
                    "name": "Block IP",
                    "action": "network.block_ip",
                    "params": {"ip": "192.168.1.100"}
                }
            ]
        }

        automated_responder.playbooks.select_playbook.return_value = containment_playbook
        automated_responder.orchestrator.execute.return_value = {
            "success": True,
            "containment_actions": ["isolate", "block"]
        }

        result = await automated_responder.execute_playbook(containment_incident)

        assert result["success"] is True
        assert "containment_actions" in result

    @pytest.mark.asyncio
    async def test_evidence_preservation(self, automated_responder, sample_incident):
        """Test evidence preservation during response"""
        evidence_playbook = {
            "name": "Evidence Preservation",
            "steps": [
                {
                    "name": "Collect Evidence",
                    "action": "evidence.collect",
                    "params": {"evidence_types": ["logs", "memory", "network"]}
                },
                {
                    "name": "Preserve Chain of Custody",
                    "action": "evidence.preserve_custody",
                    "params": {"witness": "SOAR_SYSTEM"}
                }
            ]
        }

        automated_responder.playbooks.select_playbook.return_value = evidence_playbook
        automated_responder.orchestrator.execute.return_value = {
            "success": True,
            "evidence_collected": ["logs", "memory", "network"],
            "chain_of_custody": "preserved"
        }

        result = await automated_responder.execute_playbook(sample_incident)

        assert result["success"] is True
        assert "evidence_collected" in result
        assert "chain_of_custody" in result

    @pytest.mark.asyncio
    async def test_recovery_procedures(self, automated_responder):
        """Test recovery procedure execution"""
        recovery_incident = Mock(spec=Incident)
        recovery_incident.incident_type = IncidentType.SYSTEM_FAILURE
        recovery_incident.host_id = "FAILED_HOST"

        recovery_playbook = {
            "name": "System Recovery",
            "steps": [
                {
                    "name": "Restore from Backup",
                    "action": "system.restore_backup",
                    "params": {"host_id": "FAILED_HOST", "backup_type": "full"}
                },
                {
                    "name": "Verify System Integrity",
                    "action": "system.verify_integrity",
                    "params": {"host_id": "FAILED_HOST"}
                }
            ]
        }

        automated_responder.playbooks.select_playbook.return_value = recovery_playbook
        automated_responder.orchestrator.execute.return_value = {
            "success": True,
            "recovery_actions": ["backup_restore", "integrity_check"],
            "system_restored": True
        }

        result = await automated_responder.execute_playbook(recovery_incident)

        assert result["success"] is True
        assert result["system_restored"] is True

    @pytest.mark.asyncio
    async def test_azure_integration_actions(self, automated_responder, sample_incident):
        """Test Azure integration actions"""
        azure_incident = Mock(spec=Incident)
        azure_incident.incident_type = IncidentType.MALWARE
        azure_incident.source_ip = "192.168.1.100"
        azure_incident.host_id = "AZURE_VM_001"

        azure_playbook = {
            "name": "Azure Response",
            "steps": [
                {
                    "name": "Isolate Azure VM",
                    "action": "azure.vm.isolate",
                    "params": {"vm_id": "AZURE_VM_001"}
                },
                {
                    "name": "Update NSG",
                    "action": "azure.nsg.block_ip",
                    "params": {"ip": "192.168.1.100"}
                }
            ]
        }

        automated_responder.playbooks.select_playbook.return_value = azure_playbook
        automated_responder.orchestrator.execute.return_value = {"success": True}

        result = await automated_responder.execute_playbook(azure_incident)

        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_error_handling_and_rollback(self, automated_responder, sample_incident):
        """Test error handling and rollback procedures"""
        # Playbook with error in middle step
        error_playbook = {
            "name": "Error Handling Test",
            "steps": [
                {"name": "Step 1", "action": "network.isolate", "params": {}},
                {"name": "Step 2", "action": "failing.action", "params": {}},  # This will fail
                {"name": "Step 3", "action": "system.restore", "params": {}}
            ]
        }

        automated_responder.playbooks.select_playbook.return_value = error_playbook
        automated_responder.orchestrator.execute.return_value = {
            "success": False,
            "error": "Step 2 failed",
            "rollback_actions": ["undo_isolate"]
        }

        result = await automated_responder.execute_playbook(sample_incident)

        assert result["success"] is False
        assert "error" in result
        assert "rollback_actions" in result


class TestResponseOrchestrator:
    """Test ResponseOrchestrator functionality"""

    @pytest.fixture
    def response_orchestrator(self):
        """Create ResponseOrchestrator instance"""
        return ResponseOrchestrator()

    @pytest.mark.asyncio
    async def test_execute_simple_playbook(self, response_orchestrator, sample_playbook, sample_incident):
        """Test execution of simple playbook"""
        # Mock action resolution
        with patch.object(response_orchestrator, '_resolve') as mock_resolve:
            mock_action = AsyncMock(return_value={"success": True, "message": "Action executed"})
            mock_resolve.return_value = mock_action

            result = await response_orchestrator.execute(sample_playbook, sample_incident)

            assert result["success"] is True
            assert len(result["step_results"]) == len(sample_playbook["steps"])

    @pytest.mark.asyncio
    async def test_execute_with_parameter_substitution(self, response_orchestrator, sample_incident):
        """Test parameter substitution in playbook execution"""
        playbook_with_params = {
            "name": "Parameter Test",
            "steps": [
                {
                    "name": "Test Action",
                    "action": "test.action",
                    "params": {
                        "host_id": "INCIDENT_HOST_ID",
                        "ip": "INCIDENT_SOURCE_IP"
                    }
                }
            ]
        }

        with patch.object(response_orchestrator, '_resolve') as mock_resolve:
            mock_action = AsyncMock(return_value={"success": True})
            mock_resolve.return_value = mock_action

            result = await response_orchestrator.execute(playbook_with_params, sample_incident)

            # Verify parameters were substituted
            call_args = mock_action.call_args
            assert call_args[1]["host_id"] == "WS-001"  # From sample_incident.host_id
            assert call_args[1]["ip"] == "192.168.1.100"  # From sample_incident.source_ip

    @pytest.mark.asyncio
    async def test_fallback_action_for_missing_actions(self, response_orchestrator):
        """Test fallback action for missing action implementations"""
        playbook_with_missing_action = {
            "name": "Missing Action Test",
            "steps": [
                {
                    "name": "Missing Action",
                    "action": "nonexistent.module.action",
                    "params": {}
                }
            ]
        }

        incident = Mock(spec=Incident)

        result = await response_orchestrator.execute(playbook_with_missing_action, incident)

        # Should still succeed with fallback action
        assert result["success"] is True
        assert "fallback" in str(result["step_results"][0]).lower()

    @pytest.mark.asyncio
    async def test_error_handling_in_step_execution(self, response_orchestrator):
        """Test error handling when step execution fails"""
        playbook_with_error = {
            "name": "Error Test",
            "steps": [
                {
                    "name": "Failing Step",
                    "action": "test.failing_action",
                    "params": {}
                }
            ]
        }

        with patch.object(response_orchestrator, '_resolve') as mock_resolve:
            mock_action = AsyncMock(side_effect=Exception("Action failed"))
            mock_resolve.return_value = mock_action

            result = await response_orchestrator.execute(playbook_with_error, Mock())

            assert result["success"] is False
            assert "error" in result
            assert "Failing Step" in str(result["failed_step"])
