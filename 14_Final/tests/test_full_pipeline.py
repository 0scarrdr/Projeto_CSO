"""
Testes avançados para o pipeline SOAR: cobre cenários do enunciado.
"""
import pytest
from soar.core.handler import IncidentHandler

@pytest.mark.asyncio
async def test_known_attack():
    handler = IncidentHandler()
    event = {
        "id": "test1",
        "type": "alert",
        "severity": "high",
        "src_ip": "192.168.1.1",
        "business_critical": True,
        "message": "malware detected",
        "source": "log"
    }
    result = await handler.handle_incident(event)
    assert result["status"] == "completed"
    assert "malware_alert" in str(result["results"])

@pytest.mark.asyncio
async def test_zero_day_attack():
    handler = IncidentHandler()
    event = {
        "id": "test2",
        "type": "alert",
        "severity": "critical",
        "src_ip": "10.0.0.2",
        "business_critical": True,
        "anomaly_score": 0.95,
        "source": "network"
    }
    result = await handler.handle_incident(event)
    assert result["status"] == "completed"
    assert "network_anomaly" in str(result["results"])

@pytest.mark.asyncio
async def test_policy_violation():
    handler = IncidentHandler()
    event = {
        "id": "test3",
        "type": "alert",
        "severity": "medium",
        "src_ip": "172.16.0.5",
        "business_critical": False,
        "message": "policy violation detected",
        "source": "log"
    }
    result = await handler.handle_incident(event)
    assert result["status"] == "completed"
    assert "policy_violation" in str(result["results"])

@pytest.mark.asyncio
async def test_data_exfiltration():
    handler = IncidentHandler()
    event = {
        "id": "test4",
        "type": "alert",
        "severity": "critical",
        "src_ip": "172.16.0.10",
        "business_critical": True,
        "exfiltration_bytes": 20000000,
        "source": "network"
    }
    result = await handler.handle_incident(event)
    assert result["status"] == "completed"
    assert "data_exfiltration" in str(result["results"])
